// src/proxy/vless.ts
// 集成版 VLESS-over-WebSocket / VLESS-over-HTTP 代理引擎。
// 直接使用 Node 原生 http/ws/net/dgram 实现 VLESS 协议头解析与流量转发，
// 与 ProxyGosha 共享同一端口与 Express / HTTP 服务实例。

import dgram from "node:dgram";
import net from "node:net";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import type { NextFunction, Request, Response } from "express";
import { WebSocket, WebSocketServer } from "ws";
import type { VlessRuntimeConfig } from "./config.ts";
import { logEvent, STATS } from "./telemetry.ts";

const MAX_WS_MESSAGE_SIZE = 100 * 1024 * 1024; // WebSocket 单条消息上限 100MB
const MAX_HTTP_BODY_SIZE = 200 * 1024 * 1024; // HTTP 请求体上限 200MB
const VLESS_HEADER_SIZE = 24; // VLESS 协议头最小长度 24 字节
const DNS_PORT = 53; // UDP 代理仅放行 53 端口 DNS 查询
const WS_READY_STATE_OPEN = 1;

const UUID_REGEX =
  /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;

const BYTE_TO_HEX = Array.from({ length: 256 }, (_, i) =>
  (i + 256).toString(16).substring(1).toLowerCase()
);

export function validateVlessUuid(uuid: unknown): uuid is string {
  return typeof uuid === "string" && UUID_REGEX.test(uuid.trim());
}

function uuidBufferToString(arr: Uint8Array, offset = 0): string {
  return (
    BYTE_TO_HEX[arr[offset]] +
    BYTE_TO_HEX[arr[offset + 1]] +
    BYTE_TO_HEX[arr[offset + 2]] +
    BYTE_TO_HEX[arr[offset + 3]] +
    "-" +
    BYTE_TO_HEX[arr[offset + 4]] +
    BYTE_TO_HEX[arr[offset + 5]] +
    "-" +
    BYTE_TO_HEX[arr[offset + 6]] +
    BYTE_TO_HEX[arr[offset + 7]] +
    "-" +
    BYTE_TO_HEX[arr[offset + 8]] +
    BYTE_TO_HEX[arr[offset + 9]] +
    "-" +
    BYTE_TO_HEX[arr[offset + 10]] +
    BYTE_TO_HEX[arr[offset + 11]] +
    BYTE_TO_HEX[arr[offset + 12]] +
    BYTE_TO_HEX[arr[offset + 13]] +
    BYTE_TO_HEX[arr[offset + 14]] +
    BYTE_TO_HEX[arr[offset + 15]]
  );
}

function getValidatedUUID(arr: Uint8Array, offset = 0): string {
  const uuid = uuidBufferToString(arr, offset);
  if (!validateVlessUuid(uuid)) {
    throw new TypeError(`Invalid UUID: ${uuid}`);
  }
  return uuid;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// 获取伪装站响应内容（未授权 HTTP VLESS 请求的兜底）
async function fetchDisguisedContent(disguisedDomain: string): Promise<string> {
  if (/^https?:\/\//i.test(disguisedDomain)) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(disguisedDomain, { signal: controller.signal });
      clearTimeout(timer);
      if (response.ok) {
        return await response.text();
      }
    } catch {
      // 忽略拉取异常，使用内置兜底页面
    }
  }
  return `<html><body>Welcome to ${escapeHtml(disguisedDomain || "LUXVEIL")}</body></html>`;
}

async function handleUnauthorizedRequest(res: ServerResponse, disguisedDomain: string): Promise<void> {
  if (res.headersSent || res.writableEnded) return;
  const disguisedContent = await fetchDisguisedContent(disguisedDomain);
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(disguisedContent);
}

function closeWebSocketSafely(socket: WebSocket | null | undefined, code = 1000): void {
  try {
    if (socket && (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === 0)) {
      socket.close(code);
    }
  } catch {
    // 忽略关闭异常
  }
}

function logInfo(cfg: VlessRuntimeConfig, message: string, context: Record<string, unknown> = {}): void {
  if (cfg.debug) {
    console.log(JSON.stringify({ type: "vless_info", message, ...context }));
  }
}

function logError(message: string, error: unknown, context: Record<string, unknown> = {}): void {
  const err = error as Error | undefined;
  console.error(
    JSON.stringify({
      type: "vless_error",
      message,
      error: err?.message || String(error),
      ...context,
    })
  );
}

function normalizeWsDataToBuffer(data: unknown): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data as Buffer[]);
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  }
  return Buffer.alloc(0);
}

// ====================== VLESS-over-HTTP 处理器 ======================

async function handleVlessHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  cfg: VlessRuntimeConfig
): Promise<void> {
  const userID = cfg.uuid.toLowerCase();

  const requiredHeaders = [
    "x-vless-version",
    "x-vless-address",
    "x-vless-port",
    "x-vless-uuid",
  ];
  for (const header of requiredHeaders) {
    if (!req.headers[header]) {
      await handleUnauthorizedRequest(res, cfg.disguisedDomain);
      return;
    }
  }

  const requestUUID = String(req.headers["x-vless-uuid"] || "").trim().toLowerCase();
  if (!validateVlessUuid(requestUUID) || requestUUID !== userID) {
    await handleUnauthorizedRequest(res, cfg.disguisedDomain);
    return;
  }

  const targetAddress = String(req.headers["x-vless-address"] || "").trim();
  const targetPort = parseInt(String(req.headers["x-vless-port"] || "0"), 10);
  const isUDP = req.headers["x-vless-udp"] === "true";

  if (!targetAddress || !Number.isFinite(targetPort) || targetPort < 1 || targetPort > 65535) {
    res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
    res.end("Invalid VLESS target address or port");
    return;
  }

  if (isUDP && targetPort !== DNS_PORT) {
    res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
    res.end(`UDP proxy only supports port ${DNS_PORT} (DNS)`);
    return;
  }

  const contentLength = parseInt(String(req.headers["content-length"] || "0"), 10);
  if (contentLength > MAX_HTTP_BODY_SIZE) {
    res.writeHead(413, { "content-type": "text/plain; charset=utf-8" });
    res.end("Request body too large");
    return;
  }

  const logContext: Record<string, unknown> = {
    address: targetAddress,
    port: targetPort,
    protocol: isUDP ? "UDP" : "TCP",
    mode: "HTTP",
  };

  try {
    STATS.vlessConnections++;
    STATS.vlessActive++;
    let decremented = false;
    const markClosed = () => {
      if (!decremented) {
        decremented = true;
        STATS.vlessActive = Math.max(0, STATS.vlessActive - 1);
      }
    };

    const earlyChunks: Buffer[] = [];
    let connected = false;
    let reqEnded = false;

    const remoteSocket = net.connect({
      host: targetAddress,
      port: targetPort,
    });

    logInfo(cfg, "HTTP VLESS connection established", logContext);
    logEvent("vless_http", `${targetAddress}:${targetPort}`);

    req.on("data", (chunk: Buffer) => {
      STATS.vlessBytesUp += chunk.length;
      if (connected && !remoteSocket.destroyed) {
        if (!remoteSocket.write(chunk)) {
          req.pause();
          remoteSocket.once("drain", () => req.resume());
        }
      } else {
        earlyChunks.push(chunk);
      }
    });

    req.on("end", () => {
      reqEnded = true;
      if (connected && !remoteSocket.destroyed) {
        remoteSocket.end();
      }
    });

    remoteSocket.once("connect", () => {
      connected = true;
      remoteSocket.setNoDelay(true);
      if (!res.headersSent) {
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "cache-control": "no-store",
        });
        res.flushHeaders();
      }
      for (const c of earlyChunks.splice(0)) {
        if (!remoteSocket.destroyed) remoteSocket.write(c);
      }
      if (reqEnded && !remoteSocket.destroyed) {
        remoteSocket.end();
      }
      remoteSocket.pipe(res);
    });

    remoteSocket.on("data", (chunk: Buffer) => {
      STATS.vlessBytesDown += chunk.length;
    });

    remoteSocket.on("error", (error) => {
      markClosed();
      logError("VLESS HTTP remote error", error, logContext);
      if (!res.headersSent) {
        res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
        res.end(`Connection failed: ${error.message}`);
      } else {
        res.destroy();
      }
    });

    remoteSocket.on("close", markClosed);
    res.on("close", () => {
      markClosed();
      if (!remoteSocket.destroyed) remoteSocket.destroy();
    });
  } catch (error) {
    logError("VLESS HTTP failed", error, logContext);
    if (!res.headersSent) {
      res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
      res.end(`Connection failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

// ====================== VLESS 协议头解析与 WS 转发 ======================

interface VlessHeaderResult {
  hasError: boolean;
  message: string;
  addressRemote: string;
  portRemote: number;
  rawDataIndex: number;
  vlessVersion: number;
  isUDP: boolean;
}

function processVlessHeader(buf: Buffer, expectedUuid: string): VlessHeaderResult {
  if (buf.byteLength < VLESS_HEADER_SIZE) {
    return {
      hasError: true,
      message: `Header too short (min ${VLESS_HEADER_SIZE} bytes)`,
      addressRemote: "",
      portRemote: 0,
      rawDataIndex: 0,
      vlessVersion: 0,
      isUDP: false,
    };
  }

  const version = buf.readUInt8(0);

  try {
    const headerUserID = getValidatedUUID(buf, 1).toLowerCase();
    if (headerUserID !== expectedUuid.toLowerCase()) {
      return {
        hasError: true,
        message: "User authentication failed",
        addressRemote: "",
        portRemote: 0,
        rawDataIndex: 0,
        vlessVersion: version,
        isUDP: false,
      };
    }

    const optLength = buf.readUInt8(17);
    const cmdPos = 18 + optLength;
    if (buf.byteLength <= cmdPos + 3) {
      return {
        hasError: true,
        message: "Truncated VLESS command section",
        addressRemote: "",
        portRemote: 0,
        rawDataIndex: 0,
        vlessVersion: version,
        isUDP: false,
      };
    }

    const command = buf.readUInt8(cmdPos);
    if (command !== 1 && command !== 2) {
      return {
        hasError: true,
        message: `Unsupported command: ${command}`,
        addressRemote: "",
        portRemote: 0,
        rawDataIndex: 0,
        vlessVersion: version,
        isUDP: false,
      };
    }

    // VLESS 规范：command === 1 为 TCP，command === 2 为 UDP
    const isUDP = command === 2;
    const portRemote = buf.readUInt16BE(cmdPos + 1);
    const addrTypePos = cmdPos + 3;
    const addressType = buf.readUInt8(addrTypePos);
    let addrValuePos = addrTypePos + 1;
    let addrLength = 0;
    let addressValue = "";

    switch (addressType) {
      case 1: // IPv4
        addrLength = 4;
        if (buf.byteLength < addrValuePos + addrLength) {
          throw new Error("Truncated IPv4 address");
        }
        addressValue = `${buf[addrValuePos]}.${buf[addrValuePos + 1]}.${buf[addrValuePos + 2]}.${buf[addrValuePos + 3]}`;
        break;
      case 2: // 域名
        if (buf.byteLength < addrValuePos + 1) {
          throw new Error("Truncated domain length");
        }
        addrLength = buf.readUInt8(addrValuePos);
        addrValuePos += 1;
        if (buf.byteLength < addrValuePos + addrLength) {
          throw new Error("Truncated domain value");
        }
        addressValue = buf.subarray(addrValuePos, addrValuePos + addrLength).toString("utf8");
        break;
      case 3: // IPv6
        addrLength = 16;
        if (buf.byteLength < addrValuePos + addrLength) {
          throw new Error("Truncated IPv6 address");
        }
        {
          const ipv6Parts: string[] = [];
          for (let i = 0; i < 8; i++) {
            ipv6Parts.push(buf.readUInt16BE(addrValuePos + i * 2).toString(16));
          }
          addressValue = ipv6Parts.join(":");
        }
        break;
      default:
        return {
          hasError: true,
          message: `Invalid address type: ${addressType}`,
          addressRemote: "",
          portRemote: 0,
          rawDataIndex: 0,
          vlessVersion: version,
          isUDP: false,
        };
    }

    if (!addressValue) {
      return {
        hasError: true,
        message: `Empty address (type: ${addressType})`,
        addressRemote: "",
        portRemote: 0,
        rawDataIndex: 0,
        vlessVersion: version,
        isUDP: false,
      };
    }

    return {
      hasError: false,
      message: "",
      addressRemote: addressValue,
      portRemote,
      rawDataIndex: addrValuePos + addrLength,
      vlessVersion: version,
      isUDP,
    };
  } catch (error) {
    return {
      hasError: true,
      message: `Header parse error: ${error instanceof Error ? error.message : String(error)}`,
      addressRemote: "",
      portRemote: 0,
      rawDataIndex: 0,
      vlessVersion: version,
      isUDP: false,
    };
  }
}

// 处理 VLESS UDP DNS 数据帧（VLESS 协议每帧前带 2 字节大端长度）
function createUdpDnsForwarder(
  ws: WebSocket,
  addressRemote: string,
  portRemote: number,
  vlessResponseHeader: Buffer,
  onStats: (up: number, down: number) => void,
  onClose: () => void
): { write: (chunk: Buffer) => void; close: () => void } {
  const socketType = net.isIPv6(addressRemote) ? "udp6" : "udp4";
  const udpSocket = dgram.createSocket(socketType);
  let headerSent = false;
  let pending: Buffer = Buffer.alloc(0);
  let closed = false;

  udpSocket.on("message", (msg) => {
    if (closed || ws.readyState !== WS_READY_STATE_OPEN) return;
    const lenPrefix = Buffer.allocUnsafe(2);
    lenPrefix.writeUInt16BE(msg.length, 0);
    const frame = headerSent
      ? Buffer.concat([lenPrefix, msg])
      : Buffer.concat([vlessResponseHeader, lenPrefix, msg]);
    headerSent = true;
    onStats(0, msg.length);
    ws.send(frame);
  });

  udpSocket.on("error", () => {
    if (!closed) {
      closed = true;
      onClose();
    }
  });

  const write = (chunk: Buffer) => {
    if (closed || chunk.length === 0) return;
    pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
    while (pending.length >= 2) {
      const pktLen = pending.readUInt16BE(0);
      if (pending.length < 2 + pktLen) break;
      const payload = pending.subarray(2, 2 + pktLen);
      pending = pending.subarray(2 + pktLen);
      onStats(payload.length, 0);
      udpSocket.send(payload, portRemote, addressRemote);
    }
  };

  const close = () => {
    if (closed) return;
    closed = true;
    try {
      udpSocket.close();
    } catch {
      // ignore
    }
  };

  return { write, close };
}

async function handleVlessWsSession(
  ws: WebSocket,
  req: IncomingMessage,
  cfg: VlessRuntimeConfig
): Promise<void> {
  const userID = cfg.uuid.toLowerCase();
  let remoteSocket: net.Socket | null = null;
  let udpForwarder: { write: (chunk: Buffer) => void; close: () => void } | null = null;
  let handshakeDone = false;
  let address = "";
  let portWithRandomLog = "";
  let activeCounted = true;
  STATS.vlessConnections++;
  STATS.vlessActive++;

  const cleanup = () => {
    if (activeCounted) {
      activeCounted = false;
      STATS.vlessActive = Math.max(0, STATS.vlessActive - 1);
    }
    if (remoteSocket) {
      try {
        remoteSocket.removeAllListeners();
        remoteSocket.destroy();
      } catch {
        // ignore
      }
      remoteSocket = null;
    }
    if (udpForwarder) {
      udpForwarder.close();
      udpForwarder = null;
    }
  };

  const earlyDataHeader = String(req.headers["sec-websocket-protocol"] || "");
  const getLogContext = (): Record<string, unknown> => ({
    address,
    port: portWithRandomLog.split("--")[0],
    earlyData: earlyDataHeader ? "yes" : "no",
  });

  const processMessage = async (raw: unknown) => {
    const chunk = normalizeWsDataToBuffer(raw);
    if (chunk.length > MAX_WS_MESSAGE_SIZE) {
      logError(`VLESS message exceeds ${MAX_WS_MESSAGE_SIZE} bytes`, null, getLogContext());
      cleanup();
      closeWebSocketSafely(ws, 1009);
      return;
    }

    if (handshakeDone) {
      if (remoteSocket && !remoteSocket.destroyed) {
        STATS.vlessBytesUp += chunk.length;
        remoteSocket.write(chunk);
      } else if (udpForwarder) {
        udpForwarder.write(chunk);
      }
      return;
    }

    try {
      const { hasError, message, portRemote, addressRemote, rawDataIndex, vlessVersion, isUDP } =
        processVlessHeader(chunk, userID);

      address = addressRemote || "";
      portWithRandomLog = `${portRemote}--${Math.random().toString(36).substring(2, 8)} ${
        isUDP ? "UDP" : "TCP"
      }`;

      if (hasError) throw new Error(message);
      if (isUDP && portRemote !== DNS_PORT) {
        throw new Error(`UDP only allowed on port ${DNS_PORT}`);
      }

      handshakeDone = true;
      const vlessResponseHeader = Buffer.from([vlessVersion, 0]);
      const clientData = chunk.subarray(rawDataIndex);

      if (isUDP) {
        logInfo(cfg, "VLESS UDP DNS session established", getLogContext());
        logEvent("vless_udp", `${addressRemote}:${portRemote}`);
        udpForwarder = createUdpDnsForwarder(
          ws,
          addressRemote,
          portRemote,
          vlessResponseHeader,
          (up, down) => {
            STATS.vlessBytesUp += up;
            STATS.vlessBytesDown += down;
          },
          () => {
            cleanup();
            closeWebSocketSafely(ws);
          }
        );
        if (clientData.length > 0) {
          udpForwarder.write(clientData);
        } else if (ws.readyState === WS_READY_STATE_OPEN) {
          ws.send(vlessResponseHeader);
        }
        return;
      }

      remoteSocket = net.connect({
        host: addressRemote,
        port: portRemote,
      });
      remoteSocket.setNoDelay(true);
      remoteSocket.setKeepAlive(true, 30000);

      logInfo(cfg, "VLESS TCP connection established", getLogContext());
      logEvent("vless_open", `${addressRemote}:${portRemote}`);

      remoteSocket.on("data", (downChunk: Buffer) => {
        if (ws.readyState === WS_READY_STATE_OPEN) {
          STATS.vlessBytesDown += downChunk.length;
          ws.send(downChunk);
        }
      });

      remoteSocket.on("error", (error) => {
        logError("VLESS remote socket error", error, getLogContext());
        cleanup();
        closeWebSocketSafely(ws);
      });

      remoteSocket.on("close", () => {
        logInfo(cfg, "VLESS remote socket closed", getLogContext());
        cleanup();
        closeWebSocketSafely(ws);
      });

      if (ws.readyState === WS_READY_STATE_OPEN) {
        ws.send(vlessResponseHeader);
      }
      if (clientData.length > 0 && !remoteSocket.destroyed) {
        STATS.vlessBytesUp += clientData.length;
        remoteSocket.write(clientData);
      }
    } catch (error) {
      logError("VLESS WebSocket processing failed", error, getLogContext());
      cleanup();
      closeWebSocketSafely(ws, 1008);
    }
  };

  ws.on("message", (data) => {
    void processMessage(data);
  });

  ws.on("error", (error) => {
    logError("VLESS WebSocket error", error, getLogContext());
    cleanup();
    closeWebSocketSafely(ws);
  });

  ws.on("close", () => {
    logInfo(cfg, "VLESS WebSocket closed", getLogContext());
    cleanup();
  });

  // 支持 VLESS Early-Data（通过 Sec-WebSocket-Protocol Base64URL 携带首包）
  if (earlyDataHeader && earlyDataHeader.length >= 32) {
    try {
      const normalized = earlyDataHeader.replace(/-/g, "+").replace(/_/g, "/");
      const binaryBuf = Buffer.from(normalized, "base64");
      if (binaryBuf.length >= VLESS_HEADER_SIZE) {
        void processMessage(binaryBuf);
      }
    } catch (error) {
      logError("VLESS early data decode failed", error, getLogContext());
    }
  }
}

// ====================== 统一接入接口 ======================

const vlessWss = new WebSocketServer({
  noServer: true,
  perMessageDeflate: false,
  maxPayload: MAX_WS_MESSAGE_SIZE,
});

// 由 engine.ts 统一升级分发器调用，避免重复绑定 upgrade 监听器导致 404 冲突
export function handleVlessWebSocketUpgrade(
  req: IncomingMessage,
  socket: Duplex,
  head: Buffer,
  cfg: VlessRuntimeConfig
): void {
  vlessWss.handleUpgrade(req, socket, head, (ws) => {
    ws.binaryType = "nodebuffer";
    if (String(req.headers.upgrade || "").toLowerCase() !== "websocket") {
      closeWebSocketSafely(ws);
      return;
    }
    void handleVlessWsSession(ws, req, cfg);
  });
}

// 生成 vless:// 标准导入链接（兼容 v2rayN / Clash / Shadowrocket / Nekobox）
export function buildVlessShareUri(
  host: string,
  proto: "https" | "http",
  cfg: VlessRuntimeConfig,
  portOverride?: string
): string {
  const cleanHost = host || "localhost";
  const port = portOverride || (proto === "https" ? "443" : "80");
  const security = proto === "https" ? "tls" : "none";
  const params = new URLSearchParams({
    encryption: "none",
    security,
    type: "ws",
    host: cleanHost,
    path: cfg.path,
  });
  if (proto === "https") {
    params.set("sni", cleanHost);
  }
  const tag = encodeURIComponent(`ProxyGosha-${cleanHost}`);
  return `vless://${cfg.uuid}@${cleanHost}:${port}?${params.toString()}#${tag}`;
}

// Express 中间件：处理 VLESS-over-HTTP 请求（匹配路径与 content-type: application/vless 时接管）
export function createVlessHttpMiddleware(getVlessCfg: () => VlessRuntimeConfig) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const cfg = getVlessCfg();
    if (!cfg.enabled) {
      next();
      return;
    }
    try {
      const parsedUrl = new URL(req.originalUrl || req.url || "/", "http://localhost");
      const ct = String(req.headers["content-type"] || "")
        .toLowerCase()
        .split(";")[0]
        .trim();
      if (parsedUrl.pathname !== cfg.path || ct !== "application/vless") {
        next();
        return;
      }
      await handleVlessHttpRequest(req, res, cfg);
    } catch (error) {
      logError("VLESS middleware error", error);
      await handleUnauthorizedRequest(res, cfg.disguisedDomain);
    }
  };
}
