import net from "node:net";
import { createCipheriv, randomBytes } from "node:crypto";
import type { IncomingMessage, Server as HttpServer } from "node:http";
import type { Duplex } from "node:stream";
import { WebSocketServer, WebSocket } from "ws";
import {
  EMPTY,
  HTTPS_PORTS,
  PORT_MODE_BASE,
  REQUEST_LIMIT,
  TOKEN_KIND_SESSION,
} from "./constants.ts";
import {
  concat,
  ObfuscatedCtrStream,
  reverse,
  sha256,
} from "./crypto.ts";
import {
  deriveSecret,
  hostAllowed,
  requestHost,
  requestPort,
  verifyToken,
  type ProxyRuntime,
} from "./config.ts";
import { fmtBytes, fmtDuration, logEvent, reportError, STATS } from "./telemetry.ts";
import { recordTunnelHeaders } from "./tunnel.ts";

export interface ProbeResult {
  dc: number;
  ip: string;
  port: number;
  ok: boolean;
  ms: number;
  mtprotoOk: boolean | null;
  mtprotoMs: number | null;
  reason: string;
}

function frame(type: number, id: number, payload: Uint8Array): Buffer {
  const out = Buffer.allocUnsafe(8 + payload.length);
  out[0] = type;
  out[1] = (id >>> 16) & 0xff;
  out[2] = (id >>> 8) & 0xff;
  out[3] = id & 0xff;
  out.writeUInt32BE(payload.length, 4);
  if (payload.length > 0) {
    Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength).copy(out, 8);
  }
  return out;
}

function windowFrame(id: number, amount: number): Buffer {
  const out = Buffer.allocUnsafe(12);
  out[0] = 0x04;
  out[1] = (id >>> 16) & 0xff;
  out[2] = (id >>> 8) & 0xff;
  out[3] = id & 0xff;
  out.writeUInt32BE(4, 4);
  out.writeUInt32BE(amount >>> 0, 8);
  return out;
}

function tagKind(tag: Uint8Array): number {
  if (tag[0] === 0xef && tag[1] === 0xef && tag[2] === 0xef && tag[3] === 0xef) return 1; // abridged
  if (tag[0] === 0xee && tag[1] === 0xee && tag[2] === 0xee && tag[3] === 0xee) return 2; // intermediate
  if (tag[0] === 0xdd && tag[1] === 0xdd && tag[2] === 0xdd && tag[3] === 0xdd) return 3; // padded intermediate
  return 0;
}

function safeDcHeaderPrefix(bytes: Uint8Array): boolean {
  if (bytes[0] === 0xef) return false;
  if (bytes[4] === 0 && bytes[5] === 0 && bytes[6] === 0 && bytes[7] === 0) return false;
  if (bytes[0] === 0x47 && bytes[1] === 0x45 && bytes[2] === 0x54 && bytes[3] === 0x20) return false;
  if (bytes[0] === 0x50 && bytes[1] === 0x4f && bytes[2] === 0x53 && bytes[3] === 0x54) return false;
  if (bytes[0] === 0x48 && bytes[1] === 0x45 && bytes[2] === 0x41 && bytes[3] === 0x44) return false;
  if (bytes[0] === 0x4f && bytes[1] === 0x50 && bytes[2] === 0x54 && bytes[3] === 0x49) return false;
  if (bytes[0] === 0xee && bytes[1] === 0xee && bytes[2] === 0xee && bytes[3] === 0xee) return false;
  if (bytes[0] === 0xdd && bytes[1] === 0xdd && bytes[2] === 0xdd && bytes[3] === 0xdd) return false;
  if (bytes[0] === 0x16 && bytes[1] === 0x03 && bytes[2] === 0x01 && bytes[3] === 0x02) return false;
  return true;
}

function connectTcpWithTimeout(host: string, port: number, timeoutMs = 3000): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error("connect timeout"));
    }, timeoutMs);

    const cleanupInit = () => {
      clearTimeout(timer);
      socket.removeListener("connect", onConnect);
      socket.removeListener("error", onError);
    };

    const onConnect = () => {
      if (settled) return;
      settled = true;
      cleanupInit();
      socket.setNoDelay(true);
      socket.setKeepAlive(true, 30000);
      resolve(socket);
    };

    const onError = (err: Error) => {
      if (settled) return;
      settled = true;
      cleanupInit();
      socket.destroy();
      reject(err);
    };

    socket.once("connect", onConnect);
    socket.once("error", onError);
  });
}

class Stream {
  private session: WsSession;
  readonly id: number;
  private phase: "header" | "ready" = "header";
  private header = Buffer.alloc(64);
  private headerLength = 0;
  private dead = false;
  private socket: net.Socket | null = null;
  private inQueue: Buffer[] = [];
  private inRunning = false;
  private queuedLocal = 0;
  private recvOutstanding = 0;
  private sendCredit: number;
  private pendingDown: Buffer | null = null;
  private drainWaiters: Array<() => void> = [];
  private dcKey = 0;
  private dcTarget = "";
  private dcSentPayloadBytes = 0;
  private dcRecvBytes = 0;

  private clientReadCipher: ObfuscatedCtrStream | null = null;
  private dcWriteCipher: ObfuscatedCtrStream | null = null;

  constructor(session: WsSession, id: number) {
    this.session = session;
    this.id = id;
    this.sendCredit = session.cfg.streamWindow;
    STATS.streams++;
    session.streamCount++;
  }

  feed(payload: Buffer): void {
    if (this.dead || !payload.length) return;
    this.recvOutstanding += payload.length;
    if (this.recvOutstanding > this.session.cfg.streamWindow + 65536) {
      this.kill(true);
      return;
    }
    const copy = Buffer.from(payload);
    this.inQueue.push(copy);
    this.queuedLocal += copy.length;
    this.session.queued += copy.length;
    if (this.session.queued > this.session.cfg.maxQueued) {
      this.kill(true);
      return;
    }
    void this.runIn();
  }

  private async runIn(): Promise<void> {
    if (this.inRunning || this.dead) return;
    this.inRunning = true;
    try {
      while (!this.dead && this.inQueue.length > 0) {
        let payload = this.inQueue[0];
        if (this.phase === "header") {
          const need = 64 - this.headerLength;
          const take = Math.min(need, payload.length);
          payload.copy(this.header, this.headerLength, 0, take);
          this.headerLength += take;
          this.queuedLocal -= take;
          this.session.queued -= take;
          if (take < payload.length) {
            this.inQueue[0] = payload.subarray(take);
          } else {
            this.inQueue.shift();
          }
          if (this.headerLength === 64) {
            await this.init();
            this.grant(64);
          }
          continue;
        }

        this.inQueue.shift();
        this.queuedLocal -= payload.length;
        this.session.queued -= payload.length;
        await this.writeToDc(payload);
      }
    } catch {
      this.kill(true);
    } finally {
      this.inRunning = false;
      if (!this.dead && this.inQueue.length > 0) {
        void this.runIn();
      }
    }
  }

  private async init(): Promise<void> {
    const header = this.header;
    const readKey = sha256(concat(header.subarray(8, 40), this.session.secret));
    const readIv = header.subarray(40, 56);
    this.clientReadCipher = new ObfuscatedCtrStream(readKey, readIv, 56);
    const tail = this.clientReadCipher.update(header.subarray(56, 64));

    const tag = tail.subarray(0, 4);
    if (!tagKind(tag)) throw new Error("bad tag");

    const dcId = tail.readInt16LE(4);
    const dcKey = Math.abs(dcId);
    this.dcKey = dcKey;
    const address = this.session.cfg.dc[dcKey];
    if (!address) throw new Error("bad dc");

    const candidateIps = Array.isArray(address) ? address : [address];
    const candidatePorts = Array.isArray(this.session.cfg.dcPorts)
      ? this.session.cfg.dcPorts
      : [this.session.cfg.dcPort || 443];

    if (this.session.cfg.adTag && this.session.cfg.debug && !this.session.loggedMeNotice) {
      this.session.loggedMeNotice = true;
      console.log(
        "[proxygosha] AD_TAG configured. Running in Direct-DC mode (ME handshake omitted)."
      );
    }

    const reversed = reverse(header.subarray(8, 56));
    const writeKey = sha256(concat(reversed.subarray(0, 32), this.session.secret));
    const clientWriteIv = reversed.subarray(32, 48);

    // FAST MODE：构造 dcHeader[8..56] = reverse(clientWriteKey || clientWriteIv)，
    // 使 Telegram DC 下行加密流与客户端解密流完全一致，服务端无需任何下行重加密
    const dcKeyMaterial = reverse(concat(writeKey, clientWriteIv));
    this.dcWriteCipher = new ObfuscatedCtrStream(
      dcKeyMaterial.subarray(0, 32),
      dcKeyMaterial.subarray(32, 48),
      56
    );

    if (this.dead) return;

    const ips = candidateIps.slice();
    for (let i = ips.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [ips[i], ips[j]] = [ips[j], ips[i]];
    }

    const attempts: Array<[string, number]> = [];
    for (const port of candidatePorts) {
      for (const hostIp of ips) {
        attempts.push([hostIp, port]);
      }
    }

    const maxAttempts = Math.min(attempts.length, 4);
    let socket: net.Socket | null = null;
    let lastError: unknown = null;

    for (let a = 0; a < maxAttempts && !socket; a++) {
      if (this.dead) return;
      const [hostIp, port] = attempts[a];
      STATS.dcAttempts++;
      try {
        socket = await connectTcpWithTimeout(hostIp, port, 3000);
        this.dcTarget = `${hostIp}:${port}`;
      } catch (err) {
        lastError = err;
        STATS.dcFails++;
      }
    }

    if (!socket) {
      logEvent("dc_fail", `dc=${dcKey}`);
      throw (lastError instanceof Error ? lastError : new Error("failed to connect to DC"));
    }

    if (this.dead) {
      socket.destroy();
      return;
    }

    this.socket = socket;
    this.attachSocketEvents(socket);

    const dcHeader = Buffer.allocUnsafe(64);
    let safe = false;
    for (let i = 0; i < 16 && !safe; i++) {
      randomBytes(8).copy(dcHeader, 0);
      safe = safeDcHeaderPrefix(dcHeader);
    }
    if (!safe) {
      Buffer.from([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]).copy(dcHeader, 0);
    }
    dcKeyMaterial.copy(dcHeader, 8);
    tag.copy(dcHeader, 56);
    dcHeader.writeInt16LE(dcId, 60);
    dcHeader.writeUInt16LE(0, 62);
    const encryptedTail = this.dcWriteCipher.update(dcHeader.subarray(56, 64));
    encryptedTail.copy(dcHeader, 56);

    await this.writeRawSocket(dcHeader);
    if (this.dead) return;
    this.phase = "ready";

    // Flush any data that arrived while connecting? Already in inQueue, runIn loop handles it!
  }

  private attachSocketEvents(socket: net.Socket): void {
    socket.on("data", (chunk: Buffer) => {
      if (this.dead) return;
      this.handleDcData(chunk);
    });

    socket.on("drain", () => {
      const waiters = this.drainWaiters.splice(0);
      for (const resolve of waiters) resolve();
    });

    socket.on("end", () => {
      this.kill(true);
    });

    socket.on("close", () => {
      this.kill(true);
    });

    socket.on("error", () => {
      this.kill(true);
    });
  }

  private writeRawSocket(data: Buffer): Promise<void> {
    if (this.dead || !this.socket || this.socket.destroyed) {
      return Promise.reject(new Error("socket closed"));
    }
    const ok = this.socket.write(data);
    if (ok) return Promise.resolve();
    return new Promise((resolve) => {
      if (this.dead) {
        resolve();
        return;
      }
      this.drainWaiters.push(resolve);
    });
  }

  private async writeToDc(payload: Buffer): Promise<void> {
    if (this.dead || !this.clientReadCipher || !this.dcWriteCipher) return;
    const plain = this.clientReadCipher.update(payload);
    if (this.dead) return;
    const encrypted = this.dcWriteCipher.update(plain);
    this.dcSentPayloadBytes += encrypted.length;
    await this.writeRawSocket(encrypted);
    this.grant(payload.length);
  }

  private handleDcData(chunk: Buffer): void {
    this.dcRecvBytes += chunk.length;
    const combined = this.pendingDown ? Buffer.concat([this.pendingDown, chunk]) : chunk;
    this.pendingDown = null;

    let offset = 0;
    while (offset < combined.length && !this.dead) {
      if (this.sendCredit <= 0) {
        this.pendingDown = Buffer.from(combined.subarray(offset));
        if (this.socket && !this.socket.destroyed) {
          this.socket.pause();
        }
        return;
      }
      const size = Math.min(
        combined.length - offset,
        this.sendCredit,
        this.session.cfg.dataChunk
      );
      if (size <= 0) break;
      const slice = combined.subarray(offset, offset + size);
      this.sendCredit -= size;
      this.session.sendFrame(frame(0x02, this.id, slice));
      offset += size;
    }

    if (this.sendCredit <= 0 && this.socket && !this.socket.destroyed) {
      this.socket.pause();
    }
  }

  addCredit(amount: number): void {
    if (this.dead) return;
    this.sendCredit = Math.min(0xffffffff, this.sendCredit + amount);
    if (this.pendingDown && this.sendCredit > 0) {
      const rem = this.pendingDown;
      this.pendingDown = null;
      this.handleDcData(rem);
    }
    if (this.sendCredit > 0 && !this.pendingDown && this.socket && !this.socket.destroyed) {
      this.socket.resume();
    }
  }

  private grant(amount: number): void {
    if (this.dead || amount <= 0) return;
    this.recvOutstanding = Math.max(0, this.recvOutstanding - amount);
    this.session.sendFrame(windowFrame(this.id, amount));
  }

  kill(notify: boolean): void {
    if (this.dead) return;
    this.dead = true;
    this.session.streams.delete(this.id);
    this.session.remember(this.id);
    this.session.queued -= this.queuedLocal;
    if (this.session.queued < 0) this.session.queued = 0;
    this.queuedLocal = 0;
    this.inQueue.length = 0;
    this.pendingDown = null;

    const waiters = this.drainWaiters.splice(0);
    for (const resolve of waiters) resolve();

    if (this.socket) {
      if (this.dcSentPayloadBytes > 0 && this.dcRecvBytes === 0) {
        STATS.dcEmptyCloses++;
        logEvent(
          "dc_eof_empty",
          `dc=${this.dcKey} target=${this.dcTarget} up=${this.dcSentPayloadBytes}B down=0B`
        );
      }
      try {
        this.socket.removeAllListeners();
        this.socket.destroy();
      } catch {
        // ignore
      }
      this.socket = null;
    }

    if (notify && !this.session.closed) {
      this.session.sendFrame(frame(0x03, this.id, EMPTY));
    }
    this.session.onStreamClosed(this.id);
  }
}

class WsSession {
  readonly laneId: number;
  private laneUsed = false;
  private ws: WebSocket;
  readonly cfg: ProxyRuntime;
  readonly secret: Buffer;
  readonly streams = new Map<number, Stream>();
  closed = false;
  queued = 0;
  private tombstones = new Set<number>();
  private tombstoneOrder: number[] = [];
  private chain: Promise<void> = Promise.resolve();
  loggedMeNotice = false;
  private lastPong = Date.now();
  private openedAt = Date.now();
  private bytesUp = 0;
  private bytesDown = 0;
  streamCount = 0;
  private keepAliveTimer: ReturnType<typeof setInterval> | null = null;

  constructor(ws: WebSocket, cfg: ProxyRuntime, secret: Buffer, laneId = 0) {
    this.laneId = laneId;
    this.ws = ws;
    this.cfg = cfg;
    this.secret = secret;
    STATS.sessions++;
    STATS.sessionsActive++;
    logEvent("session_open", `lane=${laneId} carrier=${cfg.carrier}`);

    if (!laneId) {
      this.keepAliveTimer = setInterval(() => {
        if (this.closed || this.ws.readyState !== WebSocket.OPEN) {
          if (this.keepAliveTimer) {
            clearInterval(this.keepAliveTimer);
            this.keepAliveTimer = null;
          }
          return;
        }
        if (Date.now() - this.lastPong > 90000) {
          this.shutdown("pong watchdog");
          return;
        }
        try {
          const pingPayload = Buffer.allocUnsafe(4);
          pingPayload.writeUInt32BE(Math.floor(Date.now() / 1000), 0);
          this.sendFrame(frame(0x05, 0, pingPayload));
        } catch {
          // ignore
        }
      }, 25000);
    }
  }

  sendFrame(bytes: Buffer): void {
    if (this.closed || this.ws.readyState !== WebSocket.OPEN) return;
    try {
      this.ws.send(bytes, { binary: true });
      this.bytesDown += bytes.length;
      STATS.bytesDown += bytes.length;
    } catch {
      this.dispose();
    }
  }

  onStreamClosed(id: number): void {
    if (!this.laneId || this.closed || id !== this.laneId) return;
    this.dispose();
    try {
      if (this.ws.readyState === WebSocket.OPEN) {
        this.ws.close(1000, "done");
      }
    } catch {
      // ignore
    }
  }

  remember(id: number): void {
    if (this.tombstones.has(id)) return;
    if (this.tombstoneOrder.length === 4096) {
      const oldest = this.tombstoneOrder.shift();
      if (oldest !== undefined) this.tombstones.delete(oldest);
    }
    this.tombstones.add(id);
    this.tombstoneOrder.push(id);
  }

  enqueue(data: Buffer): void {
    this.chain = this.chain.then(() => this.handle(data)).catch(() => this.shutdown());
  }

  private async handle(bytes: Buffer): Promise<void> {
    if (this.closed) return;
    if (!Buffer.isBuffer(bytes)) {
      this.shutdown();
      return;
    }
    if (bytes.length === 0 || bytes.length > REQUEST_LIMIT) {
      this.shutdown();
      return;
    }
    this.bytesUp += bytes.length;
    STATS.bytesUp += bytes.length;

    let offset = 0;
    let frames = 0;
    while (offset < bytes.length) {
      if (bytes.length - offset < 8 || ++frames > 4096) {
        this.shutdown();
        return;
      }
      const type = bytes[offset];
      const id = (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
      const size = bytes.readUInt32BE(offset + 4);
      const end = offset + 8 + size;
      if (size > 1048576 || end > bytes.length) {
        this.shutdown();
        return;
      }
      const payload = bytes.subarray(offset + 8, end);
      offset = end;

      if (this.laneId && id !== this.laneId) {
        this.shutdown();
        return;
      }

      if (type === 0x01) {
        // OPEN
        if (id === 0 || size !== 0) {
          this.shutdown();
          return;
        }
        if (this.laneId) {
          if (this.laneUsed) {
            this.shutdown();
            return;
          }
          this.laneUsed = true;
          this.streams.set(id, new Stream(this, id));
          continue;
        }
        if (
          this.streams.has(id) ||
          this.tombstones.has(id) ||
          this.streams.size >= this.cfg.maxStreams
        ) {
          this.sendFrame(frame(0x03, id, EMPTY));
          continue;
        }
        this.streams.set(id, new Stream(this, id));
      } else if (type === 0x02) {
        // DATA
        if (id === 0 || size === 0) {
          this.shutdown();
          return;
        }
        const stream = this.streams.get(id);
        if (stream) {
          stream.feed(payload);
        } else if (!this.tombstones.has(id)) {
          this.sendFrame(frame(0x03, id, EMPTY));
        }
      } else if (type === 0x03) {
        // CLOSE
        if (id === 0 || size !== 0) {
          this.shutdown();
          return;
        }
        const stream = this.streams.get(id);
        if (stream) stream.kill(false);
      } else if (type === 0x04) {
        // WINDOW
        if (id === 0 || size !== 4) {
          this.shutdown();
          return;
        }
        const stream = this.streams.get(id);
        if (stream) stream.addCredit(payload.readUInt32BE(0));
      } else if (type === 0x05) {
        // PING
        if (id === 0) {
          if (size > 64) {
            this.shutdown();
            return;
          }
          this.sendFrame(frame(0x06, 0, payload));
        }
      } else if (type === 0x06) {
        // PONG
        if (id !== 0) {
          this.shutdown();
          return;
        }
        this.lastPong = Date.now();
      } else {
        this.shutdown();
        return;
      }
    }
  }

  dispose(): void {
    if (this.closed) return;
    this.closed = true;
    STATS.sessionsActive = Math.max(0, STATS.sessionsActive - 1);
    logEvent(
      "session_close",
      `${fmtDuration(Date.now() - this.openedAt)} streams=${this.streamCount} up=${fmtBytes(this.bytesUp)} down=${fmtBytes(this.bytesDown)}`
    );
    if (this.keepAliveTimer) {
      clearInterval(this.keepAliveTimer);
      this.keepAliveTimer = null;
    }
    for (const stream of Array.from(this.streams.values())) {
      stream.kill(false);
    }
    this.streams.clear();
    this.tombstones.clear();
    this.tombstoneOrder.length = 0;
    this.queued = 0;
  }

  shutdown(reason?: string): void {
    logEvent("session_kill", reason || "protocol");
    this.dispose();
    try {
      if (this.ws.readyState === WebSocket.OPEN) {
        this.ws.close(1011, "closed");
      }
    } catch {
      // ignore
    }
  }
}

function rejectUpgrade(socket: Duplex, status = 404, message = "Not Found"): void {
  try {
    socket.write(
      `HTTP/1.1 ${status} ${status === 404 ? "Not Found" : "Bad Request"}\r\n` +
        `Content-Type: text/plain; charset=utf-8\r\n` +
        `Content-Length: ${Buffer.byteLength(message)}\r\n` +
        `Cache-Control: no-store\r\n` +
        `Connection: close\r\n\r\n${message}`
    );
    socket.destroy();
  } catch {
    socket.destroy();
  }
}

export function attachWebSocketServer(
  httpServer: HttpServer,
  getCfg: () => ProxyRuntime | null
): void {
  const wss = new WebSocketServer({
    noServer: true,
    perMessageDeflate: false,
    maxPayload: REQUEST_LIMIT,
    handleProtocols: (protocols) => {
      if (protocols.size !== 1) return false;
      const [first] = protocols;
      return first;
    },
  });

  httpServer.on("upgrade", (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    try {
      const cfg = getCfg();
      if (!cfg) {
        rejectUpgrade(socket, 404);
        return;
      }

      const rawUrl = req.url || "/";
      const parsed = new URL(rawUrl, "http://localhost");
      if (parsed.pathname !== cfg.wsPath && parsed.pathname !== "/api/v1/ws") {
        // Do not interfere with non-proxy upgrades (if any); otherwise reject.
        rejectUpgrade(socket, 404);
        return;
      }

      const host = requestHost(req);
      const port = requestPort(req);
      recordTunnelHeaders(req, host);

      if (!hostAllowed(cfg, host)) {
        rejectUpgrade(socket, 404);
        return;
      }

      if (req.method !== "GET") {
        rejectUpgrade(socket, 404);
        return;
      }
      if (req.headers.authorization) {
        rejectUpgrade(socket, 404);
        return;
      }

      const rawProtocols = req.headers["sec-websocket-protocol"];
      const protocolHeader = Array.isArray(rawProtocols) ? rawProtocols.join(",") : (rawProtocols || "");
      const offered = protocolHeader
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean);

      if (offered.length !== 1) {
        rejectUpgrade(socket, 404);
        return;
      }

      const protocol = offered[0];
      let token = "";
      let laneId = 0;

      if (protocol.startsWith("tproxy-v1.")) {
        token = protocol.substring(10);
      } else if (protocol.startsWith("tproxy-lane-v1.")) {
        const rest = protocol.substring(15);
        const dot = rest.lastIndexOf(".");
        if (dot <= 0 || !/^[1-9][0-9]{0,7}$/.test(rest.substring(dot + 1))) {
          rejectUpgrade(socket, 404);
          return;
        }
        token = rest.substring(0, dot);
        laneId = parseInt(rest.substring(dot + 1), 10);
        if (laneId > 0xffffff) {
          rejectUpgrade(socket, 404);
          return;
        }
      } else {
        rejectUpgrade(socket, 404);
        return;
      }

      const verified = verifyToken(cfg, token, TOKEN_KIND_SESSION);
      if (!verified) {
        STATS.wsRejects++;
        logEvent("ws_reject", "invalid or expired session token");
        rejectUpgrade(socket, 404);
        return;
      }

      if ((verified.mode === 1 || verified.mode === 2) && !cfg.acceptGenerated) {
        rejectUpgrade(socket, 404);
        return;
      }

      let secret: Buffer | null = cfg.base;
      if (
        verified.mode >= PORT_MODE_BASE &&
        verified.mode < PORT_MODE_BASE + HTTPS_PORTS.length
      ) {
        const portNum = HTTPS_PORTS[verified.mode - PORT_MODE_BASE];
        secret = cfg.portSecrets[portNum]?.secret || cfg.base;
      } else if (verified.mode === 1 || verified.mode === 2) {
        const label =
          verified.mode === 2 && port && port !== "443" && port !== "80"
            ? `${host}:${port}`
            : host;
        secret = deriveSecret(cfg, label);
      }

      if (!secret) {
        rejectUpgrade(socket, 404);
        return;
      }

      const finalSecret = secret;
      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.binaryType = "nodebuffer";
        let session: WsSession;
        try {
          session = new WsSession(ws, cfg, finalSecret, laneId);
        } catch (err) {
          reportError("ws session", err);
          try {
            ws.close(1011, "error");
          } catch {
            // ignore
          }
          return;
        }

        ws.on("message", (data: Buffer | ArrayBuffer | Buffer[], isBinary: boolean) => {
          try {
            if (!isBinary) {
              session.shutdown("non-binary");
              return;
            }
            const buf = Buffer.isBuffer(data)
              ? data
              : Array.isArray(data)
              ? Buffer.concat(data)
              : Buffer.from(data);
            session.enqueue(buf);
          } catch (err) {
            reportError("ws message", err);
            try {
              session.shutdown("handler error");
            } catch {
              // ignore
            }
          }
        });

        ws.on("close", () => {
          try {
            session.dispose();
          } catch (err) {
            reportError("ws close", err);
          }
        });

        ws.on("error", () => {
          try {
            session.dispose();
          } catch (err) {
            reportError("ws error", err);
          }
        });
      });
    } catch (err) {
      reportError("ws upgrade", err);
      rejectUpgrade(socket, 404);
    }
  });
}

function probeSingleDc(dc: number, ip: string, port: number): Promise<ProbeResult> {
  return new Promise((resolve) => {
    const started = Date.now();
    let tcpMs = 0;
    let tcpConnected = false;
    let settled = false;
    let rxBytes = 0;
    const sock = net.createConnection({ host: ip, port });

    const finish = (mtprotoOk: boolean | null, reason: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        sock.removeAllListeners();
        sock.destroy();
      } catch {
        // ignore
      }
      resolve({
        dc,
        ip,
        port,
        ok: tcpConnected,
        ms: tcpConnected ? tcpMs : Date.now() - started,
        mtprotoOk,
        mtprotoMs: tcpConnected ? Date.now() - started : null,
        reason,
      });
    };

    const timer = setTimeout(() => {
      finish(dc === 203 && tcpConnected ? null : false, tcpConnected ? "mtproto_timeout" : "tcp_timeout");
    }, 3000);

    sock.once("connect", () => {
      tcpConnected = true;
      tcpMs = Date.now() - started;
      sock.setNoDelay(true);

      // DC203 为媒体/CDN 节点，不直接响应明文 req_pq_multi，仅保留 TCP 连通测试
      if (dc === 203) {
        finish(null, "cdn_tcp_ok");
        return;
      }

      // 构造无 secret 的标准 Obfuscated2 (0xef 缩写模式) + req_pq_multi 握手包，验证真实 MTProto 可达性
      const nonce = Buffer.allocUnsafe(64);
      let safe = false;
      for (let i = 0; i < 16 && !safe; i++) {
        randomBytes(56).copy(nonce, 0);
        safe = safeDcHeaderPrefix(nonce);
      }
      if (!safe) {
        Buffer.from([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]).copy(nonce, 0);
      }
      const writeKey = nonce.subarray(8, 40);
      const writeIv = nonce.subarray(40, 56);
      const rev = reverse(nonce.subarray(8, 56));
      const readKey = rev.subarray(0, 32);
      const readIv = rev.subarray(32, 48);

      const enc = createCipheriv("aes-256-ctr", writeKey, writeIv);
      enc.update(Buffer.alloc(56));
      const dec = createCipheriv("aes-256-ctr", readKey, readIv);

      const tail = Buffer.alloc(8);
      tail.fill(0xef, 0, 4);
      tail.writeInt16LE(dc, 4);
      tail.writeUInt16LE(0, 6);
      enc.update(tail).copy(nonce, 56);

      const reqPq = Buffer.alloc(40);
      reqPq.writeBigUInt64LE(0n, 0);
      reqPq.writeBigUInt64LE(BigInt(Math.floor(Date.now() / 1000)) << 32n, 8);
      reqPq.writeInt32LE(20, 16);
      reqPq.writeUInt32LE(0xbe7e8ef1, 20);
      randomBytes(16).copy(reqPq, 24);
      const encReq = enc.update(Buffer.concat([Buffer.from([10]), reqPq]));

      const rxChunks: Buffer[] = [];
      sock.on("data", (chunk: Buffer) => {
        rxBytes += chunk.length;
        rxChunks.push(dec.update(chunk));
        if (rxBytes >= 25) {
          const plain = Buffer.concat(rxChunks);
          const validUnencrypted = plain.subarray(1, 9).equals(Buffer.alloc(8));
          finish(validUnencrypted, validUnencrypted ? "resPQ_ok" : "invalid_reply");
        }
      });

      sock.write(Buffer.concat([nonce, encReq]));
    });

    sock.once("end", () => finish(false, `eof(${rxBytes}B)`));
    sock.once("close", () => finish(false, `close(${rxBytes}B)`));
    sock.once("error", (err) => finish(false, err.message));
  });
}

export async function probeDcs(cfg: ProxyRuntime): Promise<ProbeResult[]> {
  const keys = Object.keys(cfg.dc)
    .map(Number)
    .sort((a, b) => a - b);
  const results: ProbeResult[] = [];
  const probePort = cfg.dcPorts?.[0] || cfg.dcPort || 443;

  const probeOne = async (key: number) => {
    const ips = Array.isArray(cfg.dc[key]) ? cfg.dc[key] : [cfg.dc[key]];
    const ip = ips[Math.floor(Math.random() * ips.length)];
    const r = await probeSingleDc(key, ip, probePort);
    results.push(r);
  };

  for (let i = 0; i < keys.length; i += 3) {
    await Promise.all(keys.slice(i, i + 3).map(probeOne));
  }

  results.sort((a, b) => a.dc - b.dc);
  logEvent(
    "dc_probe",
    results
      .map((r) => `DC${r.dc}:${r.ok ? (r.mtprotoOk === false ? "tcp_only_eof" : "ok") : "fail"}`)
      .join(" ")
  );
  return results;
}
