import { spawn, execSync, type ChildProcess } from "node:child_process";
import type { IncomingMessage } from "node:http";
import { logEvent, STATS } from "./telemetry.ts";

export interface TunnelStatus {
  binaryAvailable: boolean;
  autostartEnabled: boolean;
  tokenConfigured: boolean;
  running: boolean;
  pid: number | null;
  requestsViaTunnel: number;
  lastTunnelHost: string;
  lastRayColo: string;
  lastError: string;
}

let tunnelProcess: ChildProcess | null = null;
let tunnelRunning = false;
let tunnelLastError = "";
let restartTimer: ReturnType<typeof setTimeout> | null = null;
let binaryChecked: boolean | null = null;
let stopping = false;

// 检测系统 PATH 中是否存在 cloudflared 可执行文件
export function isCloudflaredAvailable(): boolean {
  if (binaryChecked !== null) return binaryChecked;
  try {
    execSync("which cloudflared", { stdio: "ignore" });
    binaryChecked = true;
  } catch {
    binaryChecked = false;
  }
  return binaryChecked;
}

// 识别并统计来自 Cloudflare Tunnel 的请求头（不记录客户端真实 IP）
export function recordTunnelHeaders(req: IncomingMessage, resolvedHost: string): boolean {
  const cfRay = req.headers["cf-ray"];
  const cfConnectingIp = req.headers["cf-connecting-ip"];
  const cfVisitor = req.headers["cf-visitor"];
  const viaTunnel = Boolean(cfRay || cfConnectingIp || cfVisitor);
  if (viaTunnel) {
    STATS.tunnelRequests++;
    if (typeof cfRay === "string") {
      const dash = cfRay.lastIndexOf("-");
      STATS.lastTunnelRay = dash > 0 ? cfRay.slice(dash + 1) : cfRay.slice(0, 12);
    }
    if (resolvedHost) {
      STATS.lastTunnelHost = resolvedHost;
    }
  }
  return viaTunnel;
}

// 若配置了 CF_TUNNEL_TOKEN 且开启了自动拉起，则托管启动 cloudflared 子进程
export function startTunnelIfConfigured(port: number): void {
  const token = (process.env.CF_TUNNEL_TOKEN || "").trim();
  const autostart = process.env.CF_TUNNEL_AUTOSTART === "true" || process.env.CF_TUNNEL_AUTOSTART === "1";
  if (!token || !autostart) return;

  if (!isCloudflaredAvailable()) {
    tunnelLastError = "未在系统 PATH 中找到 cloudflared 二进制文件；请在外部手动运行 cloudflared 指向 http://127.0.0.1:" + port;
    logEvent("tunnel_skip", "cloudflared binary missing");
    return;
  }

  if (tunnelProcess || stopping) return;

  try {
    tunnelLastError = "";
    const child = spawn("cloudflared", ["tunnel", "--no-autoupdate", "run", "--token", token], {
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });
    tunnelProcess = child;
    tunnelRunning = true;
    logEvent("tunnel_start", `pid=${child.pid ?? "?"} target=127.0.0.1:${port}`);

    child.stderr?.on("data", (chunk: Buffer) => {
      const line = chunk.toString("utf8").trim();
      if (line.includes("ERR") || line.includes("failed")) {
        tunnelLastError = line.slice(-180);
      }
    });

    child.on("exit", (code, signal) => {
      tunnelRunning = false;
      tunnelProcess = null;
      logEvent("tunnel_exit", `code=${code ?? "null"} sig=${signal ?? "none"}`);
      if (!stopping && (process.env.CF_TUNNEL_AUTOSTART === "true" || process.env.CF_TUNNEL_AUTOSTART === "1")) {
        restartTimer = setTimeout(() => {
          restartTimer = null;
          startTunnelIfConfigured(port);
        }, 5000);
      }
    });

    child.on("error", (err) => {
      tunnelRunning = false;
      tunnelProcess = null;
      tunnelLastError = err.message;
      logEvent("tunnel_error", err.message);
    });
  } catch (err) {
    tunnelLastError = err instanceof Error ? err.message : String(err);
    logEvent("tunnel_error", tunnelLastError);
  }
}

// 优雅停止托管的 cloudflared 隧道进程
export function stopTunnel(): void {
  stopping = true;
  if (restartTimer) {
    clearTimeout(restartTimer);
    restartTimer = null;
  }
  if (tunnelProcess) {
    try {
      tunnelProcess.kill("SIGTERM");
    } catch {
      // 忽略关闭异常
    }
    tunnelProcess = null;
    tunnelRunning = false;
  }
}

export function getTunnelStatus(): TunnelStatus {
  const token = (process.env.CF_TUNNEL_TOKEN || "").trim();
  const autostart = process.env.CF_TUNNEL_AUTOSTART === "true" || process.env.CF_TUNNEL_AUTOSTART === "1";
  return {
    binaryAvailable: isCloudflaredAvailable(),
    autostartEnabled: autostart,
    tokenConfigured: token.length > 0,
    running: tunnelRunning,
    pid: tunnelProcess?.pid ?? null,
    requestsViaTunnel: STATS.tunnelRequests,
    lastTunnelHost: STATS.lastTunnelHost,
    lastRayColo: STATS.lastTunnelRay,
    lastError: tunnelLastError,
  };
}
