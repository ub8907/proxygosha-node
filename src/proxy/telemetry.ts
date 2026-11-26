export interface LogEntry {
  t: number;
  event: string;
  detail: string;
}

// 进程启动时间戳与内存遥测计数器（不记录客户端 IP、Token 或 Secret）
export const PROCESS_START = Date.now();

export const STATS = {
  sessions: 0,
  sessionsActive: 0,
  streams: 0,
  dcAttempts: 0,
  dcFails: 0,
  dcEmptyCloses: 0,
  bytesUp: 0,
  bytesDown: 0,
  wsRejects: 0,
  panelViews: 0,
  statusViews: 0,
  vlessConnections: 0,
  vlessActive: 0,
  vlessBytesUp: 0,
  vlessBytesDown: 0,
};

const LOG_LIMIT = 150;
export const LOG: LogEntry[] = [];

// 写入内存环形事件日志
export function logEvent(event: string, detail?: string): void {
  try {
    LOG.push({
      t: Date.now(),
      event: String(event).slice(0, 28),
      detail: String(detail || "").slice(0, 140),
    });
    if (LOG.length > LOG_LIMIT) {
      LOG.splice(0, LOG.length - LOG_LIMIT);
    }
  } catch {
    // 忽略日志写入异常
  }
}

// 统一错误记录（避免异常穿透导致进程退出）
export function reportError(where: string, error: unknown): void {
  try {
    const errObj = error as { stack?: string; message?: string } | null;
    const message = errObj?.stack ? String(errObj.stack) : String(error);
    console.error(`[proxygosha] ${where}: ${message}`);
    logEvent("error", `${where}: ${errObj?.message || message}`);
  } catch {
    // 忽略异常
  }
}

export function fmtBytes(value: number): string {
  const n = Number(value) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

export function fmtDuration(milliseconds: number): string {
  const total = Math.max(0, Math.floor(milliseconds / 1000));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m ${total % 60}s`;
}
