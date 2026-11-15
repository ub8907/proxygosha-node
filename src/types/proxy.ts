export interface TunnelStatusData {
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

export interface SetupStatusData {
  configured: boolean;
  host: string;
  proto: "https" | "http";
  adminKeyTooShort: boolean;
  suggestedKey: string;
  tunnel: TunnelStatusData;
  version: string;
}

export interface PortLinkEntry {
  port: number;
  isDefault: boolean;
  secret: string;
  link: string;
}

export interface HostConfigEntry {
  host: string;
  isLocalhost: boolean;
  isWorkersDev: boolean;
  ports: PortLinkEntry[];
}

export interface LogEntryData {
  t: number;
  event: string;
  detail: string;
}

export interface PanelStateData {
  version: string;
  proto: "https" | "http";
  currentHost: string;
  ephemeralSetup: boolean;
  config: {
    carrier: "websocket" | "websocket-lanes";
    secretMode: "derived" | "fixed" | "none";
    maxStreams: number;
    sessionPath: string;
    wsPath: string;
    decoyUrl: string | null;
    adTagConfigured: boolean;
    extraHosts: string[];
    allowedHosts: string[];
  };
  hostConfigs: HostConfigEntry[];
  stats: {
    sessions: number;
    sessionsActive: number;
    streams: number;
    dcAttempts: number;
    dcFails: number;
    dcSuccess: number;
    bytesUp: number;
    bytesDown: number;
    bytesUpFormatted: string;
    bytesDownFormatted: string;
    wsRejects: number;
    panelViews: number;
    statusViews: number;
    uptimeMs: number;
    uptimeFormatted: string;
  };
  tunnel: TunnelStatusData;
  logs: LogEntryData[];
}

export interface ProbeResultData {
  dc: number;
  ip: string;
  ok: boolean;
  ms: number;
}
