export interface SetupStatusData {
  configured: boolean;
  host: string;
  proto: "https" | "http";
  adminKeyTooShort: boolean;
  suggestedKey: string;
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

export interface VlessHostEntry {
  host: string;
  port: string;
  security: "tls" | "none";
  uri: string;
  httpUrl: string;
}

export interface PanelStateData {
  version: string;
  proto: "https" | "http";
  currentHost: string;
  unifiedSecret: string;
  ephemeralSetup: boolean;
  runtimePersisted?: boolean;
  hasRuntimeOverride?: boolean;
  baseEnvConfigured?: boolean;
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
    dcPorts?: number[];
    debug?: boolean;
    generatorEnabled?: boolean;
    acceptGenerated?: boolean;
    vlessEnabled?: boolean;
    vlessUuid?: string;
    vlessPath?: string;
    vlessDisguisedDomain?: string;
  };
  vless: {
    enabled: boolean;
    uuid: string;
    path: string;
    disguisedDomain: string;
    hosts: VlessHostEntry[];
  };
  hostConfigs: HostConfigEntry[];
  stats: {
    sessions: number;
    sessionsActive: number;
    streams: number;
    dcAttempts: number;
    dcFails: number;
    dcEmptyCloses?: number;
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
    vlessConnections?: number;
    vlessActive?: number;
    vlessBytesUpFormatted?: string;
    vlessBytesDownFormatted?: string;
  };
  logs: LogEntryData[];
}

export interface ProbeAltPortResult {
  port: number;
  ok: boolean;
  ms: number;
  mtprotoOk: boolean | null;
  reason: string;
}

export interface ProbeResultData {
  dc: number;
  ip: string;
  port?: number;
  ok: boolean;
  ms: number;
  mtprotoOk?: boolean | null;
  mtprotoMs?: number | null;
  reason?: string;
  altPorts?: ProbeAltPortResult[];
}

export interface WsProbeServerResponse {
  local: {
    ok: boolean;
    rttMs: number;
    listeningPort: number;
    subprotocolOk: boolean;
    binaryEchoOk: boolean;
    error: string | null;
  };
  request: {
    proto: "https" | "http";
    host: string;
    forwardedProto: string;
    forwardedHost: string;
    via: string;
    cfRay: string;
  };
  endpoints: {
    mtprotoWsPath: string;
    vlessWsPath: string | null;
    wsTestPath: string;
  };
}

export interface WsBrowserTestResult {
  ok: boolean;
  wsUrl: string;
  rttMs: number | null;
  handshakeOk: boolean;
  subprotocolOk: boolean;
  negotiatedProtocol: string;
  binaryEchoOk: boolean;
  closeCode: number | null;
  closeReason: string;
  error: string | null;
}
