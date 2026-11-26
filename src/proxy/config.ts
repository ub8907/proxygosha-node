import fs from "node:fs";
import path from "node:path";
import type { IncomingMessage } from "node:http";
import {
  DEFAULT_CONFIG,
  HTTPS_PORTS,
  PORT_MODE_BASE,
  TOKEN_DOMAIN,
  TOKEN_KIND_BOOTSTRAP,
  TOKEN_KIND_SESSION,
} from "./constants.ts";
import {
  b64uDecodeStrict,
  b64uEncode,
  bytesToHex,
  concat,
  hmacSha256,
  hmacVerify,
  parseAdTag,
  parseSecret,
  randomTokenBytes,
  safeEqual,
  sha256,
  unseal,
} from "./crypto.ts";

export interface PortSecretEntry {
  secret: Buffer;
  secretHex: string;
  keys: [Buffer, Buffer];
}

export interface VlessRuntimeConfig {
  enabled: boolean;
  uuid: string;
  path: string;
  disguisedDomain: string;
  debug: boolean;
}

export const DEFAULT_VLESS_UUID = "03267b72-5095-44be-8af1-a511b692832b";
export const DEFAULT_VLESS_PATH = "/helloss-jsusyxystsdsahysy";
const VLESS_UUID_REGEX =
  /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;

export interface ProxyRuntime {
  base: Buffer | null;
  portSecrets: Record<number, PortSecretEntry>;
  adminKey: string;
  secretDerived: boolean;
  extraHosts: string[];
  bridgeKeys: Buffer[];
  generatorKeyBytes: Buffer | null;
  tokenKey: Buffer;
  hosts: string[];
  dc: Record<number, string[]>;
  dcPort: number;
  dcPorts: number[];
  adTag: Buffer | null;
  adTagHex: string;
  debug: boolean;
  decoyUrl: string;
  sessionPath: string;
  wsPath: string;
  acceptGenerated: boolean;
  generatorEnabled: boolean;
  streamWindow: number;
  maxQueued: number;
  maxStreams: number;
  dataChunk: number;
  bootstrapTtl: number;
  sessionTtl: number;
  carrier: "websocket" | "websocket-lanes";
  batchBytes: number;
  ephemeralSetup: boolean;
  vlessEnabled: boolean;
  vlessUuid: string;
  vlessPath: string;
  vlessDisguisedDomain: string;
}

const RUNTIME_FILE_PATH = path.resolve(process.cwd(), "storage", "runtime.json");
let runtimeOverrideEnv: Record<string, string> | null = null;
let runtimeFileHash: string | null = null;
let runtimePersisted = false;
let cachedRuntime: ProxyRuntime | null = null;
let cachedKey: string | null = null;

function reloadRuntimeFileIfChanged(): void {
  try {
    if (!fs.existsSync(RUNTIME_FILE_PATH)) {
      if (runtimeFileHash !== null) {
        runtimeFileHash = null;
        runtimePersisted = false;
        runtimeOverrideEnv = null;
        cachedRuntime = null;
        cachedKey = null;
      }
      return;
    }
    const raw = fs.readFileSync(RUNTIME_FILE_PATH, "utf8");
    const hash = `${raw.length}:${bytesToHex(sha256(Buffer.from(raw, "utf8"))).slice(0, 16)}`;
    if (hash === runtimeFileHash) return;
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const clean: Record<string, string> = {};
      for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof v === "string") clean[k] = v;
      }
      runtimeOverrideEnv = clean;
      runtimeFileHash = hash;
      runtimePersisted = true;
      cachedRuntime = null;
      cachedKey = null;
    }
  } catch {
    // 忽略读取异常，保留内存态配置
  }
}

export function setRuntimeOverride(env: Record<string, string> | null): void {
  runtimeOverrideEnv = env;
  runtimePersisted = false;
  cachedRuntime = null;
  cachedKey = null;
}

export function saveRuntimeOverride(override: Record<string, string>): boolean {
  setRuntimeOverride(override);
  try {
    const dir = path.dirname(RUNTIME_FILE_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const raw = JSON.stringify(override, null, 2) + "\n";
    fs.writeFileSync(RUNTIME_FILE_PATH, raw, { encoding: "utf8", mode: 0o600 });
    runtimeFileHash = `${raw.length}:${bytesToHex(sha256(Buffer.from(raw, "utf8"))).slice(0, 16)}`;
    runtimePersisted = true;
    return true;
  } catch {
    runtimePersisted = false;
    return false;
  }
}

export function resetRuntimeOverride(): boolean {
  runtimeOverrideEnv = null;
  runtimeFileHash = null;
  runtimePersisted = false;
  cachedRuntime = null;
  cachedKey = null;
  try {
    if (fs.existsSync(RUNTIME_FILE_PATH)) {
      fs.unlinkSync(RUNTIME_FILE_PATH);
    }
    return true;
  } catch {
    return false;
  }
}

export function isEphemeralSetup(): boolean {
  return runtimeOverrideEnv !== null && !runtimePersisted;
}

export function isRuntimePersisted(): boolean {
  return runtimePersisted;
}

export function hasRuntimeOverride(): boolean {
  return runtimeOverrideEnv !== null;
}

export function hasBaseEnvRuntime(env: NodeJS.ProcessEnv = process.env): boolean {
  return buildRuntime(resolveConfig(env, true)) !== null;
}

export function resolveConfig(env: NodeJS.ProcessEnv, ignoreOverride = false) {
  if (!ignoreOverride) reloadRuntimeFileIfChanged();
  const merged = !ignoreOverride && runtimeOverrideEnv ? { ...env, ...runtimeOverrideEnv } : env;
  const secretHex = (typeof merged.SECRET === "string" ? merged.SECRET : DEFAULT_CONFIG.secretHex || "").trim();
  const adTagHex = (typeof merged.AD_TAG === "string" ? merged.AD_TAG : DEFAULT_CONFIG.adTagHex || "").trim();
  const debug = merged.DEBUG === "true" || merged.DEBUG === "1" || DEFAULT_CONFIG.debug === true;
  const decoyUrl = (typeof merged.DECOY_URL === "string" ? merged.DECOY_URL : "").trim();

  const rawHostnames =
    typeof merged.ALLOWED_HOSTS === "string" && merged.ALLOWED_HOSTS.trim()
      ? merged.ALLOWED_HOSTS
      : typeof merged.HOSTNAME === "string" && merged.HOSTNAME.trim()
      ? merged.HOSTNAME
      : "";

  let hostnames: string[] = [];
  if (rawHostnames) {
    hostnames = rawHostnames
      .split(",")
      .map((s) => s.trim().toLowerCase())
      // 忽略 Linux/Docker 自动注入的无点号主机名（如 container_id、lsd-ProgramNoodle），仅保留 * 或真实域名
      .filter((s) => s === "*" || s.includes("."));
  }
  if (hostnames.length === 0 && Array.isArray(DEFAULT_CONFIG.hostnames)) {
    hostnames = DEFAULT_CONFIG.hostnames.map((s) => String(s).trim().toLowerCase()).filter(Boolean);
  }

  const parsedStreams = merged.MAX_STREAMS ? parseInt(merged.MAX_STREAMS, 10) : NaN;
  const maxStreams = Number.isFinite(parsedStreams)
    ? Math.min(64, Math.max(1, parsedStreams))
    : DEFAULT_CONFIG.maxStreams;

  const sessionPath = (typeof merged.SESSION_PATH === "string" && merged.SESSION_PATH.trim())
    ? (merged.SESSION_PATH.trim().startsWith("/") ? merged.SESSION_PATH.trim() : "/" + merged.SESSION_PATH.trim())
    : DEFAULT_CONFIG.sessionPath;

  const wsPath = (typeof merged.WS_PATH === "string" && merged.WS_PATH.trim())
    ? (merged.WS_PATH.trim().startsWith("/") ? merged.WS_PATH.trim() : "/" + merged.WS_PATH.trim())
    : DEFAULT_CONFIG.wsPath;

  const adminKey = (typeof merged.ADMIN_KEY === "string" ? merged.ADMIN_KEY.trim() : "");

  const extraHosts = (typeof merged.EXTRA_HOSTS === "string" ? merged.EXTRA_HOSTS : "")
    .split(/[,\s]+/)
    .map((value) => value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[:/].*$/, "").replace(/\.$/, ""))
    .filter((value) => /^[a-z0-9.-]+$/.test(value) && !value.includes(".."));

  const carrierEnv = (typeof merged.CARRIER === "string" ? merged.CARRIER.trim().toLowerCase() : "");
  const carrier: "websocket" | "websocket-lanes" =
    carrierEnv === "websocket" || carrierEnv === "websocket-lanes" ? carrierEnv : DEFAULT_CONFIG.carrier;

  let dcPorts: number[] = DEFAULT_CONFIG.dcPorts;
  if (typeof merged.DC_PORTS === "string" && merged.DC_PORTS.trim()) {
    const parsedPorts = merged.DC_PORTS.split(/[,\s]+/)
      .map((v) => parseInt(v.trim(), 10))
      .filter((n) => Number.isFinite(n) && n >= 1 && n <= 65535);
    if (parsedPorts.length > 0) dcPorts = parsedPorts;
  }

  const vlessEnabled =
    merged.VLESS_ENABLED !== undefined
      ? merged.VLESS_ENABLED !== "false" && merged.VLESS_ENABLED !== "0"
      : true;

  const rawUuid = typeof merged.UUID === "string" ? merged.UUID.trim().toLowerCase() : "";
  const vlessUuid = VLESS_UUID_REGEX.test(rawUuid) ? rawUuid : DEFAULT_VLESS_UUID;

  const vlessPath =
    typeof merged.VLESS_PATH === "string" && merged.VLESS_PATH.trim()
      ? merged.VLESS_PATH.trim().startsWith("/")
        ? merged.VLESS_PATH.trim()
        : "/" + merged.VLESS_PATH.trim()
      : DEFAULT_VLESS_PATH;

  const vlessDisguisedDomain =
    (typeof merged.DISGUISED_DOMAIN === "string" && merged.DISGUISED_DOMAIN.trim()) ||
    decoyUrl ||
    "https://example.com";

  return {
    secretHex,
    adminKey,
    extraHosts,
    adTagHex,
    debug,
    hostnames,
    decoyUrl,
    maxStreams,
    sessionPath,
    wsPath,
    generatorEnabled: merged.GENERATOR_ENABLED !== undefined
      ? (merged.GENERATOR_ENABLED === "true" || merged.GENERATOR_ENABLED === "1")
      : DEFAULT_CONFIG.generatorEnabled,
    generatorKey: (typeof merged.GENERATOR_KEY === "string" ? merged.GENERATOR_KEY : DEFAULT_CONFIG.generatorKey || "").trim(),
    acceptGenerated: merged.ACCEPT_GENERATED !== undefined
      ? (merged.ACCEPT_GENERATED === "true" || merged.ACCEPT_GENERATED === "1")
      : DEFAULT_CONFIG.acceptGenerated,
    dc: DEFAULT_CONFIG.dc,
    dcPort: dcPorts[0] || DEFAULT_CONFIG.dcPort,
    dcPorts,
    carrier,
    batchBytes: DEFAULT_CONFIG.batchBytes,
    bootstrapTtl: DEFAULT_CONFIG.bootstrapTtl,
    sessionTtl: DEFAULT_CONFIG.sessionTtl,
    maxQueued: DEFAULT_CONFIG.maxQueued,
    streamWindow: DEFAULT_CONFIG.streamWindow,
    dataChunk: DEFAULT_CONFIG.dataChunk,
    ephemeralSetup: runtimeOverrideEnv !== null,
    vlessEnabled,
    vlessUuid,
    vlessPath,
    vlessDisguisedDomain,
  };
}

export function buildRuntime(cfg: ReturnType<typeof resolveConfig>): ProxyRuntime | null {
  const adminKey = cfg.adminKey && cfg.adminKey.length >= 16 ? cfg.adminKey : "";
  const seal = unseal();
  let base = parseSecret(cfg.secretHex);
  const secretDerived = !base && Boolean(adminKey);

  if (secretDerived) {
    base = sha256(
      concat(
        Buffer.from("proxygosha-secret-from-admin-v2\n", "utf8"),
        seal.bytes,
        Buffer.from("\n" + adminKey, "utf8")
      )
    ).subarray(0, 16);
  }

  const generatorText = String(cfg.generatorKey || "").trim();
  if (!base && !generatorText) return null;

  const fallback = base || sha256(concat(Buffer.from("tgweb-fallback-v1\0", "utf8"), Buffer.from(generatorText, "utf8")));
  const generatorRaw = generatorText
    ? sha256(concat(Buffer.from("tgweb-generator-v1\0", "utf8"), Buffer.from(generatorText, "utf8")))
    : base;

  const bridgeKeys: Buffer[] = [];
  if (base) {
    bridgeKeys.push(base);
    bridgeKeys.push(concat(Buffer.of(0xdd), base));
  }

  // 所有端口统一使用同一个 SECRET（不再按端口派生不同密钥）
  const portSecrets: Record<number, PortSecretEntry> = {};
  if (base) {
    const unifiedHex = "dd" + bytesToHex(base);
    const unifiedKeys: [Buffer, Buffer] = [base, concat(Buffer.of(0xdd), base)];
    for (const p of HTTPS_PORTS) {
      portSecrets[p] = {
        secret: base,
        secretHex: unifiedHex,
        keys: unifiedKeys,
      };
    }
  }

  const tokenKey = sha256(concat(Buffer.from("tgweb-token-key-v1\0", "utf8"), seal.bytes, fallback));
  const hosts = Array.isArray(cfg.hostnames)
    ? cfg.hostnames.map((v) => String(v).trim().toLowerCase()).filter(Boolean)
    : [];
  const adTag = parseAdTag(cfg.adTagHex);

  return {
    base,
    portSecrets,
    adminKey,
    secretDerived,
    extraHosts: cfg.extraHosts || [],
    bridgeKeys,
    generatorKeyBytes: generatorRaw,
    tokenKey,
    hosts,
    dc: cfg.dc,
    dcPort: cfg.dcPort,
    dcPorts: cfg.dcPorts,
    adTag,
    adTagHex: cfg.adTagHex,
    debug: cfg.debug,
    decoyUrl: cfg.decoyUrl,
    sessionPath: cfg.sessionPath,
    wsPath: cfg.wsPath,
    acceptGenerated: cfg.acceptGenerated,
    generatorEnabled: cfg.generatorEnabled,
    streamWindow: cfg.streamWindow,
    maxQueued: cfg.maxQueued,
    maxStreams: cfg.maxStreams,
    dataChunk: cfg.dataChunk,
    bootstrapTtl: cfg.bootstrapTtl,
    sessionTtl: cfg.sessionTtl,
    carrier: cfg.carrier,
    batchBytes: cfg.batchBytes,
    ephemeralSetup: cfg.ephemeralSetup,
    vlessEnabled: cfg.vlessEnabled,
    vlessUuid: cfg.vlessUuid,
    vlessPath: cfg.vlessPath,
    vlessDisguisedDomain: cfg.vlessDisguisedDomain,
  };
}

export function getVlessRuntime(env: NodeJS.ProcessEnv = process.env): VlessRuntimeConfig {
  const resolved = resolveConfig(env);
  return {
    enabled: resolved.vlessEnabled,
    uuid: resolved.vlessUuid,
    path: resolved.vlessPath,
    disguisedDomain: resolved.vlessDisguisedDomain,
    debug: resolved.debug,
  };
}

export function getRuntime(env: NodeJS.ProcessEnv = process.env): ProxyRuntime | null {
  reloadRuntimeFileIfChanged();
  const resolved = resolveConfig(env);
  const cacheKey = `${resolved.secretHex}:${resolved.generatorKey}:${resolved.hostnames.join(",")}:${resolved.adTagHex}:${resolved.decoyUrl}:${resolved.maxStreams}:${resolved.sessionPath}:${resolved.wsPath}:${resolved.debug}:${resolved.carrier}:${resolved.acceptGenerated}:${resolved.generatorEnabled}:${resolved.adminKey}:${resolved.extraHosts.join(",")}:${resolved.dcPorts.join(",")}:${resolved.ephemeralSetup}:${resolved.vlessEnabled}:${resolved.vlessUuid}:${resolved.vlessPath}:${resolved.vlessDisguisedDomain}`;
  if (cachedRuntime && cachedKey === cacheKey) {
    return cachedRuntime;
  }
  const runtime = buildRuntime(resolved);
  cachedRuntime = runtime;
  cachedKey = cacheKey;
  return runtime;
}

export function buildOverrideFromConfigInput(
  body: Record<string, unknown>,
  currentCfg: ProxyRuntime,
  env: NodeJS.ProcessEnv = process.env
): { ok: true; override: Record<string, string> } | { ok: false; error: string } {
  const currentResolved = resolveConfig(env);

  const adminKeyRaw = typeof body.adminKey === "string" ? body.adminKey.trim() : currentCfg.adminKey;
  if (adminKeyRaw.length < 16 || !/^[A-Za-z0-9_-]+$/.test(adminKeyRaw)) {
    return { ok: false, error: "ADMIN_KEY must be at least 16 characters (letters, digits, - or _)." };
  }

  let secretHex = currentResolved.secretHex;
  const secretAction = typeof body.secretAction === "string" ? body.secretAction : "keep";
  if (secretAction === "derive") {
    secretHex = "";
  } else if (secretAction === "set") {
    const rawSecret = typeof body.secret === "string" ? body.secret.trim() : "";
    if (!parseSecret(rawSecret)) {
      return { ok: false, error: "SECRET must be 32 hex chars or dd + 32 hex chars." };
    }
    secretHex = rawSecret.toLowerCase();
  }

  const carrier = body.carrier === "websocket" || body.carrier === "websocket-lanes"
    ? body.carrier
    : currentCfg.carrier;

  const maxStreamsNum = typeof body.maxStreams === "number"
    ? Math.trunc(body.maxStreams)
    : parseInt(String(body.maxStreams ?? currentCfg.maxStreams), 10);
  if (!Number.isFinite(maxStreamsNum) || maxStreamsNum < 1 || maxStreamsNum > 64) {
    return { ok: false, error: "MAX_STREAMS must be an integer between 1 and 64." };
  }

  const allowedRaw = typeof body.allowedHosts === "string"
    ? body.allowedHosts
    : currentCfg.hosts.join(", ");
  const allowedList = allowedRaw
    .split(/[,\s]+/)
    .map((s) => s.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[:/].*$/, "").replace(/\.$/, ""))
    .filter(Boolean);
  for (const h of allowedList) {
    if (h !== "*" && (!/^[a-z0-9.-]+$/.test(h) || h.includes("..") || !h.includes("."))) {
      return { ok: false, error: `Invalid ALLOWED_HOSTS entry: ${h}` };
    }
  }
  const allowedHostsStr = allowedList.length > 0 ? Array.from(new Set(allowedList)).join(",") : "*";

  const extraRaw = typeof body.extraHosts === "string"
    ? body.extraHosts
    : currentCfg.extraHosts.join(", ");
  const extraList = extraRaw
    .split(/[,\s]+/)
    .map((s) => s.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[:/].*$/, "").replace(/\.$/, ""))
    .filter(Boolean);
  for (const h of extraList) {
    if (!/^[a-z0-9.-]+$/.test(h) || h.includes("..")) {
      return { ok: false, error: `Invalid EXTRA_HOSTS entry: ${h}` };
    }
  }
  const extraHostsStr = Array.from(new Set(extraList)).join(",");

  const decoyUrlRaw = typeof body.decoyUrl === "string" ? body.decoyUrl.trim() : currentCfg.decoyUrl;
  if (decoyUrlRaw !== "") {
    if (!/^https?:\/\/.+/i.test(decoyUrlRaw)) {
      return { ok: false, error: "DECOY_URL must start with http:// or https://, or be empty." };
    }
    try {
      new URL(decoyUrlRaw);
    } catch {
      return { ok: false, error: "DECOY_URL is not a valid URL." };
    }
  }

  let sessionPath = typeof body.sessionPath === "string" ? body.sessionPath.trim() : currentCfg.sessionPath;
  if (!sessionPath) sessionPath = "/api/v1/session";
  if (!sessionPath.startsWith("/")) sessionPath = "/" + sessionPath;
  if (!/^\/[A-Za-z0-9/_-]+$/.test(sessionPath)) {
    return { ok: false, error: "SESSION_PATH contains invalid characters." };
  }

  let wsPath = typeof body.wsPath === "string" ? body.wsPath.trim() : currentCfg.wsPath;
  if (!wsPath) wsPath = "/api/v1/ws";
  if (!wsPath.startsWith("/")) wsPath = "/" + wsPath;
  if (!/^\/[A-Za-z0-9/_-]+$/.test(wsPath)) {
    return { ok: false, error: "WS_PATH contains invalid characters." };
  }
  if (wsPath === sessionPath) {
    return { ok: false, error: "WS_PATH and SESSION_PATH must be different." };
  }

  const dcPortsRaw = typeof body.dcPorts === "string"
    ? body.dcPorts
    : currentCfg.dcPorts.join(",");
  const dcPortsList = dcPortsRaw
    .split(/[,\s]+/)
    .map((v) => parseInt(v.trim(), 10))
    .filter((n) => Number.isFinite(n) && n >= 1 && n <= 65535);
  if (dcPortsList.length === 0) {
    return { ok: false, error: "DC_PORTS must contain at least one valid port (1–65535)." };
  }
  const dcPortsStr = Array.from(new Set(dcPortsList)).join(",");

  let adTagHex = currentResolved.adTagHex;
  const adTagAction = typeof body.adTagAction === "string" ? body.adTagAction : "keep";
  if (adTagAction === "clear") {
    adTagHex = "";
  } else if (adTagAction === "set") {
    const rawTag = typeof body.adTag === "string" ? body.adTag.trim() : "";
    if (!parseAdTag(rawTag)) {
      return { ok: false, error: "AD_TAG must be exactly 32 hexadecimal characters." };
    }
    adTagHex = rawTag.toLowerCase();
  }

  const debugFlag = typeof body.debug === "boolean" ? body.debug : currentCfg.debug;
  const generatorEnabled = typeof body.generatorEnabled === "boolean" ? body.generatorEnabled : currentCfg.generatorEnabled;
  const acceptGenerated = typeof body.acceptGenerated === "boolean" ? body.acceptGenerated : currentCfg.acceptGenerated;

  const vlessEnabled = typeof body.vlessEnabled === "boolean" ? body.vlessEnabled : currentCfg.vlessEnabled;
  const vlessUuid = typeof body.vlessUuid === "string"
    ? body.vlessUuid.trim().toLowerCase()
    : currentCfg.vlessUuid;
  if (!VLESS_UUID_REGEX.test(vlessUuid)) {
    return { ok: false, error: "UUID must be a valid UUID v4 string (e.g. 03267b72-5095-44be-8af1-a511b692832b)." };
  }

  let vlessPath = typeof body.vlessPath === "string" ? body.vlessPath.trim() : currentCfg.vlessPath;
  if (!vlessPath) vlessPath = DEFAULT_VLESS_PATH;
  if (!vlessPath.startsWith("/")) vlessPath = "/" + vlessPath;
  if (!/^\/[A-Za-z0-9/_-]+$/.test(vlessPath)) {
    return { ok: false, error: "VLESS_PATH contains invalid characters." };
  }
  if (vlessPath === sessionPath || vlessPath === wsPath) {
    return { ok: false, error: "VLESS_PATH must be different from SESSION_PATH and WS_PATH." };
  }

  const vlessDisguisedDomain = typeof body.vlessDisguisedDomain === "string"
    ? body.vlessDisguisedDomain.trim()
    : currentCfg.vlessDisguisedDomain;
  if (vlessDisguisedDomain !== "") {
    if (!/^https?:\/\/.+/i.test(vlessDisguisedDomain)) {
      return { ok: false, error: "DISGUISED_DOMAIN must start with http:// or https://, or be empty." };
    }
    try {
      new URL(vlessDisguisedDomain);
    } catch {
      return { ok: false, error: "DISGUISED_DOMAIN is not a valid URL." };
    }
  }

  return {
    ok: true,
    override: {
      ADMIN_KEY: adminKeyRaw,
      SECRET: secretHex,
      CARRIER: carrier,
      MAX_STREAMS: String(maxStreamsNum),
      ALLOWED_HOSTS: allowedHostsStr,
      EXTRA_HOSTS: extraHostsStr,
      DECOY_URL: decoyUrlRaw,
      SESSION_PATH: sessionPath,
      WS_PATH: wsPath,
      DC_PORTS: dcPortsStr,
      AD_TAG: adTagHex,
      DEBUG: debugFlag ? "true" : "false",
      GENERATOR_ENABLED: generatorEnabled ? "true" : "false",
      ACCEPT_GENERATED: acceptGenerated ? "true" : "false",
      VLESS_ENABLED: vlessEnabled ? "true" : "false",
      UUID: vlessUuid,
      VLESS_PATH: vlessPath,
      DISGUISED_DOMAIN: vlessDisguisedDomain || "https://example.com",
    },
  };
}

export function rawRequestAuthority(req: IncomingMessage): string {
  const fwdHost = req.headers["x-forwarded-host"];
  const rawFwd = Array.isArray(fwdHost) ? fwdHost[0] : fwdHost;
  if (typeof rawFwd === "string" && rawFwd.trim()) {
    return rawFwd.split(",")[0].trim();
  }
  const host = req.headers.host;
  return typeof host === "string" ? host.trim() : "";
}

export function requestHost(req: IncomingMessage): string {
  let host = rawRequestAuthority(req).toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (host.startsWith("[")) {
    const endBracket = host.indexOf("]");
    if (endBracket > 0) return host.slice(0, endBracket + 1);
    return host;
  }
  const colon = host.lastIndexOf(":");
  if (colon > 0 && host.indexOf(":") === colon) {
    host = host.slice(0, colon);
  }
  return host;
}

export function requestPort(req: IncomingMessage): string {
  const authority = rawRequestAuthority(req);
  const match = /:([0-9]+)$/.exec(authority);
  if (match) return match[1];
  const fwdPort = req.headers["x-forwarded-port"];
  const rawPort = Array.isArray(fwdPort) ? fwdPort[0] : fwdPort;
  if (typeof rawPort === "string" && /^[0-9]+$/.test(rawPort.trim())) {
    return rawPort.trim();
  }
  return "";
}

export function requestProto(req: IncomingMessage): "https" | "http" {
  const cfVisitor = req.headers["cf-visitor"];
  if (typeof cfVisitor === "string" && cfVisitor.includes('"https"')) {
    return "https";
  }
  const fwdProto = req.headers["x-forwarded-proto"];
  const rawProto = Array.isArray(fwdProto) ? fwdProto[0] : fwdProto;
  if (typeof rawProto === "string") {
    const first = rawProto.split(",")[0].trim().toLowerCase();
    if (first === "https") return "https";
    if (first === "http") return "http";
  }
  const host = requestHost(req);
  if (host === "localhost" || host === "127.0.0.1" || host === "::1") {
    return "http";
  }
  return "https";
}

export function hostAllowed(cfg: ProxyRuntime, host: string): boolean {
  if (!/^[a-z0-9.-]+$/.test(host) || host.includes("..")) return false;
  if (
    cfg.hosts.length === 0 ||
    cfg.hosts.includes("*") ||
    (cfg.hosts.length === 1 && cfg.hosts[0] === "proxy.example.com")
  ) {
    return true;
  }
  return cfg.hosts.includes(host) || cfg.extraHosts.includes(host);
}

export function deriveSecret(cfg: ProxyRuntime, label: string): Buffer | null {
  if (!cfg.generatorKeyBytes) return null;
  const mac = hmacSha256(cfg.generatorKeyBytes, Buffer.from("tgweb-secret-v1\n" + label, "utf8"));
  return mac.subarray(0, 16);
}

export function bridgeMode(
  cfg: ProxyRuntime,
  host: string,
  capability: string,
  port: string,
  extraHeaderHosts: string[] = []
): number {
  const provided = b64uDecodeStrict(capability);
  if (!provided || provided.length !== 32) return -1;

  // 合并待校验域名：当前请求 Host + X-Original-Host/原始 Host + EXTRA_HOSTS + 白名单中的具体域名（适配 CDN 回源重写 Host 的加速域名场景）
  const baseHosts: string[] = [];
  const pushHost = (h: string) => {
    const clean = h.trim().toLowerCase().replace(/\.$/, "").replace(/:[0-9]+$/, "");
    if (clean && clean !== "*" && clean !== "proxy.example.com" && !baseHosts.includes(clean)) {
      baseHosts.push(clean);
    }
  };
  pushHost(host);
  for (const h of extraHeaderHosts) pushHost(h);
  for (const h of cfg.extraHosts) pushHost(h);
  for (const h of cfg.hosts) pushHost(h);

  const incomingPort = port ? parseInt(port, 10) : 443;
  const isKnownPort = (HTTPS_PORTS as readonly number[]).includes(incomingPort);

  for (const candidateHost of baseHosts) {
    if (isKnownPort && cfg.portSecrets[incomingPort]) {
      const pKeys = cfg.portSecrets[incomingPort].keys;
      const contexts = incomingPort === 443
        ? [Buffer.from("tdesktop-web-proxy-bridge-v1\n" + candidateHost, "utf8")]
        : [
            Buffer.from(`tdesktop-web-proxy-bridge-v1\n${candidateHost}:${incomingPort}`, "utf8"),
            Buffer.from("tdesktop-web-proxy-bridge-v1\n" + candidateHost, "utf8"),
          ];
      for (const ctx of contexts) {
        for (const key of pKeys) {
          if (hmacVerify(key, provided, ctx)) {
            return PORT_MODE_BASE + (HTTPS_PORTS as readonly number[]).indexOf(incomingPort);
          }
        }
      }
    }
  }

  const candidateHosts: string[] = [];
  const candidatePorts: string[] = [];
  if (port && port !== "443" && port !== "80") candidatePorts.push(port);
  for (const p of HTTPS_PORTS) {
    if (p !== 443 && !candidatePorts.includes(String(p))) candidatePorts.push(String(p));
  }
  for (const h of baseHosts) {
    candidateHosts.push(h);
    for (const p of candidatePorts) candidateHosts.push(`${h}:${p}`);
  }

  for (const h of candidateHosts) {
    const context = Buffer.from("tdesktop-web-proxy-bridge-v1\n" + h, "utf8");
    for (const key of cfg.bridgeKeys) {
      if (hmacVerify(key, provided, context)) {
        return PORT_MODE_BASE;
      }
    }
  }

  if (cfg.portSecrets) {
    for (const candidateHost of baseHosts) {
      for (let idx = 0; idx < HTTPS_PORTS.length; idx++) {
        const p = HTTPS_PORTS[idx];
        if (p === incomingPort && candidateHost === host) continue;
        const pKeys = cfg.portSecrets[p]?.keys;
        if (!pKeys) continue;
        const contexts = [
          Buffer.from(`tdesktop-web-proxy-bridge-v1\n${candidateHost}:${p}`, "utf8"),
          Buffer.from("tdesktop-web-proxy-bridge-v1\n" + candidateHost, "utf8"),
        ];
        for (const ctx of contexts) {
          for (const key of pKeys) {
            if (hmacVerify(key, provided, ctx)) {
              if (!port || port === "443" || port === String(p)) {
                return PORT_MODE_BASE + idx;
              }
            }
          }
        }
      }
    }
  }

  if (cfg.acceptGenerated) {
    for (let index = 0; index < candidateHosts.length; index++) {
      const h = candidateHosts[index];
      const context = Buffer.from("tdesktop-web-proxy-bridge-v1\n" + h, "utf8");
      const secret = deriveSecret(cfg, h);
      if (secret && hmacVerify(secret, provided, context)) {
        return h.includes(":") ? 2 : 1;
      }
    }
  }

  return -1;
}

export function issueToken(cfg: ProxyRuntime, kind: number, ttl: number, mode: number): string {
  const nonce = Buffer.allocUnsafe(16);
  nonce.writeUInt32BE(Math.floor(Date.now() / 1000) + ttl, 0);
  nonce[4] = typeof mode === "number" && mode >= 0 && mode <= 255 ? mode : 0;
  randomTokenBytes(11).copy(nonce, 5);
  const mac = hmacSha256(cfg.tokenKey, concat(TOKEN_DOMAIN, Buffer.of(kind), nonce));
  return b64uEncode(concat(nonce, mac));
}

export function verifyToken(cfg: ProxyRuntime, token: string, kind: number): { nonce: Buffer; mode: number } | null {
  const raw = b64uDecodeStrict(token);
  if (!raw || raw.length !== 48) return null;
  const nonce = raw.subarray(0, 16);
  const mac = raw.subarray(16);
  if (!hmacVerify(cfg.tokenKey, mac, concat(TOKEN_DOMAIN, Buffer.of(kind), nonce))) {
    return null;
  }
  const expires = nonce.readUInt32BE(0);
  if (expires < Math.floor(Date.now() / 1000)) return null;
  return { nonce, mode: nonce[4] };
}

export function panelRoute(pathname: string, searchParams: URLSearchParams, cfg: ProxyRuntime): "panel" | "status" | "config" | "api-state" | "api-probe" | "api-ws-probe" | "api-config" | null {
  if (!cfg.adminKey) return null;
  let path = "";
  try {
    path = decodeURIComponent(pathname.slice(1));
  } catch {
    return null;
  }
  if (path.endsWith("/")) path = path.slice(0, -1);
  if (path && safeEqual(path, cfg.adminKey)) return "panel";
  if (path && safeEqual(path, cfg.adminKey + "/status")) return "status";
  if (path && safeEqual(path, cfg.adminKey + "/config")) return "config";
  if (path && safeEqual(path, cfg.adminKey + "/api/state")) return "api-state";
  if (path && safeEqual(path, cfg.adminKey + "/api/probe")) return "api-probe";
  if (path && safeEqual(path, cfg.adminKey + "/api/ws-probe")) return "api-ws-probe";
  if (path && safeEqual(path, cfg.adminKey + "/api/config")) return "api-config";
  if (generatorLabel(searchParams) === "" && safeEqual(searchParams.get("key") || "", cfg.adminKey)) {
    return "panel";
  }
  return null;
}

export function generatorLabel(searchParams: URLSearchParams): string | null {
  for (const key of ["--create-secret", "create-secret", "create_secret"]) {
    if (searchParams.has(key)) return searchParams.get(key) || "";
  }
  return null;
}

export { TOKEN_KIND_BOOTSTRAP, TOKEN_KIND_SESSION };
