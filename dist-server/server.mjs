// server.ts
import "dotenv/config";
import fs2 from "node:fs";
import http from "node:http";
import path2 from "node:path";
import express2 from "express";

// src/proxy/config.ts
import fs from "node:fs";
import path from "node:path";

// src/proxy/constants.ts
var VERSION = "1.2.3-node";
var HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
var DEFAULT_DC_MAP = {
  1: ["149.154.175.50", "149.154.175.53", "149.154.175.54"],
  2: ["149.154.167.51", "149.154.167.50", "149.154.167.40", "149.154.167.41"],
  3: ["149.154.175.100", "149.154.175.101"],
  4: ["149.154.167.91", "149.154.167.92", "149.154.167.90"],
  5: ["91.108.56.156", "91.108.56.165", "91.108.56.170"],
  203: ["91.105.192.110"]
};
var DEFAULT_CONFIG = {
  secretHex: "",
  adTagHex: "",
  hostnames: ["*"],
  debug: false,
  generatorEnabled: false,
  generatorKey: "",
  acceptGenerated: false,
  dc: DEFAULT_DC_MAP,
  dcPort: 443,
  dcPorts: [443, 80, 5222],
  carrier: "websocket-lanes",
  sessionPath: "/api/v1/session",
  wsPath: "/api/v1/ws",
  batchBytes: 2097152,
  bootstrapTtl: 3600,
  sessionTtl: 86400,
  maxStreams: 16,
  maxQueued: 16777216,
  streamWindow: 4194304,
  dataChunk: 65536
};
var TOKEN_DOMAIN = Buffer.from("tgweb-token-v1\0", "utf8");
var BUILD_SEAL = "Pt54F2/pkjqM1YnQmZRs3Xvqd54U1iZVSYCfYAOgf5wIRzjyeruT";
var TOKEN_KIND_BOOTSTRAP = 1;
var TOKEN_KIND_SESSION = 2;
var PORT_MODE_BASE = 10;
var REQUEST_LIMIT = 16777216;
var WELCOME = Buffer.from([17, 0, 0, 0, 0, 0, 0, 0]);
var EMPTY = Buffer.alloc(0);
var PERMISSIONS_POLICY = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()";

// src/proxy/crypto.ts
import { createCipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
var sealCache = null;
function concat(...parts) {
  return Buffer.concat(parts);
}
function reverse(bytes) {
  const out = Buffer.allocUnsafe(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = bytes[bytes.length - 1 - i];
  }
  return out;
}
function hexToBytes(hex) {
  return Buffer.from(hex, "hex");
}
function bytesToHex(bytes) {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("hex");
}
function b64uEncode(bytes) {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64url");
}
function b64uDecodeStrict(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const remainder = value.length % 4;
  if (remainder === 1) return null;
  try {
    const out = Buffer.from(value, "base64url");
    return b64uEncode(out) === value ? out : null;
  } catch {
    return null;
  }
}
function sha256(bytes) {
  return createHash("sha256").update(bytes).digest();
}
function hmacSha256(key, data) {
  return createHmac("sha256", key).update(data).digest();
}
function hmacVerify(key, signature, data) {
  const expected = hmacSha256(key, data);
  if (expected.length !== signature.length) return false;
  return timingSafeEqual(expected, signature);
}
function safeEqual(a, b) {
  const x = Buffer.from(String(a), "utf8");
  const y = Buffer.from(String(b), "utf8");
  const len = Math.max(x.length, y.length);
  const px = Buffer.alloc(len);
  const py = Buffer.alloc(len);
  x.copy(px);
  y.copy(py);
  return timingSafeEqual(px, py) && x.length === y.length;
}
function unseal() {
  if (sealCache) return sealCache;
  const data = Buffer.from(BUILD_SEAL, "base64");
  const salt = Buffer.concat([TOKEN_DOMAIN, Buffer.of(80, 71, 1)]);
  let stream = Buffer.alloc(0);
  for (let block = 0; stream.length < data.length; block++) {
    stream = Buffer.concat([stream, sha256(Buffer.concat([salt, Buffer.of(block)]))]);
  }
  const out = Buffer.allocUnsafe(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i] ^ stream[i];
  }
  const text = out.toString("utf8");
  const bar = text.indexOf(" | ");
  sealCache = {
    bytes: out,
    name: bar > 0 ? text.slice(0, bar) : text,
    mail: bar > 0 ? text.slice(bar + 3) : ""
  };
  return sealCache;
}
function parseSecret(hexValue) {
  if (!hexValue) return null;
  let hex = String(hexValue).trim().toLowerCase();
  if (hex.startsWith("0x")) hex = hex.substring(2);
  if (!/^[0-9a-f]+$/.test(hex)) return null;
  if (hex.length === 32) return hexToBytes(hex);
  if (hex.length === 34 && hex.startsWith("dd")) return hexToBytes(hex.substring(2));
  return null;
}
function parseAdTag(hexValue) {
  const hex = String(hexValue || "").trim().toLowerCase();
  if (/^[0-9a-f]{32}$/.test(hex)) return hexToBytes(hex);
  return null;
}
function randomTokenBytes(size) {
  return randomBytes(size);
}
var ObfuscatedCtrStream = class {
  constructor(key, iv, startOffset = 56) {
    this.cipher = createCipheriv("aes-256-ctr", key, iv);
    if (startOffset > 0) {
      this.cipher.update(Buffer.alloc(startOffset));
    }
  }
  update(data) {
    return this.cipher.update(data);
  }
};

// src/proxy/config.ts
var RUNTIME_FILE_PATH = path.resolve(process.cwd(), "storage", "runtime.json");
var runtimeOverrideEnv = null;
var runtimeFileHash = null;
var runtimePersisted = false;
var cachedRuntime = null;
var cachedKey = null;
function reloadRuntimeFileIfChanged() {
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
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const clean = {};
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === "string") clean[k] = v;
      }
      runtimeOverrideEnv = clean;
      runtimeFileHash = hash;
      runtimePersisted = true;
      cachedRuntime = null;
      cachedKey = null;
    }
  } catch {
  }
}
function setRuntimeOverride(env) {
  runtimeOverrideEnv = env;
  runtimePersisted = false;
  cachedRuntime = null;
  cachedKey = null;
}
function saveRuntimeOverride(override) {
  setRuntimeOverride(override);
  try {
    const dir = path.dirname(RUNTIME_FILE_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const raw = JSON.stringify(override, null, 2) + "\n";
    fs.writeFileSync(RUNTIME_FILE_PATH, raw, { encoding: "utf8", mode: 384 });
    runtimeFileHash = `${raw.length}:${bytesToHex(sha256(Buffer.from(raw, "utf8"))).slice(0, 16)}`;
    runtimePersisted = true;
    return true;
  } catch {
    runtimePersisted = false;
    return false;
  }
}
function resetRuntimeOverride() {
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
function isEphemeralSetup() {
  return runtimeOverrideEnv !== null && !runtimePersisted;
}
function isRuntimePersisted() {
  return runtimePersisted;
}
function hasRuntimeOverride() {
  return runtimeOverrideEnv !== null;
}
function hasBaseEnvRuntime(env = process.env) {
  return buildRuntime(resolveConfig(env, true)) !== null;
}
function resolveConfig(env, ignoreOverride = false) {
  if (!ignoreOverride) reloadRuntimeFileIfChanged();
  const merged = !ignoreOverride && runtimeOverrideEnv ? { ...env, ...runtimeOverrideEnv } : env;
  const secretHex = (typeof merged.SECRET === "string" ? merged.SECRET : DEFAULT_CONFIG.secretHex || "").trim();
  const adTagHex = (typeof merged.AD_TAG === "string" ? merged.AD_TAG : DEFAULT_CONFIG.adTagHex || "").trim();
  const debug = merged.DEBUG === "true" || merged.DEBUG === "1" || DEFAULT_CONFIG.debug === true;
  const decoyUrl = (typeof merged.DECOY_URL === "string" ? merged.DECOY_URL : "").trim();
  const rawHostnames = typeof merged.ALLOWED_HOSTS === "string" && merged.ALLOWED_HOSTS.trim() ? merged.ALLOWED_HOSTS : typeof merged.HOSTNAME === "string" && merged.HOSTNAME.trim() ? merged.HOSTNAME : "";
  let hostnames = [];
  if (rawHostnames) {
    hostnames = rawHostnames.split(",").map((s) => s.trim().toLowerCase()).filter((s) => s === "*" || s.includes("."));
  }
  if (hostnames.length === 0 && Array.isArray(DEFAULT_CONFIG.hostnames)) {
    hostnames = DEFAULT_CONFIG.hostnames.map((s) => String(s).trim().toLowerCase()).filter(Boolean);
  }
  const parsedStreams = merged.MAX_STREAMS ? parseInt(merged.MAX_STREAMS, 10) : NaN;
  const maxStreams = Number.isFinite(parsedStreams) ? Math.min(64, Math.max(1, parsedStreams)) : DEFAULT_CONFIG.maxStreams;
  const sessionPath = typeof merged.SESSION_PATH === "string" && merged.SESSION_PATH.trim() ? merged.SESSION_PATH.trim().startsWith("/") ? merged.SESSION_PATH.trim() : "/" + merged.SESSION_PATH.trim() : DEFAULT_CONFIG.sessionPath;
  const wsPath = typeof merged.WS_PATH === "string" && merged.WS_PATH.trim() ? merged.WS_PATH.trim().startsWith("/") ? merged.WS_PATH.trim() : "/" + merged.WS_PATH.trim() : DEFAULT_CONFIG.wsPath;
  const adminKey = typeof merged.ADMIN_KEY === "string" ? merged.ADMIN_KEY.trim() : "";
  const extraHosts = (typeof merged.EXTRA_HOSTS === "string" ? merged.EXTRA_HOSTS : "").split(/[,\s]+/).map((value) => value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[:/].*$/, "").replace(/\.$/, "")).filter((value) => /^[a-z0-9.-]+$/.test(value) && !value.includes(".."));
  const carrierEnv = typeof merged.CARRIER === "string" ? merged.CARRIER.trim().toLowerCase() : "";
  const carrier = carrierEnv === "websocket" || carrierEnv === "websocket-lanes" ? carrierEnv : DEFAULT_CONFIG.carrier;
  let dcPorts = DEFAULT_CONFIG.dcPorts;
  if (typeof merged.DC_PORTS === "string" && merged.DC_PORTS.trim()) {
    const parsedPorts = merged.DC_PORTS.split(/[,\s]+/).map((v) => parseInt(v.trim(), 10)).filter((n) => Number.isFinite(n) && n >= 1 && n <= 65535);
    if (parsedPorts.length > 0) dcPorts = parsedPorts;
  }
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
    generatorEnabled: merged.GENERATOR_ENABLED !== void 0 ? merged.GENERATOR_ENABLED === "true" || merged.GENERATOR_ENABLED === "1" : DEFAULT_CONFIG.generatorEnabled,
    generatorKey: (typeof merged.GENERATOR_KEY === "string" ? merged.GENERATOR_KEY : DEFAULT_CONFIG.generatorKey || "").trim(),
    acceptGenerated: merged.ACCEPT_GENERATED !== void 0 ? merged.ACCEPT_GENERATED === "true" || merged.ACCEPT_GENERATED === "1" : DEFAULT_CONFIG.acceptGenerated,
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
    ephemeralSetup: runtimeOverrideEnv !== null
  };
}
function buildRuntime(cfg) {
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
  const generatorRaw = generatorText ? sha256(concat(Buffer.from("tgweb-generator-v1\0", "utf8"), Buffer.from(generatorText, "utf8"))) : base;
  const bridgeKeys = [];
  if (base) {
    bridgeKeys.push(base);
    bridgeKeys.push(concat(Buffer.of(221), base));
  }
  const portSecrets = {};
  if (base) {
    for (const p of HTTPS_PORTS) {
      const sBytes = p === 443 ? base : sha256(
        concat(
          Buffer.from("proxygosha-port-secret-v1\n", "utf8"),
          base,
          Buffer.from("\n" + p, "utf8")
        )
      ).subarray(0, 16);
      portSecrets[p] = {
        secret: sBytes,
        secretHex: "dd" + bytesToHex(sBytes),
        keys: [sBytes, concat(Buffer.of(221), sBytes)]
      };
    }
  }
  const tokenKey = sha256(concat(Buffer.from("tgweb-token-key-v1\0", "utf8"), seal.bytes, fallback));
  const hosts = Array.isArray(cfg.hostnames) ? cfg.hostnames.map((v) => String(v).trim().toLowerCase()).filter(Boolean) : [];
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
    ephemeralSetup: cfg.ephemeralSetup
  };
}
function getRuntime(env = process.env) {
  reloadRuntimeFileIfChanged();
  const resolved = resolveConfig(env);
  const cacheKey = `${resolved.secretHex}:${resolved.generatorKey}:${resolved.hostnames.join(",")}:${resolved.adTagHex}:${resolved.decoyUrl}:${resolved.maxStreams}:${resolved.sessionPath}:${resolved.wsPath}:${resolved.debug}:${resolved.carrier}:${resolved.acceptGenerated}:${resolved.generatorEnabled}:${resolved.adminKey}:${resolved.extraHosts.join(",")}:${resolved.dcPorts.join(",")}:${resolved.ephemeralSetup}`;
  if (cachedRuntime && cachedKey === cacheKey) {
    return cachedRuntime;
  }
  const runtime = buildRuntime(resolved);
  cachedRuntime = runtime;
  cachedKey = cacheKey;
  return runtime;
}
function buildOverrideFromConfigInput(body, currentCfg, env = process.env) {
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
  const carrier = body.carrier === "websocket" || body.carrier === "websocket-lanes" ? body.carrier : currentCfg.carrier;
  const maxStreamsNum = typeof body.maxStreams === "number" ? Math.trunc(body.maxStreams) : parseInt(String(body.maxStreams ?? currentCfg.maxStreams), 10);
  if (!Number.isFinite(maxStreamsNum) || maxStreamsNum < 1 || maxStreamsNum > 64) {
    return { ok: false, error: "MAX_STREAMS must be an integer between 1 and 64." };
  }
  const allowedRaw = typeof body.allowedHosts === "string" ? body.allowedHosts : currentCfg.hosts.join(", ");
  const allowedList = allowedRaw.split(/[,\s]+/).map((s) => s.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[:/].*$/, "").replace(/\.$/, "")).filter(Boolean);
  for (const h of allowedList) {
    if (h !== "*" && (!/^[a-z0-9.-]+$/.test(h) || h.includes("..") || !h.includes("."))) {
      return { ok: false, error: `Invalid ALLOWED_HOSTS entry: ${h}` };
    }
  }
  const allowedHostsStr = allowedList.length > 0 ? Array.from(new Set(allowedList)).join(",") : "*";
  const extraRaw = typeof body.extraHosts === "string" ? body.extraHosts : currentCfg.extraHosts.join(", ");
  const extraList = extraRaw.split(/[,\s]+/).map((s) => s.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[:/].*$/, "").replace(/\.$/, "")).filter(Boolean);
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
  const dcPortsRaw = typeof body.dcPorts === "string" ? body.dcPorts : currentCfg.dcPorts.join(",");
  const dcPortsList = dcPortsRaw.split(/[,\s]+/).map((v) => parseInt(v.trim(), 10)).filter((n) => Number.isFinite(n) && n >= 1 && n <= 65535);
  if (dcPortsList.length === 0) {
    return { ok: false, error: "DC_PORTS must contain at least one valid port (1\u201365535)." };
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
      ACCEPT_GENERATED: acceptGenerated ? "true" : "false"
    }
  };
}
function rawRequestAuthority(req) {
  const fwdHost = req.headers["x-forwarded-host"];
  const rawFwd = Array.isArray(fwdHost) ? fwdHost[0] : fwdHost;
  if (typeof rawFwd === "string" && rawFwd.trim()) {
    return rawFwd.split(",")[0].trim();
  }
  const host = req.headers.host;
  return typeof host === "string" ? host.trim() : "";
}
function requestHost(req) {
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
function requestPort(req) {
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
function requestProto(req) {
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
function hostAllowed(cfg, host) {
  if (!/^[a-z0-9.-]+$/.test(host) || host.includes("..")) return false;
  if (cfg.hosts.length === 0 || cfg.hosts.includes("*") || cfg.hosts.length === 1 && cfg.hosts[0] === "proxy.example.com") {
    return true;
  }
  return cfg.hosts.includes(host) || cfg.extraHosts.includes(host);
}
function deriveSecret(cfg, label) {
  if (!cfg.generatorKeyBytes) return null;
  const mac = hmacSha256(cfg.generatorKeyBytes, Buffer.from("tgweb-secret-v1\n" + label, "utf8"));
  return mac.subarray(0, 16);
}
function bridgeMode(cfg, host, capability, port, extraHeaderHosts = []) {
  const provided = b64uDecodeStrict(capability);
  if (!provided || provided.length !== 32) return -1;
  const baseHosts = [];
  const pushHost = (h) => {
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
  const isKnownPort = HTTPS_PORTS.includes(incomingPort);
  for (const candidateHost of baseHosts) {
    if (isKnownPort && cfg.portSecrets[incomingPort]) {
      const pKeys = cfg.portSecrets[incomingPort].keys;
      const contexts = incomingPort === 443 ? [Buffer.from("tdesktop-web-proxy-bridge-v1\n" + candidateHost, "utf8")] : [
        Buffer.from(`tdesktop-web-proxy-bridge-v1
${candidateHost}:${incomingPort}`, "utf8"),
        Buffer.from("tdesktop-web-proxy-bridge-v1\n" + candidateHost, "utf8")
      ];
      for (const ctx of contexts) {
        for (const key of pKeys) {
          if (hmacVerify(key, provided, ctx)) {
            return PORT_MODE_BASE + HTTPS_PORTS.indexOf(incomingPort);
          }
        }
      }
    }
  }
  const candidateHosts = [];
  const candidatePorts = [];
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
          Buffer.from(`tdesktop-web-proxy-bridge-v1
${candidateHost}:${p}`, "utf8"),
          Buffer.from("tdesktop-web-proxy-bridge-v1\n" + candidateHost, "utf8")
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
function issueToken(cfg, kind, ttl, mode) {
  const nonce = Buffer.allocUnsafe(16);
  nonce.writeUInt32BE(Math.floor(Date.now() / 1e3) + ttl, 0);
  nonce[4] = typeof mode === "number" && mode >= 0 && mode <= 255 ? mode : 0;
  randomTokenBytes(11).copy(nonce, 5);
  const mac = hmacSha256(cfg.tokenKey, concat(TOKEN_DOMAIN, Buffer.of(kind), nonce));
  return b64uEncode(concat(nonce, mac));
}
function verifyToken(cfg, token, kind) {
  const raw = b64uDecodeStrict(token);
  if (!raw || raw.length !== 48) return null;
  const nonce = raw.subarray(0, 16);
  const mac = raw.subarray(16);
  if (!hmacVerify(cfg.tokenKey, mac, concat(TOKEN_DOMAIN, Buffer.of(kind), nonce))) {
    return null;
  }
  const expires = nonce.readUInt32BE(0);
  if (expires < Math.floor(Date.now() / 1e3)) return null;
  return { nonce, mode: nonce[4] };
}
function panelRoute(pathname, searchParams, cfg) {
  if (!cfg.adminKey) return null;
  let path3 = "";
  try {
    path3 = decodeURIComponent(pathname.slice(1));
  } catch {
    return null;
  }
  if (path3.endsWith("/")) path3 = path3.slice(0, -1);
  if (path3 && safeEqual(path3, cfg.adminKey)) return "panel";
  if (path3 && safeEqual(path3, cfg.adminKey + "/status")) return "status";
  if (path3 && safeEqual(path3, cfg.adminKey + "/config")) return "config";
  if (path3 && safeEqual(path3, cfg.adminKey + "/api/state")) return "api-state";
  if (path3 && safeEqual(path3, cfg.adminKey + "/api/probe")) return "api-probe";
  if (path3 && safeEqual(path3, cfg.adminKey + "/api/config")) return "api-config";
  if (generatorLabel(searchParams) === "" && safeEqual(searchParams.get("key") || "", cfg.adminKey)) {
    return "panel";
  }
  return null;
}
function generatorLabel(searchParams) {
  for (const key of ["--create-secret", "create-secret", "create_secret"]) {
    if (searchParams.has(key)) return searchParams.get(key) || "";
  }
  return null;
}

// src/proxy/engine.ts
import net from "node:net";
import { createCipheriv as createCipheriv2, randomBytes as randomBytes2 } from "node:crypto";
import { WebSocketServer, WebSocket } from "ws";

// src/proxy/telemetry.ts
var PROCESS_START = Date.now();
var STATS = {
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
  statusViews: 0
};
var LOG_LIMIT = 150;
var LOG = [];
function logEvent(event, detail) {
  try {
    LOG.push({
      t: Date.now(),
      event: String(event).slice(0, 28),
      detail: String(detail || "").slice(0, 140)
    });
    if (LOG.length > LOG_LIMIT) {
      LOG.splice(0, LOG.length - LOG_LIMIT);
    }
  } catch {
  }
}
function reportError(where, error) {
  try {
    const errObj = error;
    const message = errObj?.stack ? String(errObj.stack) : String(error);
    console.error(`[proxygosha] ${where}: ${message}`);
    logEvent("error", `${where}: ${errObj?.message || message}`);
  } catch {
  }
}
function fmtBytes(value) {
  const n = Number(value) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}
function fmtDuration(milliseconds) {
  const total = Math.max(0, Math.floor(milliseconds / 1e3));
  const days = Math.floor(total / 86400);
  const hours = Math.floor(total % 86400 / 3600);
  const minutes = Math.floor(total % 3600 / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m ${total % 60}s`;
}

// src/proxy/engine.ts
function frame(type, id, payload) {
  const out = Buffer.allocUnsafe(8 + payload.length);
  out[0] = type;
  out[1] = id >>> 16 & 255;
  out[2] = id >>> 8 & 255;
  out[3] = id & 255;
  out.writeUInt32BE(payload.length, 4);
  if (payload.length > 0) {
    Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength).copy(out, 8);
  }
  return out;
}
function windowFrame(id, amount) {
  const out = Buffer.allocUnsafe(12);
  out[0] = 4;
  out[1] = id >>> 16 & 255;
  out[2] = id >>> 8 & 255;
  out[3] = id & 255;
  out.writeUInt32BE(4, 4);
  out.writeUInt32BE(amount >>> 0, 8);
  return out;
}
function tagKind(tag) {
  if (tag[0] === 239 && tag[1] === 239 && tag[2] === 239 && tag[3] === 239) return 1;
  if (tag[0] === 238 && tag[1] === 238 && tag[2] === 238 && tag[3] === 238) return 2;
  if (tag[0] === 221 && tag[1] === 221 && tag[2] === 221 && tag[3] === 221) return 3;
  return 0;
}
function safeDcHeaderPrefix(bytes) {
  if (bytes[0] === 239) return false;
  if (bytes[4] === 0 && bytes[5] === 0 && bytes[6] === 0 && bytes[7] === 0) return false;
  if (bytes[0] === 71 && bytes[1] === 69 && bytes[2] === 84 && bytes[3] === 32) return false;
  if (bytes[0] === 80 && bytes[1] === 79 && bytes[2] === 83 && bytes[3] === 84) return false;
  if (bytes[0] === 72 && bytes[1] === 69 && bytes[2] === 65 && bytes[3] === 68) return false;
  if (bytes[0] === 79 && bytes[1] === 80 && bytes[2] === 84 && bytes[3] === 73) return false;
  if (bytes[0] === 238 && bytes[1] === 238 && bytes[2] === 238 && bytes[3] === 238) return false;
  if (bytes[0] === 221 && bytes[1] === 221 && bytes[2] === 221 && bytes[3] === 221) return false;
  if (bytes[0] === 22 && bytes[1] === 3 && bytes[2] === 1 && bytes[3] === 2) return false;
  return true;
}
function connectTcpWithTimeout(host, port, timeoutMs = 3e3) {
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
      socket.setKeepAlive(true, 3e4);
      resolve(socket);
    };
    const onError = (err) => {
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
var Stream = class {
  constructor(session, id) {
    this.phase = "header";
    this.header = Buffer.alloc(64);
    this.headerLength = 0;
    this.dead = false;
    this.socket = null;
    this.inQueue = [];
    this.inRunning = false;
    this.queuedLocal = 0;
    this.recvOutstanding = 0;
    this.pendingDown = null;
    this.drainWaiters = [];
    this.dcKey = 0;
    this.dcTarget = "";
    this.dcSentPayloadBytes = 0;
    this.dcRecvBytes = 0;
    this.clientReadCipher = null;
    this.dcWriteCipher = null;
    this.session = session;
    this.id = id;
    this.sendCredit = session.cfg.streamWindow;
    STATS.streams++;
    session.streamCount++;
  }
  feed(payload) {
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
  async runIn() {
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
  async init() {
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
    const candidatePorts = Array.isArray(this.session.cfg.dcPorts) ? this.session.cfg.dcPorts : [this.session.cfg.dcPort || 443];
    if (this.session.cfg.adTag && this.session.cfg.debug && !this.session.loggedMeNotice) {
      this.session.loggedMeNotice = true;
      console.log(
        "[proxygosha] AD_TAG configured. Running in Direct-DC mode (ME handshake omitted)."
      );
    }
    const reversed = reverse(header.subarray(8, 56));
    const writeKey = sha256(concat(reversed.subarray(0, 32), this.session.secret));
    const clientWriteIv = reversed.subarray(32, 48);
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
    const attempts = [];
    for (const port of candidatePorts) {
      for (const hostIp of ips) {
        attempts.push([hostIp, port]);
      }
    }
    const maxAttempts = Math.min(attempts.length, 4);
    let socket = null;
    let lastError = null;
    for (let a = 0; a < maxAttempts && !socket; a++) {
      if (this.dead) return;
      const [hostIp, port] = attempts[a];
      STATS.dcAttempts++;
      try {
        socket = await connectTcpWithTimeout(hostIp, port, 3e3);
        this.dcTarget = `${hostIp}:${port}`;
      } catch (err) {
        lastError = err;
        STATS.dcFails++;
      }
    }
    if (!socket) {
      logEvent("dc_fail", `dc=${dcKey}`);
      throw lastError instanceof Error ? lastError : new Error("failed to connect to DC");
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
      randomBytes2(8).copy(dcHeader, 0);
      safe = safeDcHeaderPrefix(dcHeader);
    }
    if (!safe) {
      Buffer.from([18, 52, 86, 120, 154, 188, 222, 240]).copy(dcHeader, 0);
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
  }
  attachSocketEvents(socket) {
    socket.on("data", (chunk) => {
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
  writeRawSocket(data) {
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
  async writeToDc(payload) {
    if (this.dead || !this.clientReadCipher || !this.dcWriteCipher) return;
    const plain = this.clientReadCipher.update(payload);
    if (this.dead) return;
    const encrypted = this.dcWriteCipher.update(plain);
    this.dcSentPayloadBytes += encrypted.length;
    await this.writeRawSocket(encrypted);
    this.grant(payload.length);
  }
  handleDcData(chunk) {
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
      this.session.sendFrame(frame(2, this.id, slice));
      offset += size;
    }
    if (this.sendCredit <= 0 && this.socket && !this.socket.destroyed) {
      this.socket.pause();
    }
  }
  addCredit(amount) {
    if (this.dead) return;
    this.sendCredit = Math.min(4294967295, this.sendCredit + amount);
    if (this.pendingDown && this.sendCredit > 0) {
      const rem = this.pendingDown;
      this.pendingDown = null;
      this.handleDcData(rem);
    }
    if (this.sendCredit > 0 && !this.pendingDown && this.socket && !this.socket.destroyed) {
      this.socket.resume();
    }
  }
  grant(amount) {
    if (this.dead || amount <= 0) return;
    this.recvOutstanding = Math.max(0, this.recvOutstanding - amount);
    this.session.sendFrame(windowFrame(this.id, amount));
  }
  kill(notify) {
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
      }
      this.socket = null;
    }
    if (notify && !this.session.closed) {
      this.session.sendFrame(frame(3, this.id, EMPTY));
    }
    this.session.onStreamClosed(this.id);
  }
};
var WsSession = class {
  constructor(ws, cfg, secret, laneId = 0) {
    this.laneUsed = false;
    this.streams = /* @__PURE__ */ new Map();
    this.closed = false;
    this.queued = 0;
    this.tombstones = /* @__PURE__ */ new Set();
    this.tombstoneOrder = [];
    this.chain = Promise.resolve();
    this.loggedMeNotice = false;
    this.lastPong = Date.now();
    this.openedAt = Date.now();
    this.bytesUp = 0;
    this.bytesDown = 0;
    this.streamCount = 0;
    this.keepAliveTimer = null;
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
        if (Date.now() - this.lastPong > 9e4) {
          this.shutdown("pong watchdog");
          return;
        }
        try {
          const pingPayload = Buffer.allocUnsafe(4);
          pingPayload.writeUInt32BE(Math.floor(Date.now() / 1e3), 0);
          this.sendFrame(frame(5, 0, pingPayload));
        } catch {
        }
      }, 25e3);
    }
  }
  sendFrame(bytes) {
    if (this.closed || this.ws.readyState !== WebSocket.OPEN) return;
    try {
      this.ws.send(bytes, { binary: true });
      this.bytesDown += bytes.length;
      STATS.bytesDown += bytes.length;
    } catch {
      this.dispose();
    }
  }
  onStreamClosed(id) {
    if (!this.laneId || this.closed || id !== this.laneId) return;
    this.dispose();
    try {
      if (this.ws.readyState === WebSocket.OPEN) {
        this.ws.close(1e3, "done");
      }
    } catch {
    }
  }
  remember(id) {
    if (this.tombstones.has(id)) return;
    if (this.tombstoneOrder.length === 4096) {
      const oldest = this.tombstoneOrder.shift();
      if (oldest !== void 0) this.tombstones.delete(oldest);
    }
    this.tombstones.add(id);
    this.tombstoneOrder.push(id);
  }
  enqueue(data) {
    this.chain = this.chain.then(() => this.handle(data)).catch(() => this.shutdown());
  }
  async handle(bytes) {
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
      const id = bytes[offset + 1] << 16 | bytes[offset + 2] << 8 | bytes[offset + 3];
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
      if (type === 1) {
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
        if (this.streams.has(id) || this.tombstones.has(id) || this.streams.size >= this.cfg.maxStreams) {
          this.sendFrame(frame(3, id, EMPTY));
          continue;
        }
        this.streams.set(id, new Stream(this, id));
      } else if (type === 2) {
        if (id === 0 || size === 0) {
          this.shutdown();
          return;
        }
        const stream = this.streams.get(id);
        if (stream) {
          stream.feed(payload);
        } else if (!this.tombstones.has(id)) {
          this.sendFrame(frame(3, id, EMPTY));
        }
      } else if (type === 3) {
        if (id === 0 || size !== 0) {
          this.shutdown();
          return;
        }
        const stream = this.streams.get(id);
        if (stream) stream.kill(false);
      } else if (type === 4) {
        if (id === 0 || size !== 4) {
          this.shutdown();
          return;
        }
        const stream = this.streams.get(id);
        if (stream) stream.addCredit(payload.readUInt32BE(0));
      } else if (type === 5) {
        if (id === 0) {
          if (size > 64) {
            this.shutdown();
            return;
          }
          this.sendFrame(frame(6, 0, payload));
        }
      } else if (type === 6) {
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
  dispose() {
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
  shutdown(reason) {
    logEvent("session_kill", reason || "protocol");
    this.dispose();
    try {
      if (this.ws.readyState === WebSocket.OPEN) {
        this.ws.close(1011, "closed");
      }
    } catch {
    }
  }
};
function rejectUpgrade(socket, status = 404, message = "Not Found") {
  try {
    socket.write(
      `HTTP/1.1 ${status} ${status === 404 ? "Not Found" : "Bad Request"}\r
Content-Type: text/plain; charset=utf-8\r
Content-Length: ${Buffer.byteLength(message)}\r
Cache-Control: no-store\r
Connection: close\r
\r
${message}`
    );
    socket.destroy();
  } catch {
    socket.destroy();
  }
}
function attachWebSocketServer(httpServer, getCfg) {
  const wss = new WebSocketServer({
    noServer: true,
    perMessageDeflate: false,
    maxPayload: REQUEST_LIMIT,
    handleProtocols: (protocols) => {
      if (protocols.size !== 1) return false;
      const [first] = protocols;
      return first;
    }
  });
  httpServer.on("upgrade", (req, socket, head) => {
    try {
      const cfg = getCfg();
      if (!cfg) {
        rejectUpgrade(socket, 404);
        return;
      }
      const rawUrl = req.url || "/";
      const parsed = new URL(rawUrl, "http://localhost");
      if (parsed.pathname !== cfg.wsPath && parsed.pathname !== "/api/v1/ws") {
        rejectUpgrade(socket, 404);
        return;
      }
      const host = requestHost(req);
      const port = requestPort(req);
      if (!hostAllowed(cfg, host)) {
        STATS.wsRejects++;
        logEvent("ws_reject", `host=${host} reason=host_not_allowed`);
        rejectUpgrade(socket, 404);
        return;
      }
      if (req.method !== "GET") {
        STATS.wsRejects++;
        logEvent("ws_reject", `method=${req.method} reason=bad_method`);
        rejectUpgrade(socket, 404);
        return;
      }
      if (req.headers.authorization) {
        STATS.wsRejects++;
        logEvent("ws_reject", "reason=unexpected_auth_header");
        rejectUpgrade(socket, 404);
        return;
      }
      const rawProtocols = req.headers["sec-websocket-protocol"];
      const protocolHeader = Array.isArray(rawProtocols) ? rawProtocols.join(",") : rawProtocols || "";
      const offered = protocolHeader.split(",").map((v) => v.trim()).filter(Boolean);
      if (offered.length !== 1) {
        STATS.wsRejects++;
        logEvent("ws_reject", `reason=bad_protocol_count(${offered.length})`);
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
          STATS.wsRejects++;
          logEvent("ws_reject", "reason=invalid_lane_id");
          rejectUpgrade(socket, 404);
          return;
        }
        token = rest.substring(0, dot);
        laneId = parseInt(rest.substring(dot + 1), 10);
        if (laneId > 16777215) {
          STATS.wsRejects++;
          logEvent("ws_reject", "reason=lane_overflow");
          rejectUpgrade(socket, 404);
          return;
        }
      } else {
        STATS.wsRejects++;
        logEvent("ws_reject", "reason=unknown_subprotocol");
        rejectUpgrade(socket, 404);
        return;
      }
      const verified = verifyToken(cfg, token, TOKEN_KIND_SESSION);
      if (!verified) {
        STATS.wsRejects++;
        logEvent("ws_reject", "reason=invalid_or_expired_token");
        rejectUpgrade(socket, 404);
        return;
      }
      if ((verified.mode === 1 || verified.mode === 2) && !cfg.acceptGenerated) {
        STATS.wsRejects++;
        logEvent("ws_reject", "reason=generated_disabled");
        rejectUpgrade(socket, 404);
        return;
      }
      let secret = cfg.base;
      if (verified.mode >= PORT_MODE_BASE && verified.mode < PORT_MODE_BASE + HTTPS_PORTS.length) {
        const portNum = HTTPS_PORTS[verified.mode - PORT_MODE_BASE];
        secret = cfg.portSecrets[portNum]?.secret || cfg.base;
      } else if (verified.mode === 1 || verified.mode === 2) {
        const label = verified.mode === 2 && port && port !== "443" && port !== "80" ? `${host}:${port}` : host;
        secret = deriveSecret(cfg, label);
      }
      if (!secret) {
        rejectUpgrade(socket, 404);
        return;
      }
      const finalSecret = secret;
      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.binaryType = "nodebuffer";
        let session;
        try {
          session = new WsSession(ws, cfg, finalSecret, laneId);
        } catch (err) {
          reportError("ws session", err);
          try {
            ws.close(1011, "error");
          } catch {
          }
          return;
        }
        ws.on("message", (data, isBinary) => {
          try {
            if (!isBinary) {
              session.shutdown("non-binary");
              return;
            }
            const buf = Buffer.isBuffer(data) ? data : Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data);
            session.enqueue(buf);
          } catch (err) {
            reportError("ws message", err);
            try {
              session.shutdown("handler error");
            } catch {
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
function probeSingleDc(dc, ip, port) {
  return new Promise((resolve) => {
    const started = Date.now();
    let tcpMs = 0;
    let tcpConnected = false;
    let settled = false;
    let rxBytes = 0;
    const sock = net.createConnection({ host: ip, port });
    const finish = (mtprotoOk, reason) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        sock.removeAllListeners();
        sock.destroy();
      } catch {
      }
      resolve({
        dc,
        ip,
        port,
        ok: tcpConnected,
        ms: tcpConnected ? tcpMs : Date.now() - started,
        mtprotoOk,
        mtprotoMs: tcpConnected ? Date.now() - started : null,
        reason
      });
    };
    const timer = setTimeout(() => {
      finish(dc === 203 && tcpConnected ? null : false, tcpConnected ? "mtproto_timeout" : "tcp_timeout");
    }, 3e3);
    sock.once("connect", () => {
      tcpConnected = true;
      tcpMs = Date.now() - started;
      sock.setNoDelay(true);
      if (dc === 203) {
        finish(null, "cdn_tcp_ok");
        return;
      }
      const nonce = Buffer.allocUnsafe(64);
      let safe = false;
      for (let i = 0; i < 16 && !safe; i++) {
        randomBytes2(56).copy(nonce, 0);
        safe = safeDcHeaderPrefix(nonce);
      }
      if (!safe) {
        Buffer.from([18, 52, 86, 120, 154, 188, 222, 240]).copy(nonce, 0);
      }
      const writeKey = nonce.subarray(8, 40);
      const writeIv = nonce.subarray(40, 56);
      const rev = reverse(nonce.subarray(8, 56));
      const readKey = rev.subarray(0, 32);
      const readIv = rev.subarray(32, 48);
      const enc = createCipheriv2("aes-256-ctr", writeKey, writeIv);
      enc.update(Buffer.alloc(56));
      const dec = createCipheriv2("aes-256-ctr", readKey, readIv);
      const tail = Buffer.alloc(8);
      tail.fill(239, 0, 4);
      tail.writeInt16LE(dc, 4);
      tail.writeUInt16LE(0, 6);
      enc.update(tail).copy(nonce, 56);
      const reqPq = Buffer.alloc(40);
      reqPq.writeBigUInt64LE(0n, 0);
      reqPq.writeBigUInt64LE(BigInt(Math.floor(Date.now() / 1e3)) << 32n, 8);
      reqPq.writeInt32LE(20, 16);
      reqPq.writeUInt32LE(3195965169, 20);
      randomBytes2(16).copy(reqPq, 24);
      const encReq = enc.update(Buffer.concat([Buffer.from([10]), reqPq]));
      const rxChunks = [];
      sock.on("data", (chunk) => {
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
async function probeDcs(cfg) {
  const keys = Object.keys(cfg.dc).map(Number).sort((a, b) => a - b);
  const results = [];
  const configuredPorts = cfg.dcPorts?.length ? cfg.dcPorts : [443, 80, 5222];
  const probePort = configuredPorts[0] || cfg.dcPort || 443;
  const fallbackPorts = [443, 80, 5222].filter((p) => p !== probePort);
  const probeOne = async (key) => {
    const ips = Array.isArray(cfg.dc[key]) ? cfg.dc[key] : [cfg.dc[key]];
    const ip = ips[Math.floor(Math.random() * ips.length)];
    const r = await probeSingleDc(key, ip, probePort);
    if (key !== 203 && r.mtprotoOk === false && fallbackPorts.length > 0) {
      const altResults = await Promise.all(
        fallbackPorts.map(async (altPort) => {
          const ar = await probeSingleDc(key, ip, altPort);
          return {
            port: altPort,
            ok: ar.ok,
            ms: ar.ms,
            mtprotoOk: ar.mtprotoOk,
            reason: ar.reason
          };
        })
      );
      r.altPorts = altResults;
    }
    results.push(r);
  };
  for (let i = 0; i < keys.length; i += 3) {
    await Promise.all(keys.slice(i, i + 3).map(probeOne));
  }
  results.sort((a, b) => a.dc - b.dc);
  logEvent(
    "dc_probe",
    results.map((r) => `DC${r.dc}:${r.ok ? r.mtprotoOk === false ? "tcp_only_eof" : "ok" : "fail"}`).join(" ")
  );
  return results;
}

// src/proxy/router.ts
import { randomBytes as randomBytes4 } from "node:crypto";
import express from "express";

// src/proxy/templates.ts
import { randomBytes as randomBytes3 } from "node:crypto";
var DECOY_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="LUXVEIL \u2014 Premium contemporary fashion. Curated collections of designer apparel, outerwear, and accessories for the modern wardrobe.">
<meta name="robots" content="index, follow">
<meta property="og:title" content="LUXVEIL \u2014 Contemporary Fashion House">
<meta property="og:type" content="website">
<title>LUXVEIL &mdash; Contemporary Fashion House</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#faf9f7;--surface:#fff;--text:#1a1a1a;--muted:#71717a;--accent:#92400e;--accent-light:#fef3c7;--border:#e4e4e7;--hover:#f4f4f5;--gold:#b8860b;--shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);--shadow-lg:0 10px 25px rgba(0,0,0,.07),0 4px 10px rgba(0,0,0,.04)}
@keyframes fadeUp{from{opacity:0;transform:translateY(28px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
@keyframes marquee{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,Helvetica,Arial,sans-serif;line-height:1.6;-webkit-font-smoothing:antialiased;overflow-x:hidden}
a{color:inherit;text-decoration:none}
.announce{background:var(--text);color:#fff;text-align:center;padding:.55rem 1rem;font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;overflow:hidden}
.announce-inner{display:inline-flex;gap:3rem;animation:marquee 25s linear infinite;white-space:nowrap}
nav{background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;backdrop-filter:blur(12px);background:rgba(255,255,255,.92)}
.nav-inner{max-width:1280px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;padding:.85rem 2rem}
.nav-logo{font-size:1.4rem;font-weight:800;letter-spacing:.22em;text-transform:uppercase}
.nav-links{display:flex;gap:2rem;list-style:none;font-size:.88rem;font-weight:500;letter-spacing:.03em;text-transform:uppercase}
.nav-links a{position:relative;padding:.25rem 0;transition:color .2s}
.nav-links a::after{content:'';position:absolute;bottom:0;left:0;width:0;height:1.5px;background:var(--accent);transition:width .3s ease}
.nav-links a:hover::after{width:100%}
.nav-links a:hover{color:var(--accent)}
.nav-icons{display:flex;align-items:center;gap:1.25rem}
.nav-icons svg{width:20px;height:20px;stroke:var(--text);stroke-width:1.5;fill:none;cursor:pointer;transition:stroke .2s}
.nav-icons svg:hover{stroke:var(--accent)}
.cart-badge{position:relative}
.cart-badge::after{content:'2';position:absolute;top:-6px;right:-8px;background:var(--accent);color:#fff;font-size:.6rem;width:16px;height:16px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700}
.hamburger{display:none;flex-direction:column;gap:4px;cursor:pointer;padding:4px}
.hamburger span{width:20px;height:1.5px;background:var(--text);border-radius:1px}
.hero{max-width:1280px;margin:0 auto;padding:0 2rem;display:grid;grid-template-columns:1fr 1fr;gap:3rem;align-items:center;min-height:75vh;animation:fadeIn .8s ease}
.hero-text{animation:fadeUp .9s ease .1s both}
.hero-tag{display:inline-block;font-size:.72rem;letter-spacing:.15em;text-transform:uppercase;color:var(--accent);background:var(--accent-light);padding:.35rem .9rem;border-radius:2rem;font-weight:600;margin-bottom:1.5rem}
.hero h1{font-size:3.5rem;font-weight:800;line-height:1.08;letter-spacing:-.02em;margin-bottom:1.25rem}
.hero h1 em{font-style:normal;color:var(--accent)}
.hero p{font-size:1.1rem;color:var(--muted);max-width:460px;margin-bottom:2rem;line-height:1.7}
.hero-btns{display:flex;gap:1rem;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:.5rem;padding:.85rem 2rem;border-radius:.4rem;font-size:.88rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;transition:all .25s ease;cursor:pointer;border:none}
.btn-primary{background:var(--text);color:#fff}
.btn-primary:hover{background:var(--accent);transform:translateY(-1px);box-shadow:var(--shadow-lg)}
.btn-outline{background:transparent;color:var(--text);border:1.5px solid var(--border)}
.btn-outline:hover{border-color:var(--text);background:var(--hover)}
.hero-visual{position:relative;animation:fadeUp .9s ease .3s both}
.hero-img{width:100%;aspect-ratio:3/4;background:linear-gradient(135deg,#e8e0d6 0%,#d4c8b8 30%,#c9b99a 60%,#b8a88a 100%);border-radius:1rem;overflow:hidden;position:relative}
.hero-img::before{content:'';position:absolute;inset:0;background:linear-gradient(45deg,transparent 40%,rgba(255,255,255,.15) 50%,transparent 60%);background-size:200% 200%;animation:shimmer 4s ease-in-out infinite}
.hero-img::after{content:'LUXVEIL';position:absolute;bottom:2rem;left:2rem;font-size:1.1rem;letter-spacing:.3em;text-transform:uppercase;color:rgba(255,255,255,.7);font-weight:300}
.hero-float{position:absolute;right:-1rem;top:25%;background:var(--surface);border-radius:.75rem;padding:1rem 1.25rem;box-shadow:var(--shadow-lg);animation:float 4s ease-in-out infinite;z-index:2}
.hero-float .hf-label{font-size:.65rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:.25rem}
.hero-float .hf-value{font-size:1.3rem;font-weight:700;color:var(--accent)}
.banner{background:var(--text);padding:1rem 0;overflow:hidden}
.banner-track{display:flex;gap:3rem;animation:marquee 20s linear infinite;white-space:nowrap}
.banner-track span{color:rgba(255,255,255,.6);font-size:.78rem;letter-spacing:.2em;text-transform:uppercase;font-weight:500}
.section{max-width:1280px;margin:0 auto;padding:5rem 2rem}
.section-head{text-align:center;margin-bottom:3.5rem}
.section-head h2{font-size:2.2rem;font-weight:800;letter-spacing:-.01em;margin-bottom:.75rem}
.section-head p{color:var(--muted);font-size:1rem;max-width:480px;margin:0 auto}
.products{display:grid;grid-template-columns:repeat(4,1fr);gap:1.5rem}
.product{cursor:pointer}
.product-img{aspect-ratio:3/4;border-radius:.75rem;overflow:hidden;position:relative;margin-bottom:1rem}
.product-img .img-fill{width:100%;height:100%;transition:transform .6s ease}
.product:hover .img-fill{transform:scale(1.06)}
.p1 .img-fill{background:linear-gradient(160deg,#c4b5a3,#a89279)}
.p2 .img-fill{background:linear-gradient(160deg,#2c2c2c,#555)}
.p3 .img-fill{background:linear-gradient(160deg,#8b7355,#c4a97d)}
.p4 .img-fill{background:linear-gradient(160deg,#d6cfc4,#a89888)}
.product-img .quick{position:absolute;bottom:0;left:0;right:0;background:rgba(26,26,26,.88);color:#fff;text-align:center;padding:.7rem;font-size:.78rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;transform:translateY(100%);transition:transform .35s ease;backdrop-filter:blur(4px)}
.product:hover .quick{transform:translateY(0)}
.product-info h3{font-size:.92rem;font-weight:600;margin-bottom:.3rem}
.product-info .cat{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.4rem}
.product-info .price{font-size:.95rem;font-weight:700}
.product-info .price .old{text-decoration:line-through;color:var(--muted);font-weight:400;margin-left:.4rem;font-size:.85rem}
.product-colors{display:flex;gap:.35rem;margin-top:.5rem}
.product-colors span{width:14px;height:14px;border-radius:50%;border:1.5px solid var(--border);transition:transform .2s}
.product-colors span:hover{transform:scale(1.3)}
.features{display:grid;grid-template-columns:repeat(4,1fr);gap:2rem;margin-top:4rem}
.feature{text-align:center;padding:2rem 1.25rem;border-radius:.75rem;transition:all .3s ease}
.feature:hover{background:var(--surface);box-shadow:var(--shadow-lg);transform:translateY(-4px)}
.feature svg{width:32px;height:32px;stroke:var(--accent);stroke-width:1.5;fill:none;margin:0 auto 1rem}
.feature h4{font-size:.92rem;font-weight:700;margin-bottom:.4rem;text-transform:uppercase;letter-spacing:.04em}
.feature p{font-size:.82rem;color:var(--muted);line-height:1.6}
.lookbook{display:grid;grid-template-columns:1fr 1fr;gap:0;min-height:65vh;margin:5rem 0}
.lookbook-img{background:linear-gradient(160deg,#d4c4b0,#baa78c);position:relative;overflow:hidden}
.lookbook-img::before{content:'';position:absolute;inset:0;background:linear-gradient(180deg,transparent 60%,rgba(0,0,0,.2) 100%)}
.lookbook-content{display:flex;flex-direction:column;justify-content:center;padding:5rem 4rem;background:var(--surface)}
.lookbook-content .lb-tag{font-size:.7rem;letter-spacing:.2em;text-transform:uppercase;color:var(--accent);margin-bottom:1rem}
.lookbook-content h2{font-size:2.8rem;font-weight:800;line-height:1.1;margin-bottom:1.25rem}
.lookbook-content p{color:var(--muted);font-size:1rem;line-height:1.8;margin-bottom:2rem;max-width:400px}
.reviews{display:grid;grid-template-columns:repeat(3,1fr);gap:1.5rem}
.review{background:var(--surface);border:1px solid var(--border);border-radius:.75rem;padding:2rem;transition:box-shadow .3s,transform .3s}
.review:hover{box-shadow:var(--shadow-lg);transform:translateY(-3px)}
.review-stars{color:var(--gold);font-size:.85rem;margin-bottom:.75rem;letter-spacing:2px}
.review p{font-size:.9rem;color:var(--text);line-height:1.7;margin-bottom:1rem;font-style:italic}
.review-author{font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.newsletter{text-align:center;background:var(--text);color:#fff;padding:5rem 2rem}
.newsletter h2{font-size:2rem;font-weight:800;margin-bottom:.75rem}
.newsletter p{color:rgba(255,255,255,.55);margin-bottom:2rem;font-size:.95rem}
.newsletter-form{display:flex;max-width:460px;margin:0 auto;border-radius:.4rem;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.2)}
.newsletter-form input{flex:1;padding:.9rem 1.25rem;border:none;font-size:.88rem;outline:none;background:#fff;color:var(--text)}
.newsletter-form button{padding:.9rem 1.8rem;background:var(--accent);color:#fff;border:none;font-size:.82rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;transition:background .2s;white-space:nowrap}
.newsletter-form button:hover{background:#7c3309}
footer{background:var(--surface);border-top:1px solid var(--border);padding:4rem 2rem 2rem}
.footer-inner{max-width:1280px;margin:0 auto}
.footer-grid{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:3rem;margin-bottom:3rem}
.footer-brand .f-logo{font-size:1.2rem;font-weight:800;letter-spacing:.2em;text-transform:uppercase;margin-bottom:.75rem}
.footer-brand p{color:var(--muted);font-size:.85rem;line-height:1.7;max-width:280px}
.footer-col h5{font-size:.75rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:1rem}
.footer-col ul{list-style:none}
.footer-col li{margin-bottom:.5rem}
.footer-col a{font-size:.88rem;color:var(--text);transition:color .2s}
.footer-col a:hover{color:var(--accent)}
.footer-bottom{display:flex;justify-content:space-between;align-items:center;padding-top:2rem;border-top:1px solid var(--border);font-size:.78rem;color:var(--muted)}
.footer-social{display:flex;gap:1rem}
.footer-social svg{width:18px;height:18px;stroke:var(--muted);stroke-width:1.5;fill:none;transition:stroke .2s;cursor:pointer}
.footer-social svg:hover{stroke:var(--accent)}
@media(max-width:1024px){
.hero{grid-template-columns:1fr;text-align:center;min-height:auto;padding-top:3rem}
.hero h1{font-size:2.6rem}
.hero p{margin:0 auto 2rem}
.hero-btns{justify-content:center}
.hero-visual{max-width:400px;margin:0 auto}
.hero-float{display:none}
.products{grid-template-columns:repeat(2,1fr)}
.features{grid-template-columns:repeat(2,1fr)}
.lookbook{grid-template-columns:1fr}
.lookbook-content{padding:3rem 2rem}
.footer-grid{grid-template-columns:1fr 1fr}
.reviews{grid-template-columns:1fr}
}
@media(max-width:640px){
.nav-links{display:none}
.hamburger{display:flex}
.hero h1{font-size:2rem}
.products,.features,.footer-grid{grid-template-columns:1fr}
.newsletter-form{flex-direction:column}
.newsletter-form input,.newsletter-form button{width:100%}
.lookbook-content h2{font-size:2rem}
}
</style>
</head>
<body>
<div class="announce"><div class="announce-inner"><span>Free express shipping on orders over \\$150</span><span>&bull;</span><span>New Season &mdash; Autumn/Winter 2026 Collection now live</span><span>&bull;</span><span>Complimentary gift wrapping on all orders</span><span>&bull;</span><span>Free express shipping on orders over \\$150</span><span>&bull;</span><span>New Season &mdash; Autumn/Winter 2026 Collection now live</span><span>&bull;</span><span>Complimentary gift wrapping on all orders</span></div></div>
<nav><div class="nav-inner"><a href="/" class="nav-logo">LUXVEIL</a><ul class="nav-links"><li><a href="/">New Arrivals</a></li><li><a href="/">Women</a></li><li><a href="/">Men</a></li><li><a href="/">Outerwear</a></li><li><a href="/">Accessories</a></li><li><a href="/">Sale</a></li></ul><div class="nav-icons"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.35-4.35"/></svg><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><div class="cart-badge"><svg viewBox="0 0 24 24"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 0 1-8 0"/></svg></div><div class="hamburger"><span></span><span></span><span></span></div></div></div></nav>
<section class="hero"><div class="hero-text"><div class="hero-tag">Autumn/Winter 2026</div><h1>Redefine Your<br><em>Everyday</em> Elegance</h1><p>Discover our latest collection of meticulously crafted garments, designed with premium fabrics and contemporary silhouettes for the modern wardrobe.</p><div class="hero-btns"><a href="/" class="btn btn-primary">Shop Collection <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg></a><a href="/" class="btn btn-outline">Lookbook</a></div></div><div class="hero-visual"><div class="hero-img"></div><div class="hero-float"><div class="hf-label">Best Seller</div><div class="hf-value">Cashmere Overcoat</div></div></div></section>
<div class="banner"><div class="banner-track"><span>Premium Quality</span><span>&#10022;</span><span>Sustainable Materials</span><span>&#10022;</span><span>Handcrafted Details</span><span>&#10022;</span><span>Worldwide Delivery</span><span>&#10022;</span><span>30-Day Returns</span><span>&#10022;</span><span>Premium Quality</span><span>&#10022;</span><span>Sustainable Materials</span><span>&#10022;</span><span>Handcrafted Details</span><span>&#10022;</span><span>Worldwide Delivery</span><span>&#10022;</span><span>30-Day Returns</span></div></div>
<section class="section"><div class="section-head"><h2>Curated Essentials</h2><p>Timeless pieces designed to transition seamlessly from season to season.</p></div><div class="products"><div class="product"><div class="product-img p1"><div class="img-fill"></div><div class="quick">Quick View</div></div><div class="product-info"><div class="cat">Outerwear</div><h3>Wool Blend Overcoat</h3><div class="price">\\$385.00</div><div class="product-colors"><span style="background:#c4b5a3"></span><span style="background:#2c2c2c"></span><span style="background:#8b7355"></span></div></div></div><div class="product"><div class="product-img p2"><div class="img-fill"></div><div class="quick">Quick View</div></div><div class="product-info"><div class="cat">Tailoring</div><h3>Relaxed Fit Blazer</h3><div class="price">\\$265.00</div><div class="product-colors"><span style="background:#2c2c2c"></span><span style="background:#3d4f5f"></span></div></div></div><div class="product"><div class="product-img p3"><div class="img-fill"></div><div class="quick">Quick View</div></div><div class="product-info"><div class="cat">Knitwear</div><h3>Merino Turtleneck</h3><div class="price">\\$145.00 <span class="old">\\$195.00</span></div><div class="product-colors"><span style="background:#8b7355"></span><span style="background:#f5f0eb"></span><span style="background:#4a3728"></span></div></div></div><div class="product"><div class="product-img p4"><div class="img-fill"></div><div class="quick">Quick View</div></div><div class="product-info"><div class="cat">Accessories</div><h3>Leather Crossbody Bag</h3><div class="price">\\$220.00</div><div class="product-colors"><span style="background:#d6cfc4"></span><span style="background:#2c2c2c"></span></div></div></div></div></section>
<section class="section" style="padding-top:0"><div class="features"><div class="feature"><svg viewBox="0 0 24 24"><rect x="1" y="3" width="15" height="13" rx="2"/><path d="M16 8l4 2v4l-4 2"/></svg><h4>Free Shipping</h4><p>Complimentary express delivery on all orders over \\$150. Worldwide tracked shipping.</p></div><div class="feature"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><h4>Secure Checkout</h4><p>256-bit SSL encryption with trusted payment partners. Your data is always protected.</p></div><div class="feature"><svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-9-9c2.5 0 4.8 1 6.5 2.6"/><path d="M22 4L12 14.01l-3-3"/></svg><h4>Quality Guarantee</h4><p>Every garment is inspected for quality. 30-day hassle-free returns and exchanges.</p></div><div class="feature"><svg viewBox="0 0 24 24"><path d="M12 3L2 12h3v8h6v-6h2v6h6v-8h3L12 3z"/></svg><h4>Sustainable Fashion</h4><p>Ethically sourced materials with carbon-neutral shipping. Fashion with a conscience.</p></div></div></section>
<section class="lookbook"><div class="lookbook-img"></div><div class="lookbook-content"><div class="lb-tag">The Lookbook</div><h2>Autumn<br>Silhouettes</h2><p>Explore our editorial collection featuring rich tonal palettes, luxurious textures, and the defining shapes of the season. Each piece tells a story of understated refinement.</p><a href="/" class="btn btn-primary">View Lookbook</a></div></section>
<section class="section"><div class="section-head"><h2>What Our Clients Say</h2><p>Trusted by thousands of discerning customers worldwide.</p></div><div class="reviews"><div class="review"><div class="review-stars">&starf;&starf;&starf;&starf;&starf;</div><p>&ldquo;The quality of the cashmere overcoat exceeded my expectations. Impeccable tailoring and the fabric feels absolutely luxurious.&rdquo;</p><div class="review-author">&mdash; Sarah M., London</div></div><div class="review"><div class="review-stars">&starf;&starf;&starf;&starf;&starf;</div><p>&ldquo;Fast shipping to Dubai and the packaging was beautiful. The merino turtleneck is now my go-to piece for every occasion.&rdquo;</p><div class="review-author">&mdash; Ahmed K., Dubai</div></div><div class="review"><div class="review-stars">&starf;&starf;&starf;&starf;&starf;</div><p>&ldquo;Finally found a brand that combines minimalist design with real craftsmanship. The blazer fits perfectly &mdash; no alterations needed.&rdquo;</p><div class="review-author">&mdash; Elena V., Paris</div></div></div></section>
<section class="newsletter"><h2>Join the LUXVEIL World</h2><p>Subscribe for exclusive access to new collections, private sales, and style inspiration.</p><div class="newsletter-form"><input type="email" placeholder="Enter your email address" autocomplete="off"><button type="button">Subscribe</button></div></section>
<footer><div class="footer-inner"><div class="footer-grid"><div class="footer-brand"><div class="f-logo">LUXVEIL</div><p>Contemporary fashion house crafting timeless garments with modern sensibility. Established 2019, shipping worldwide from our ateliers in Milan and London.</p></div><div class="footer-col"><h5>Shop</h5><ul><li><a href="/">New Arrivals</a></li><li><a href="/">Women</a></li><li><a href="/">Men</a></li><li><a href="/">Outerwear</a></li><li><a href="/">Accessories</a></li><li><a href="/">Sale</a></li></ul></div><div class="footer-col"><h5>Company</h5><ul><li><a href="/">About Us</a></li><li><a href="/">Sustainability</a></li><li><a href="/">Careers</a></li><li><a href="/">Press</a></li><li><a href="/">Store Locator</a></li></ul></div><div class="footer-col"><h5>Support</h5><ul><li><a href="/">Contact Us</a></li><li><a href="/">Shipping &amp; Returns</a></li><li><a href="/">Size Guide</a></li><li><a href="/">FAQ</a></li><li><a href="/">Privacy Policy</a></li></ul></div></div><div class="footer-bottom"><span>&copy; 2026 LUXVEIL Ltd. All rights reserved.</span><div class="footer-social"><svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="20" rx="5"/><circle cx="12" cy="12" r="5"/><circle cx="17.5" cy="6.5" r="1.5" fill="currentColor" stroke="none"/></svg><svg viewBox="0 0 24 24"><path d="M22 4s-.7 2.1-2 3.4c1.6 10-9.4 17.3-18 11.6 2.2.1 4.4-.6 6-2C3 15.5.5 9.6 3 5c2.2 2.6 5.6 4.1 9 4-.9-4.2 4-6.6 7-3.8 1.1 0 3-1.2 3-1.2z"/></svg><svg viewBox="0 0 24 24"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-4 0v7h-4v-7a6 6 0 0 1 6-6z"/><rect x="2" y="9" width="4" height="12"/><circle cx="4" cy="4" r="2"/></svg></div></div></div></footer>
</body>
</html>`;
var BRIDGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connection</title>
</head>
<body>
<script nonce="__NONCE__">
(()=>{
'use strict';
const relayBase=location.origin+'/',bootstrap=__BOOTSTRAP__,carrierMode=__CARRIER_MODE__,sessionPath=__SESSION_PATH__,wsPath=__WS_PATH__;
const fragment=location.hash,androidNonce=/^#android=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1]||'';
history.replaceState(null,'',location.pathname);
let initialized=false,closed=false,port=null,sessionToken='',createStarted=false;
let queuedBytes=0,queuedItems=0,pollController=null,webSocket=null,webSocketTimer=0;
const pending=[],upPending=[],lanes=new Map(),closedLanes=new Set(),closedLaneOrder=[];
const queueLimit=33554432,queueItemLimit=16384,closedLaneLimit=4096;
const laneQueueLimit=8388608,laneItemLimit=1024,batchLimit=__BATCH_LIMIT__;
let upSequence=1,downCursor='0',upRunning=false;
let pingTimer=0,reconnectAttempts=0,reconnecting=false;
const openStreams=new Set();
function trackFrames(value,up){
 const view=new DataView(value);let offset=0;
 while(value.byteLength-offset>=8){
  const type=view.getUint8(offset),id=(view.getUint8(offset+1)<<16)|(view.getUint8(offset+2)<<8)|view.getUint8(offset+3);
  if(id){if(up&&type===1)openStreams.add(id);else if(type===3)openStreams.delete(id)}
  offset+=8+view.getUint32(offset+4);
 }
}
function startHeartbeat(){
 if(pingTimer)clearInterval(pingTimer);
 pingTimer=setInterval(()=>{
  if(closed||!webSocket||webSocket.readyState!==WebSocket.OPEN)return;
  try{
   const ping=new Uint8Array(12);
   ping[0]=5;
   const v=new DataView(ping.buffer);
   v.setUint32(4,4);
   v.setUint32(8,Math.floor(Date.now()/1000));
   webSocket.send(ping.buffer);
  }catch(_){}
 },20000);
}
function stopHeartbeat(){
 if(pingTimer){clearInterval(pingTimer);pingTimer=0}
}
const status=state=>{if(port&&!closed)port.postMessage({t:'status',state})};
const pause=milliseconds=>new Promise(resolve=>setTimeout(resolve,milliseconds));
const options=(method,token,body,headers,signal,keepalive)=>({
 method,body,signal,keepalive:!!keepalive,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
 headers:Object.assign(token?{Authorization:'Bearer '+token}:{},body?{'Content-Type':'application/octet-stream'}:{},headers||{})
});
const bufferedBytes=()=>{
 let total=webSocket&&webSocket.readyState===WebSocket.OPEN?webSocket.bufferedAmount:0;
 if(carrierMode==='websocket-lanes')for(const lane of lanes.values())if(lane.socket&&lane.socket.readyState===WebSocket.OPEN)total+=lane.socket.bufferedAmount;
 return total;
};
function reserve(data,lane){
 if(!data.byteLength||queuedBytes+bufferedBytes()>queueLimit-data.byteLength||queuedItems>=queueItemLimit)return false;
 if(lane&&(lane.bytes>laneQueueLimit-data.byteLength||lane.items>=laneItemLimit))return false;
 queuedBytes+=data.byteLength;queuedItems++;
 if(lane){lane.bytes+=data.byteLength;lane.items++}
 return true;
}
function release(bytes,items,lane){
 queuedBytes-=bytes;queuedItems-=items;
 if(lane){lane.bytes-=bytes;lane.items-=items}
}
function splitFrames(value){
 const view=new DataView(value),result=[];let offset=0;
 while(offset<value.byteLength){
  if(value.byteLength-offset<8||result.length>=4096)throw new Error('invalid frame batch');
  const type=view.getUint8(offset),id=(view.getUint8(offset+1)<<16)|(view.getUint8(offset+2)<<8)|view.getUint8(offset+3);
  const size=view.getUint32(offset+4),end=offset+8+size;
  if((type===2&&!size)||size>1048576||end>value.byteLength)throw new Error('invalid frame');
  result.push({type,id,data:offset===0&&end===value.byteLength?value:value.slice(offset,end)});offset=end;
 }
 if(!result.length)throw new Error('empty frame batch');
 return result;
}
function frameBound(value,maxFrames,maxBytes){
 const view=new DataView(value);let offset=0,frames=0;
 while(offset<value.byteLength){
  if(value.byteLength-offset<8)throw new Error('invalid frame batch');
  const size=view.getUint32(offset+4),end=offset+8+size;
  if(end>value.byteLength)throw new Error('invalid frame');
  if(frames>0&&(frames>=maxFrames||end>maxBytes))break;
  frames++;offset=end;
 }
 return {frames,bytes:offset};
}
function joinPending(values,lane){
 let total=0,count=0,frames=0;
 while(count<values.length){
  const bound=frameBound(values[count],4096,batchLimit);
  const whole=bound.bytes===values[count].byteLength;
  if(count===0&&!whole){
   const head=new Uint8Array(values[0],0,bound.bytes).slice();
   values[0]=values[0].slice(bound.bytes);
   queuedItems++;if(lane)lane.items++;
   return {body:head.buffer,total:bound.bytes,count:1};
  }
  if(count!==0&&(total+values[count].byteLength>batchLimit||frames+bound.frames>4096))break;
  total+=values[count].byteLength;frames+=bound.frames;count++;
 }
 const joined=new Uint8Array(total);let offset=0;
 for(const data of values.splice(0,count)){joined.set(new Uint8Array(data),offset);offset+=data.byteLength}
 return {body:joined.buffer,total,count};
}
function retryAfterMs(response){
 const header=response.headers.get('Retry-After');
 if(!header)return 0;
 const seconds=Number(header);
 if(Number.isFinite(seconds)&&seconds>=0)return Math.min(seconds*1000,30000);
 const when=Date.parse(header);
 if(Number.isFinite(when)){const delta=when-Date.now();return delta>0?Math.min(delta,30000):0}
 return 0;
}
async function request(path,makeOptions){
 let delay=250,attempt=0;const deadline=Date.now()+90000;
 while(true){
  const requestOptions=makeOptions(),controller=new AbortController();
  const external=requestOptions.signal,abort=()=>controller.abort();
  if(external)external.addEventListener('abort',abort,{once:true});
  requestOptions.signal=controller.signal;
  const timer=setTimeout(abort,90000);
  let wait=0,serviceUnavailable=false;
  try{
   const response=await fetch(relayBase+path,requestOptions);
   if(response.status!==503)return response;
   serviceUnavailable=true;wait=retryAfterMs(response);
   await response.arrayBuffer();
  }catch(error){if(closed||(external&&external.aborted))throw error;attempt++;if(attempt===9)throw new Error('carrier retry limit reached')}
  finally{clearTimeout(timer);if(external)external.removeEventListener('abort',abort)}
  if(serviceUnavailable&&Date.now()>=deadline)throw new Error('carrier retry limit reached');
  status('reconnecting');
  const backoff=wait||(delay+Math.floor(Math.random()*Math.max(1,delay/4)));
  await pause(backoff);
  if(!serviceUnavailable)delay=Math.min(delay*2,5000);
 }
}
function fail(){
 if(closed)return;
 status('failed');
 if(port)port.postMessage({t:'close'});
 close(true);
}
async function createSession(first){
 try{
  status('connecting');
  const response=await request(sessionPath,()=>options('POST',bootstrap,first));
  if(response.status!==200||response.headers.get('X-Carrier-Mode')!==carrierMode)throw new Error('session creation rejected');
  sessionToken=response.headers.get('X-Session-Token')||'';
  downCursor=response.headers.get('X-Down-Cursor')||'0';
  if(!sessionToken)throw new Error('missing session token');
  if(closed){fetch(relayBase+sessionPath,options('DELETE',sessionToken,null,null,undefined,true)).catch(()=>{});return}
  const welcome=await response.arrayBuffer();
  if(carrierMode==='websocket')await openWebSocket();
  if(closed){fetch(relayBase+sessionPath,options('DELETE',sessionToken,null,null,undefined,true)).catch(()=>{});return}
  port.postMessage(welcome,[welcome]);
  status('connected');
  for(const data of pending.splice(0)){release(data.byteLength,1,null);queueCarrier(data)}
  if(carrierMode==='https')poll();
  else if(carrierMode==='https-lanes')pollLane(ensureLane(0));
 }catch(error){fail()}
}
function queueCarrier(data){
 try{
  if(carrierMode==='https')queueUp(data);
  else if(carrierMode==='https-lanes')for(const value of splitFrames(data))queueLane(value);
  else if(carrierMode==='websocket')queueWebSocket(data);
  else for(const value of splitFrames(data))queueWebSocketLane(value);
 }catch(error){fail()}
}
function queueUp(data){
 if(!reserve(data,null)){fail();return}
 upPending.push(data);runUp();
}
async function runUp(){
 if(upRunning)return;
 upRunning=true;
 try{
  while(!closed&&sessionToken&&upPending.length){
   const batch=joinPending(upPending,null),sequence=String(upSequence);
   const response=await request('api/v1/up',()=>options('POST',sessionToken,batch.body,{'X-Up-Seq':sequence}));
   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('uplink rejected');
   release(batch.total,batch.count,null);port.postMessage({t:'traffic',up:batch.total,down:0});upSequence++;
  }
 }catch(error){fail()}
 finally{upRunning=false;if(!closed&&sessionToken&&upPending.length)runUp()}
}
async function poll(){
 while(!closed&&sessionToken){
  try{
   pollController=new AbortController();
   const response=await request('api/v1/down',()=>options('POST',sessionToken,null,{'X-Down-Cursor':downCursor},pollController.signal));
   if(response.status===204){status('connected');continue}
   if(response.status!==200)throw new Error('downlink rejected');
   const next=response.headers.get('X-Down-Cursor')||'',data=await response.arrayBuffer();
   if(!next||!data.byteLength)throw new Error('invalid downlink response');
   if(closed)return;
   port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);downCursor=next;status('connected');
  }catch(error){if(!closed)fail();return}
 }
}
function ensureLane(id){
 let lane=lanes.get(id);
 if(!lane){lane={id,sequence:1,cursor:'0',pending:[],bytes:0,items:0,running:false,polling:false,socket:null,timer:0,opened:false,localClosed:false,remoteClosed:false,finished:false};lanes.set(id,lane)}
 return lane;
}
function rememberLaneClosed(id){
 if(!id||closedLanes.has(id))return;
 if(closedLaneOrder.length===closedLaneLimit)closedLanes.delete(closedLaneOrder.shift());
 closedLanes.add(id);closedLaneOrder.push(id);
}
function queueLane(value){
 let lane=lanes.get(value.id);
 if(!lane&&(value.type===2||value.type===3||value.type===4))return;
 if(!lane&&closedLanes.has(value.id))throw new Error('closed lane was reused');
 if(!lane&&value.type!==1)throw new Error('lane did not begin with OPEN');
 lane=lane||ensureLane(value.id);
 if(!reserve(value.data,lane)){fail();return}
 lane.pending.push(value.data);runLaneUp(lane);
}
async function runLaneUp(lane){
 if(lane.running)return;
 lane.running=true;
 try{
  while(!closed&&sessionToken&&lane.pending.length){
   const batch=joinPending(lane.pending,lane),sequence=String(lane.sequence),laneID=String(lane.id);
   const response=await request('api/v1/up',()=>options('POST',sessionToken,batch.body,{'X-Up-Seq':sequence,'X-Lane-ID':laneID}));
   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('lane uplink rejected');
   release(batch.total,batch.count,lane);port.postMessage({t:'traffic',up:batch.total,down:0});lane.sequence++;
   if(!lane.polling)pollLane(lane);
  }
 }catch(error){fail()}
 finally{lane.running=false;if(!closed&&sessionToken&&lane.pending.length)runLaneUp(lane)}
}
async function pollLane(lane){
 if(lane.polling)return;
 lane.polling=true;
 try{
  while(!closed&&sessionToken&&lanes.get(lane.id)===lane){
   const controller=new AbortController(),laneID=String(lane.id);
   lane.controller=controller;
   const response=await request('api/v1/down',()=>options('POST',sessionToken,null,{'X-Down-Cursor':lane.cursor,'X-Lane-ID':laneID},controller.signal));
   if(response.status===204){
    if(response.headers.get('X-Lane-Closed')==='1'){lanes.delete(lane.id);rememberLaneClosed(lane.id);return}
    status('connected');continue;
   }
   if(response.status!==200)throw new Error('lane downlink rejected');
   const next=response.headers.get('X-Down-Cursor')||'',data=await response.arrayBuffer();
   if(!next||!data.byteLength)throw new Error('invalid lane downlink response');
   for(const value of splitFrames(data))if(value.id!==lane.id)throw new Error('cross-lane frame');
   if(closed)return;
   port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);lane.cursor=next;status('connected');
  }
 }catch(error){if(!closed)fail()}
 finally{lane.polling=false;lane.controller=null}
}
function openWebSocket(){
 return new Promise((resolve,reject)=>{
  const target=relayBase.replace(/^http(s?):/,'ws$1:')+wsPath,socket=new WebSocket(target,'tproxy-v1.'+sessionToken);
  webSocket=socket;socket.binaryType='arraybuffer';
  let opened=false;
  socket.onopen=()=>{
   opened=true;
   startHeartbeat();
   resolve();
  };
  socket.onmessage=event=>{
   if(!(event.data instanceof ArrayBuffer)||!event.data.byteLength){fail();return}
   if(event.data.byteLength>=8){
    const view=new DataView(event.data);
    const type=view.getUint8(0);
    const id=(view.getUint8(1)<<16)|(view.getUint8(2)<<8)|view.getUint8(3);
    if(id===0){
     if(type===5){
      const pong=new Uint8Array(event.data.slice(0));
      pong[0]=6;
      if(socket.readyState===WebSocket.OPEN)try{socket.send(pong.buffer)}catch(_){}
      return;
     }
     if(type===6)return;
    }
   }
   try{trackFrames(event.data,false)}catch(_){}
   port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
  };
  socket.onerror=()=>reject(new Error('websocket failed'));
  socket.onclose=()=>{
   if(closed||webSocket!==socket||!opened)return;
   scheduleReconnect();
  };
 });
}
function scheduleReconnect(){
 if(closed||reconnecting)return;
 reconnecting=true;stopHeartbeat();status('reconnecting');
 // The server-side session (DC sockets + cipher state) died with the old socket.
 // Close those streams towards Telegram so it reopens them at once instead of hanging,
 // and drop uplink bytes that belong to the dead streams.
 for(const id of openStreams){const frame=closeFrame(id);port.postMessage(frame,[frame])}
 openStreams.clear();
 if(upPending.length){let bytes=0;for(const data of upPending)bytes+=data.byteLength;release(bytes,upPending.length,null);upPending.length=0}
 const attempt=()=>{
  if(closed)return;
  if(reconnectAttempts>=12){fail();return}
  const delay=Math.min(1000*Math.pow(1.5,Math.min(reconnectAttempts,8)),10000);
  reconnectAttempts++;
  setTimeout(()=>{
   if(closed)return;
   openWebSocket().then(()=>{reconnecting=false;reconnectAttempts=0;status('connected');runWebSocketUp()}).catch(attempt);
  },delay);
 };
 attempt();
}
function queueWebSocket(data){
 trackFrames(data,true);
 if(!reserve(data,null)){fail();return}
 upPending.push(data);runWebSocketUp();
}
function runWebSocketUp(){
 if(closed||!webSocket||webSocket.readyState!==WebSocket.OPEN||!upPending.length)return;
 if(webSocket.bufferedAmount+queuedBytes>queueLimit||webSocket.bufferedAmount>=batchLimit){
  if(!webSocketTimer)webSocketTimer=setTimeout(()=>{webSocketTimer=0;runWebSocketUp()},10);
  return;
 }
 try{
  const batch=joinPending(upPending,null);webSocket.send(batch.body);release(batch.total,batch.count,null);
  port.postMessage({t:'traffic',up:batch.total,down:0});
  if(upPending.length)queueMicrotask(runWebSocketUp);
 }catch(error){fail()}
}
function closeFrame(id){
 const data=new ArrayBuffer(8),view=new DataView(data);
 view.setUint8(0,3);view.setUint8(1,id>>>16);view.setUint8(2,id>>>8);view.setUint8(3,id);view.setUint32(4,0);
 return data;
}
function finishWebSocketLane(lane,notify){
 if(lane.finished||lanes.get(lane.id)!==lane)return;
 lane.finished=true;if(lane.timer)clearTimeout(lane.timer);
 if(lane.bytes||lane.items)release(lane.bytes,lane.items,lane);
 lane.pending.length=0;lanes.delete(lane.id);rememberLaneClosed(lane.id);
 if(lane.socket&&(lane.socket.readyState===WebSocket.OPEN||lane.socket.readyState===WebSocket.CONNECTING))try{lane.socket.close()}catch(error){}
 if(notify&&port&&!closed){const frame=closeFrame(lane.id);port.postMessage(frame,[frame])}
}
function openWebSocketLane(lane){
 const target=relayBase.replace(/^http(s?):/,'ws$1:')+wsPath;
 const socket=new WebSocket(target,'tproxy-lane-v1.'+sessionToken+'.'+lane.id);
 lane.socket=socket;socket.binaryType='arraybuffer';
 socket.onopen=()=>{if(closed||lane.finished){socket.close();return}lane.opened=true;status('connected');runWebSocketLaneUp(lane)};
 socket.onmessage=event=>{
  if(!(event.data instanceof ArrayBuffer)||!event.data.byteLength){fail();return}
  let values;try{values=splitFrames(event.data)}catch(error){fail();return}
  if(values.some(value=>value.id!==lane.id)){fail();return}
  if(values.some(value=>value.type===3))lane.remoteClosed=true;
  port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
 };
 socket.onerror=()=>{};
 socket.onclose=()=>{
  if(closed||lane.finished)return;
  if(!lane.opened){fail();return}
  finishWebSocketLane(lane,!lane.localClosed&&!lane.remoteClosed);
 };
}
function queueWebSocketLane(value){
 let lane=lanes.get(value.id);
 if(!lane&&(value.type===2||value.type===3||value.type===4))return;
 if(!value.id||(!lane&&closedLanes.has(value.id)))throw new Error('closed lane was reused');
 if(!lane&&value.type!==1)throw new Error('lane did not begin with OPEN');
 lane=lane||ensureLane(value.id);
 if(value.type===3&&!lane.opened){finishWebSocketLane(lane,false);return}
 if(!reserve(value.data,lane)){fail();return}
 lane.pending.push(value.data);if(value.type===3)lane.localClosed=true;
 if(!lane.socket)openWebSocketLane(lane);else runWebSocketLaneUp(lane);
}
function runWebSocketLaneUp(lane){
 const socket=lane.socket;
 if(closed||lane.finished||!socket||socket.readyState!==WebSocket.OPEN||!lane.pending.length)return;
 if(socket.bufferedAmount>=batchLimit){
  if(!lane.timer)lane.timer=setTimeout(()=>{lane.timer=0;runWebSocketLaneUp(lane)},10);
  return;
 }
 try{
  const batch=joinPending(lane.pending,lane);socket.send(batch.body);release(batch.total,batch.count,lane);
  port.postMessage({t:'traffic',up:batch.total,down:0});
  if(lane.pending.length)queueMicrotask(()=>runWebSocketLaneUp(lane));
 }catch(error){fail()}
}
function close(notifyServer){
 if(closed)return;
 closed=true;
 stopHeartbeat();
 if(pollController)pollController.abort();
 for(const lane of lanes.values()){
  if(lane.controller)lane.controller.abort();
  if(lane.timer)clearTimeout(lane.timer);
  if(lane.socket)try{lane.socket.close()}catch(error){}
 }
 if(webSocketTimer)clearTimeout(webSocketTimer);
 if(webSocket)webSocket.close();
 if(notifyServer&&sessionToken)fetch(relayBase+sessionPath,options('DELETE',sessionToken,null,null,undefined,true)).catch(()=>{});
 if(port)port.close();
}
function activatePort(nextPort){
 initialized=true;port=nextPort;
 port.onmessage=message=>{
  if(message.data instanceof ArrayBuffer){
   if(!createStarted){createStarted=true;createSession(message.data)}
   else if(!sessionToken){if(!reserve(message.data,null)){fail();return}pending.push(message.data)}
   else queueCarrier(message.data);
  }else if(message.data&&message.data.t==='close')close(true);
 };
 port.start();status('connecting');
}
addEventListener('message',event=>{
 if(initialized||event.source!==parent||event.data===null||typeof event.data!=='object')return;
 const keys=Object.keys(event.data).sort();
 if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||event.data.t!=='tproxy-init'||event.data.v!==1||event.ports.length!==1)return;
 let source;try{source=new URL(event.origin)}catch(error){return}
 if(source.protocol!=='http:'||source.hostname!=='127.0.0.1'||!source.port||source.origin!==event.origin)return;
 activatePort(event.ports[0]);
},{once:false});
const androidBridge=globalThis.TelegramWebProxy;
if(!initialized&&androidNonce&&androidBridge&&typeof androidBridge.postMessage==='function'){
 const androidPort={onmessage:null,start(){},close(){androidBridge.onmessage=null},postMessage(value){
  if(value instanceof ArrayBuffer){
   let frames;try{frames=splitFrames(value)}catch(error){fail();return}
   for(const frame of frames)androidBridge.postMessage(frame.data);
  }else androidBridge.postMessage(JSON.stringify(value));
 }};
 androidBridge.onmessage=event=>{
  let data=event.data;if(typeof data==='string'){try{data=JSON.parse(data)}catch(error){return}}
  if(androidPort.onmessage)androidPort.onmessage({data});
 };
 activatePort(androidPort);androidBridge.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce:androidNonce}));
}
addEventListener('pagehide',()=>close(true),{once:true});
})();
</script>
</body>
</html>
`;
async function sendDecoy(req, res, decoyUrl) {
  if (decoyUrl && (decoyUrl.startsWith("http://") || decoyUrl.startsWith("https://"))) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8e3);
      const upstream = await fetch(decoyUrl, {
        method: req.method === "HEAD" ? "HEAD" : "GET",
        signal: controller.signal,
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }
      });
      clearTimeout(timer);
      const status = upstream.status >= 200 && upstream.status <= 599 ? upstream.status : 200;
      const nullBody = req.method === "HEAD" || status === 204 || status === 205 || status === 304;
      res.status(status);
      res.setHeader("Content-Type", upstream.headers.get("content-type") || "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "no-cache");
      if (nullBody) {
        res.end();
        return;
      }
      const buf = Buffer.from(await upstream.arrayBuffer());
      res.send(buf);
      return;
    } catch {
    }
  }
  res.status(200);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Vary", "Accept-Encoding");
  if (req.method === "HEAD") {
    res.end();
    return;
  }
  res.send(DECOY_HTML);
}
function serveBridge(req, res, cfg, host, proto, mode, port) {
  const nonce = b64uEncode(randomBytes3(18));
  const bootstrap = issueToken(cfg, TOKEN_KIND_BOOTSTRAP, cfg.bootstrapTtl, mode);
  const body = BRIDGE_HTML.replaceAll("__NONCE__", nonce).replaceAll("__BOOTSTRAP__", JSON.stringify(bootstrap)).replaceAll("__CARRIER_MODE__", JSON.stringify(cfg.carrier)).replaceAll("__BATCH_LIMIT__", String(cfg.batchBytes)).replaceAll("__SESSION_PATH__", JSON.stringify(cfg.sessionPath.replace(/^\//, ""))).replaceAll("__WS_PATH__", JSON.stringify(cfg.wsPath.replace(/^\//, "")));
  const wsProto = proto === "http" ? "ws" : "wss";
  const cspHosts = [host, ...cfg.extraHosts, ...cfg.hosts].map((h) => h.trim().toLowerCase()).filter((h, i, arr) => h && h !== "*" && h !== "proxy.example.com" && arr.indexOf(h) === i);
  const connectSources = cspHosts.flatMap((h) => [
    `${proto}://${h}:*`,
    `${wsProto}://${h}:*`,
    `${proto}://${h}`,
    `${wsProto}://${h}`,
    `https://${h}:*`,
    `wss://${h}:*`,
    `https://${h}`,
    `wss://${h}`
  ]);
  const csp = [
    "default-src 'none'",
    "base-uri 'none'",
    "child-src 'none'",
    `connect-src 'self' ${connectSources.join(" ")}`,
    "font-src 'none'",
    "form-action 'none'",
    "frame-ancestors http://127.0.0.1:*",
    "frame-src 'none'",
    "img-src 'none'",
    "manifest-src 'none'",
    "media-src 'none'",
    "object-src 'none'",
    "script-src 'nonce-" + nonce + "'",
    "style-src 'none'",
    "worker-src 'none'",
    "sandbox allow-same-origin allow-scripts"
  ].join("; ");
  res.status(200);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Content-Security-Policy", csp);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  res.setHeader("Permissions-Policy", PERMISSIONS_POLICY);
  if (req.method === "HEAD") {
    res.end();
    return;
  }
  res.send(body);
}

// src/proxy/router.ts
function sendNotFound(res) {
  res.status(404).setHeader("Content-Type", "text/plain; charset=utf-8").setHeader("Cache-Control", "no-store").send("Not Found");
}
function sendSecretText(res, cfg, host, label, port) {
  const cleanLabel = String(label || "").replace(/^https?:\/\//i, "").replace(/\/.*$/, "").replace(/[\u0000-\u001f\u007f]/g, "").trim().toLowerCase().slice(0, 128);
  const isCustomDomain = cleanLabel.length > 0;
  let hex = "";
  let domainHex = "";
  let isExisting = false;
  if (isCustomDomain) {
    for (let i = 0; i < cleanLabel.length; i++) {
      domainHex += cleanLabel.charCodeAt(i).toString(16).padStart(2, "0");
    }
    const derived = deriveSecret(cfg, cleanLabel);
    if (derived) hex = bytesToHex(derived);
    if (!hex) hex = bytesToHex(randomBytes4(16));
  } else if (cfg.base) {
    hex = bytesToHex(cfg.base);
    isExisting = true;
  } else {
    hex = bytesToHex(randomBytes4(16));
  }
  const portSuffix = port && port !== "443" && port !== "80" ? `&port=${port}` : "";
  const link = `tg://webproxy?server=${encodeURIComponent(host)}${portSuffix}&secret=${hex}`;
  const paddedSecret = `dd${hex}`;
  const paddedLink = `tg://webproxy?server=${encodeURIComponent(host)}${portSuffix}&secret=${paddedSecret}`;
  const lines = [
    "=== ProxyGosha Node.js Secret Generator ===",
    isCustomDomain ? `[Mode: DOMAIN-DERIVED SECRET for "${cleanLabel}"]` : isExisting ? "[Status: ACTIVE CONFIGURATION]" : "[Status: NEW SECRET GENERATED]",
    "",
    "Server:        " + host + (port && port !== "443" && port !== "80" ? ":" + port : "")
  ];
  if (isCustomDomain) {
    lines.push("Target Domain: " + cleanLabel);
    lines.push("Domain Hex:    " + domainHex);
  }
  lines.push("Secret:        " + hex);
  lines.push("Telegram Link: " + link);
  lines.push("");
  lines.push("Padded Secret: " + paddedSecret + " (Random padding mode - recommended)");
  lines.push("Padded Link:   " + paddedLink);
  lines.push("");
  res.status(200).setHeader("Content-Type", "text/plain; charset=utf-8").setHeader("Cache-Control", "no-store").setHeader("X-Robots-Tag", "noindex").setHeader("Referrer-Policy", "no-referrer").setHeader("X-Content-Type-Options", "nosniff").send(lines.join("\n"));
}
async function handleSession(req, res, cfg) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ") || auth.length <= 7) {
    logEvent("session_reject", `method=${req.method} reason=missing_bearer`);
    sendNotFound(res);
    return;
  }
  const token = auth.substring(7);
  if (req.method === "DELETE") {
    if (!verifyToken(cfg, token, TOKEN_KIND_SESSION)) {
      logEvent("session_reject", "method=DELETE reason=invalid_token");
      sendNotFound(res);
      return;
    }
    res.status(204).setHeader("Cache-Control", "no-store").end();
    return;
  }
  if (req.method !== "POST") {
    logEvent("session_reject", `method=${req.method} reason=bad_method`);
    sendNotFound(res);
    return;
  }
  if (req.headers.cookie) {
    logEvent("session_reject", "reason=cookie_present");
    sendNotFound(res);
    return;
  }
  const contentType = (req.headers["content-type"] || "").toLowerCase().split(";")[0].trim();
  if (contentType !== "application/octet-stream") {
    logEvent("session_reject", `reason=bad_ct(${contentType || "empty"})`);
    sendNotFound(res);
    return;
  }
  const declaredLength = parseInt(String(req.headers["content-length"] || ""), 10);
  if (Number.isFinite(declaredLength) && declaredLength > 4096) {
    logEvent("session_reject", `reason=too_large(${declaredLength})`);
    sendNotFound(res);
    return;
  }
  const verified = verifyToken(cfg, token, TOKEN_KIND_BOOTSTRAP);
  if (!verified) {
    logEvent("session_reject", "reason=invalid_bootstrap");
    sendNotFound(res);
    return;
  }
  if ((verified.mode === 1 || verified.mode === 2) && !cfg.acceptGenerated) {
    logEvent("session_reject", `reason=generated_disabled mode=${verified.mode}`);
    sendNotFound(res);
    return;
  }
  const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  if (body.length !== 9) {
    logEvent("session_reject", `reason=bad_body_len(${body.length})`);
    sendNotFound(res);
    return;
  }
  if (body[0] !== 16 || body[1] !== 0 || body[2] !== 0 || body[3] !== 0 || body[4] !== 0 || body[5] !== 0 || body[6] !== 0 || body[7] !== 1 || body[8] !== 1) {
    logEvent("session_reject", "reason=bad_hello_magic");
    sendNotFound(res);
    return;
  }
  const sessionToken = issueToken(cfg, TOKEN_KIND_SESSION, cfg.sessionTtl, verified.mode);
  logEvent("session_ok", `carrier=${cfg.carrier} mode=${verified.mode}`);
  res.status(200).setHeader("Content-Type", "application/octet-stream").setHeader("Cache-Control", "no-store").setHeader("X-Session-Token", sessionToken).setHeader("X-Down-Cursor", "0").setHeader("X-Carrier-Mode", cfg.carrier).send(WELCOME);
}
function buildPanelStatePayload(cfg, host, proto) {
  const baseSecret = cfg.base ? "dd" + bytesToHex(cfg.base) : "";
  const hosts = [];
  for (const h of [host, ...cfg.extraHosts]) {
    if (h && !hosts.includes(h)) hosts.push(h);
  }
  const hostConfigs = hosts.map((h) => ({
    host: h,
    isLocalhost: h === "localhost" || h === "127.0.0.1" || h === "::1",
    isWorkersDev: h.endsWith(".workers.dev"),
    ports: HTTPS_PORTS.map((p) => {
      const secret = cfg.portSecrets[p]?.secretHex || baseSecret;
      const link = `tg://webproxy?server=${encodeURIComponent(h)}${p !== 443 ? `&port=${p}` : ""}&secret=${secret}`;
      return {
        port: p,
        isDefault: p === 443,
        secret,
        link
      };
    })
  }));
  return {
    version: VERSION,
    proto,
    currentHost: host,
    ephemeralSetup: isEphemeralSetup(),
    runtimePersisted: isRuntimePersisted(),
    hasRuntimeOverride: hasRuntimeOverride(),
    baseEnvConfigured: hasBaseEnvRuntime(),
    config: {
      carrier: cfg.carrier,
      secretMode: cfg.secretDerived ? "derived" : cfg.base ? "fixed" : "none",
      maxStreams: cfg.maxStreams,
      sessionPath: cfg.sessionPath,
      wsPath: cfg.wsPath,
      decoyUrl: cfg.decoyUrl || null,
      adTagConfigured: Boolean(cfg.adTag),
      extraHosts: cfg.extraHosts,
      allowedHosts: cfg.hosts,
      dcPorts: cfg.dcPorts,
      debug: cfg.debug,
      generatorEnabled: cfg.generatorEnabled,
      acceptGenerated: cfg.acceptGenerated
    },
    hostConfigs,
    stats: {
      sessions: STATS.sessions,
      sessionsActive: STATS.sessionsActive,
      streams: STATS.streams,
      dcAttempts: STATS.dcAttempts,
      dcFails: STATS.dcFails,
      dcEmptyCloses: STATS.dcEmptyCloses,
      dcSuccess: Math.max(0, STATS.dcAttempts - STATS.dcFails),
      bytesUp: STATS.bytesUp,
      bytesDown: STATS.bytesDown,
      bytesUpFormatted: fmtBytes(STATS.bytesUp),
      bytesDownFormatted: fmtBytes(STATS.bytesDown),
      wsRejects: STATS.wsRejects,
      panelViews: STATS.panelViews,
      statusViews: STATS.statusViews,
      uptimeMs: Date.now() - PROCESS_START,
      uptimeFormatted: fmtDuration(Date.now() - PROCESS_START)
    },
    logs: LOG.slice(-60).reverse()
  };
}
function createProxyRouter(options) {
  const router = express.Router();
  router.use((req, res, next) => {
    const cfg = getRuntime();
    const sessionPath = cfg?.sessionPath || "/api/v1/session";
    if (req.path === sessionPath || req.path === "/api/v1/session") {
      express.raw({ type: "*/*", limit: "4kb" })(req, res, next);
      return;
    }
    next();
  });
  router.get("/api/setup/status", (req, res) => {
    const cfg = getRuntime();
    if (cfg) {
      sendNotFound(res);
      return;
    }
    const host = requestHost(req);
    const proto = requestProto(req);
    const currentKey = typeof process.env.ADMIN_KEY === "string" ? process.env.ADMIN_KEY.trim() : "";
    const suggestedKey = b64uEncode(randomBytes4(18)).replace(/[-_]/g, "x");
    res.status(200).setHeader("Cache-Control", "no-store").json({
      configured: false,
      host,
      proto,
      adminKeyTooShort: currentKey.length > 0 && currentKey.length < 16,
      suggestedKey,
      version: VERSION
    });
  });
  router.post("/api/setup/activate", express.json({ limit: "8kb" }), (req, res) => {
    const cfg = getRuntime();
    if (cfg) {
      sendNotFound(res);
      return;
    }
    const body = req.body || {};
    const adminKey = typeof body.adminKey === "string" ? body.adminKey.trim() : "";
    if (adminKey.length < 16 || !/^[A-Za-z0-9_-]+$/.test(adminKey)) {
      res.status(400).json({
        error: "ADMIN_KEY must be at least 16 characters (letters, digits, - or _)."
      });
      return;
    }
    const override = {
      ADMIN_KEY: adminKey
    };
    if (typeof body.secret === "string" && body.secret.trim()) {
      override.SECRET = body.secret.trim();
    }
    if (body.carrier === "websocket" || body.carrier === "websocket-lanes") {
      override.CARRIER = body.carrier;
    }
    if (typeof body.decoyUrl === "string" && body.decoyUrl.trim()) {
      override.DECOY_URL = body.decoyUrl.trim();
    }
    if (typeof body.extraHosts === "string" && body.extraHosts.trim()) {
      override.EXTRA_HOSTS = body.extraHosts.trim();
    }
    saveRuntimeOverride(override);
    const nextCfg = getRuntime();
    if (!nextCfg) {
      resetRuntimeOverride();
      res.status(400).json({ error: "Failed to initialize runtime with supplied configuration." });
      return;
    }
    res.status(200).setHeader("Cache-Control", "no-store").json({
      ok: true,
      panelPath: "/" + encodeURIComponent(adminKey),
      statusPath: "/" + encodeURIComponent(adminKey) + "/status"
    });
  });
  router.all("*", async (req, res, next) => {
    try {
      const cfg = getRuntime();
      const host = requestHost(req);
      const port = requestPort(req);
      const proto = requestProto(req);
      const urlObj = new URL(req.originalUrl, `${proto}://${host || "localhost"}`);
      const pathname = urlObj.pathname;
      if (pathname.startsWith("/src/") || pathname.startsWith("/assets/") || pathname.startsWith("/@vite") || pathname.startsWith("/@react-refresh") || pathname.startsWith("/node_modules/") || pathname.startsWith("/@id/") || pathname.startsWith("/@fs/")) {
        next();
        return;
      }
      if (!cfg) {
        if (pathname === "/" && (req.method === "GET" || req.method === "HEAD")) {
          res.setHeader("Cache-Control", "no-store");
          res.setHeader("X-Robots-Tag", "noindex, nofollow");
          await options.serveSpa(req, res);
          return;
        }
        sendNotFound(res);
        return;
      }
      if (!cfg.adminKey && pathname === "/setup" && (req.method === "GET" || req.method === "HEAD")) {
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("X-Robots-Tag", "noindex, nofollow");
        await options.serveSpa(req, res);
        return;
      }
      const route = panelRoute(pathname, urlObj.searchParams, cfg);
      if (route === "api-state" && req.method === "GET") {
        res.status(200).setHeader("Cache-Control", "no-store").json(buildPanelStatePayload(cfg, host, proto));
        return;
      }
      if (route === "api-probe" && (req.method === "POST" || req.method === "GET")) {
        const results = await probeDcs(cfg);
        res.status(200).setHeader("Content-Type", "application/json; charset=utf-8").setHeader("Cache-Control", "no-store").json({ results });
        return;
      }
      if (route === "api-config" && req.method === "POST") {
        await new Promise((resolve) => {
          express.json({ limit: "16kb" })(req, res, () => resolve());
        });
        const body = req.body && typeof req.body === "object" ? req.body : {};
        if (body.action === "reset") {
          if (!hasBaseEnvRuntime()) {
            res.status(400).json({ error: "Cannot reset: .env / environment has no base ADMIN_KEY or SECRET." });
            return;
          }
          resetRuntimeOverride();
          const nextCfg2 = getRuntime();
          if (!nextCfg2) {
            res.status(400).json({ error: "Failed to reload base environment configuration." });
            return;
          }
          logEvent("config_reset", "reverted to .env defaults");
          const basePath2 = "/" + encodeURIComponent(nextCfg2.adminKey);
          res.status(200).setHeader("Cache-Control", "no-store").json({
            ok: true,
            adminKeyChanged: nextCfg2.adminKey !== cfg.adminKey,
            panelPath: basePath2,
            statusPath: basePath2 + "/status",
            configPath: basePath2 + "/config",
            state: buildPanelStatePayload(nextCfg2, host, proto)
          });
          return;
        }
        const built = buildOverrideFromConfigInput(body, cfg);
        if (!built.ok) {
          res.status(400).json({ error: built.error });
          return;
        }
        saveRuntimeOverride(built.override);
        const nextCfg = getRuntime();
        if (!nextCfg) {
          res.status(400).json({ error: "Failed to apply configuration update." });
          return;
        }
        logEvent(
          "config_update",
          `carrier=${nextCfg.carrier} maxStreams=${nextCfg.maxStreams} extra=${nextCfg.extraHosts.join(",") || "-"}`
        );
        const basePath = "/" + encodeURIComponent(nextCfg.adminKey);
        res.status(200).setHeader("Cache-Control", "no-store").json({
          ok: true,
          adminKeyChanged: nextCfg.adminKey !== cfg.adminKey,
          panelPath: basePath,
          statusPath: basePath + "/status",
          configPath: basePath + "/config",
          state: buildPanelStatePayload(nextCfg, host, proto)
        });
        return;
      }
      if ((route === "panel" || route === "status" || route === "config") && req.method === "GET") {
        if (route === "panel") STATS.panelViews++;
        if (route === "status") STATS.statusViews++;
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("X-Robots-Tag", "noindex, nofollow");
        res.setHeader("Referrer-Policy", "no-referrer");
        res.setHeader("X-Content-Type-Options", "nosniff");
        await options.serveSpa(req, res);
        return;
      }
      const label = generatorLabel(urlObj.searchParams);
      if (label !== null) {
        if (!cfg.generatorEnabled || !cfg.adminKey || !label || !safeEqual(urlObj.searchParams.get("key") || "", cfg.adminKey)) {
          await sendDecoy(req, res, cfg.decoyUrl);
          return;
        }
        sendSecretText(res, cfg, host, label, port);
        return;
      }
      if (pathname === "/robots.txt" && (req.method === "GET" || req.method === "HEAD")) {
        res.status(200).setHeader("Content-Type", "text/plain; charset=utf-8").setHeader("Cache-Control", "public, max-age=86400");
        if (req.method === "HEAD") {
          res.end();
          return;
        }
        res.send("User-agent: *\nAllow: /\nDisallow: /api/\n");
        return;
      }
      if (pathname === "/favicon.ico" && (req.method === "GET" || req.method === "HEAD")) {
        const svgIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#1a1a1a"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" font-family="system-ui,sans-serif" font-weight="800" font-size="14" fill="#fff" letter-spacing="2">LV</text></svg>`;
        res.status(200).setHeader("Content-Type", "image/svg+xml").setHeader("Cache-Control", "public, max-age=86400").setHeader("X-Content-Type-Options", "nosniff");
        if (req.method === "HEAD") {
          res.end();
          return;
        }
        res.send(svgIcon);
        return;
      }
      if ((pathname === "/health" || pathname === "/status") && (req.method === "GET" || req.method === "HEAD")) {
        const payload = JSON.stringify({
          status: "operational",
          store: "LUXVEIL",
          region: "global",
          uptime: "99.99%",
          timestamp: Math.floor(Date.now() / 1e3)
        });
        res.status(200).setHeader("Content-Type", "application/json; charset=utf-8").setHeader("Cache-Control", "no-cache");
        if (req.method === "HEAD") {
          res.end();
          return;
        }
        res.send(payload);
        return;
      }
      if (!hostAllowed(cfg, host)) {
        if (urlObj.searchParams.has("bridge") || pathname === cfg.sessionPath || pathname === "/api/v1/session") {
          logEvent("host_reject", `host=${host} allowed=${cfg.hosts.join(",") || "*"}`);
        }
        await sendDecoy(req, res, cfg.decoyUrl);
        return;
      }
      if (pathname === "/" && (req.method === "GET" || req.method === "HEAD")) {
        const rawBridge = urlObj.searchParams.getAll("bridge");
        if (rawBridge.length === 0) {
          await sendDecoy(req, res, cfg.decoyUrl);
          return;
        }
        const keys = Array.from(urlObj.searchParams.keys());
        if (keys.length !== 1 || keys[0] !== "bridge" || rawBridge.length !== 1) {
          logEvent("bridge_reject", `host=${host} reason=extra_params`);
          sendNotFound(res);
          return;
        }
        const headerHosts = [
          typeof req.headers.host === "string" ? req.headers.host : "",
          typeof req.headers["x-original-host"] === "string" ? req.headers["x-original-host"] : ""
        ].filter(Boolean);
        const mode = bridgeMode(cfg, host, rawBridge[0], port, headerHosts);
        if (mode < 0) {
          logEvent("bridge_reject", `host=${host} port=${port || "443"} reason=secret_mismatch`);
          sendNotFound(res);
          return;
        }
        logEvent("bridge_ok", `host=${host} port=${port || "443"} mode=${mode}`);
        serveBridge(req, res, cfg, host, proto, mode, port);
        return;
      }
      if (pathname === cfg.sessionPath || pathname === "/api/v1/session") {
        await handleSession(req, res, cfg);
        return;
      }
      await sendDecoy(req, res, cfg.decoyUrl);
    } catch (err) {
      next(err);
    }
  });
  return router;
}

// server.ts
var isDevCommand = Boolean(process.env.npm_lifecycle_event?.includes("dev")) || process.execArgv.some((arg) => arg.includes("tsx")) || Boolean(process.env._?.includes("tsx"));
var PORT = parseInt(process.env.PROXY_PORT || "", 10) || (isDevCommand ? 3e3 : parseInt(process.env.PORT || "3000", 10) || 3e3);
var HOST = process.env.HOST || "0.0.0.0";
async function bootstrapServer() {
  const app = express2();
  app.disable("x-powered-by");
  app.set("trust proxy", true);
  const rootDir = process.cwd();
  const distDir = path2.resolve(rootDir, "dist");
  const distIndexPath = path2.join(distDir, "index.html");
  const isProd = process.env.NODE_ENV === "production" || !isDevCommand && fs2.existsSync(distIndexPath);
  let vite = null;
  if (!isProd) {
    const { createServer: createViteServer } = await import("vite");
    vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "custom"
    });
  }
  const serveSpa = async (req, res) => {
    if (!isProd && vite) {
      const templatePath = path2.resolve(rootDir, "index.html");
      const rawHtml = fs2.readFileSync(templatePath, "utf8");
      const transformed = await vite.transformIndexHtml(req.originalUrl, rawHtml);
      res.status(200).setHeader("Content-Type", "text/html; charset=utf-8").send(transformed);
      return;
    }
    if (fs2.existsSync(distIndexPath)) {
      res.status(200).setHeader("Content-Type", "text/html; charset=utf-8").sendFile(distIndexPath);
      return;
    }
    res.status(500).setHeader("Content-Type", "text/plain; charset=utf-8").send("\u672A\u627E\u5230\u524D\u7AEF\u6784\u5EFA\u4EA7\u7269\uFF0C\u8BF7\u5148\u6267\u884C npm run build\u3002");
  };
  app.use(createProxyRouter({ serveSpa }));
  if (!isProd && vite) {
    app.use(vite.middlewares);
  } else if (fs2.existsSync(distDir)) {
    app.use(
      express2.static(distDir, {
        index: false,
        maxAge: "7d"
      })
    );
  }
  app.use(async (err, req, res, _next) => {
    reportError(`http ${req.method} ${req.path}`, err);
    if (res.headersSent) return;
    try {
      await sendDecoy(req, res, (process.env.DECOY_URL || "").trim());
    } catch {
      res.status(200).send("");
    }
  });
  const httpServer = http.createServer(app);
  httpServer.keepAliveTimeout = 65e3;
  httpServer.headersTimeout = 66e3;
  attachWebSocketServer(httpServer, () => getRuntime());
  httpServer.listen(PORT, HOST, () => {
    const cfg = getRuntime();
    console.log(`[proxygosha-node] Express + WS \u670D\u52A1\u5DF2\u542F\u52A8\uFF0C\u76D1\u542C http://${HOST}:${PORT}`);
    console.log(
      `[proxygosha-node] \u5F53\u524D\u72B6\u6001: ${cfg ? `\u5DF2\u914D\u7F6E (carrier=${cfg.carrier}, maxStreams=${cfg.maxStreams})` : "\u672A\u914D\u7F6E\uFF08\u8BF7\u8BBF\u95EE / \u5B8C\u6210\u521D\u59CB\u5316\uFF09"}`
    );
  });
  const shutdown = () => {
    httpServer.close(() => {
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 3e3).unref();
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}
bootstrapServer().catch((err) => {
  console.error("[proxygosha-node] Fatal startup error:", err);
  process.exit(1);
});
