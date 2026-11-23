import { randomBytes } from "node:crypto";
import express, { type Request, type Response, type Router } from "express";
import {
  HTTPS_PORTS,
  TOKEN_KIND_BOOTSTRAP,
  TOKEN_KIND_SESSION,
  VERSION,
  WELCOME,
} from "./constants.ts";
import {
  b64uEncode,
  bytesToHex,
  safeEqual,
} from "./crypto.ts";
import {
  bridgeMode,
  buildOverrideFromConfigInput,
  deriveSecret,
  generatorLabel,
  getRuntime,
  hasBaseEnvRuntime,
  hasRuntimeOverride,
  hostAllowed,
  isEphemeralSetup,
  isRuntimePersisted,
  issueToken,
  panelRoute,
  requestHost,
  requestPort,
  requestProto,
  resetRuntimeOverride,
  saveRuntimeOverride,
  verifyToken,
  type ProxyRuntime,
} from "./config.ts";
import { probeDcs } from "./engine.ts";
import { sendDecoy, serveBridge } from "./templates.ts";
import { fmtBytes, fmtDuration, LOG, logEvent, PROCESS_START, STATS } from "./telemetry.ts";

export interface ProxyRouterOptions {
  serveSpa: (req: Request, res: Response) => Promise<void>;
}

function sendNotFound(res: Response): void {
  res
    .status(404)
    .setHeader("Content-Type", "text/plain; charset=utf-8")
    .setHeader("Cache-Control", "no-store")
    .send("Not Found");
}

function sendSecretText(
  res: Response,
  cfg: ProxyRuntime,
  host: string,
  label: string,
  port: string
): void {
  const cleanLabel = String(label || "")
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .toLowerCase()
    .slice(0, 128);

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
    if (!hex) hex = bytesToHex(randomBytes(16));
  } else if (cfg.base) {
    hex = bytesToHex(cfg.base);
    isExisting = true;
  } else {
    hex = bytesToHex(randomBytes(16));
  }

  const portSuffix = port && port !== "443" && port !== "80" ? `&port=${port}` : "";
  const link = `tg://webproxy?server=${encodeURIComponent(host)}${portSuffix}&secret=${hex}`;
  const paddedSecret = `dd${hex}`;
  const paddedLink = `tg://webproxy?server=${encodeURIComponent(host)}${portSuffix}&secret=${paddedSecret}`;

  const lines = [
    "=== ProxyGosha Node.js Secret Generator ===",
    isCustomDomain
      ? `[Mode: DOMAIN-DERIVED SECRET for "${cleanLabel}"]`
      : isExisting
      ? "[Status: ACTIVE CONFIGURATION]"
      : "[Status: NEW SECRET GENERATED]",
    "",
    "Server:        " + host + (port && port !== "443" && port !== "80" ? ":" + port : ""),
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

  res
    .status(200)
    .setHeader("Content-Type", "text/plain; charset=utf-8")
    .setHeader("Cache-Control", "no-store")
    .setHeader("X-Robots-Tag", "noindex")
    .setHeader("Referrer-Policy", "no-referrer")
    .setHeader("X-Content-Type-Options", "nosniff")
    .send(lines.join("\n"));
}

async function handleSession(req: Request, res: Response, cfg: ProxyRuntime): Promise<void> {
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
  if (
    body[0] !== 0x10 ||
    body[1] !== 0 ||
    body[2] !== 0 ||
    body[3] !== 0 ||
    body[4] !== 0 ||
    body[5] !== 0 ||
    body[6] !== 0 ||
    body[7] !== 1 ||
    body[8] !== 1
  ) {
    logEvent("session_reject", "reason=bad_hello_magic");
    sendNotFound(res);
    return;
  }

  const sessionToken = issueToken(cfg, TOKEN_KIND_SESSION, cfg.sessionTtl, verified.mode);
  logEvent("session_ok", `carrier=${cfg.carrier} mode=${verified.mode}`);
  res
    .status(200)
    .setHeader("Content-Type", "application/octet-stream")
    .setHeader("Cache-Control", "no-store")
    .setHeader("X-Session-Token", sessionToken)
    .setHeader("X-Down-Cursor", "0")
    .setHeader("X-Carrier-Mode", cfg.carrier)
    .send(WELCOME);
}

function buildPanelStatePayload(cfg: ProxyRuntime, host: string, proto: "https" | "http") {
  const baseSecret = cfg.base ? "dd" + bytesToHex(cfg.base) : "";
  const hosts: string[] = [];
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
        link,
      };
    }),
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
      acceptGenerated: cfg.acceptGenerated,
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
      uptimeFormatted: fmtDuration(Date.now() - PROCESS_START),
    },
    logs: LOG.slice(-60).reverse(),
  };
}

export function createProxyRouter(options: ProxyRouterOptions): Router {
  const router = express.Router();

  // 针对 /api/v1/session 握手接口限制原始二进制请求体不超过 4KB，防止内存耗尽攻击
  router.use((req, res, next) => {
    const cfg = getRuntime();
    const sessionPath = cfg?.sessionPath || "/api/v1/session";
    if (req.path === sessionPath || req.path === "/api/v1/session") {
      express.raw({ type: "*/*", limit: "4kb" })(req, res, next);
      return;
    }
    next();
  });

  // 初始化状态查询接口：仅在服务尚未配置时开放
  router.get("/api/setup/status", (req, res) => {
    const cfg = getRuntime();
    if (cfg) {
      sendNotFound(res);
      return;
    }
    const host = requestHost(req);
    const proto = requestProto(req);
    const currentKey = typeof process.env.ADMIN_KEY === "string" ? process.env.ADMIN_KEY.trim() : "";
    const suggestedKey = b64uEncode(randomBytes(18)).replace(/[-_]/g, "x");
    res.status(200).setHeader("Cache-Control", "no-store").json({
      configured: false,
      host,
      proto,
      adminKeyTooShort: currentKey.length > 0 && currentKey.length < 16,
      suggestedKey,
      version: VERSION,
    });
  });

  router.post("/api/setup/activate", express.json({ limit: "8kb" }), (req, res) => {
    const cfg = getRuntime();
    if (cfg) {
      sendNotFound(res);
      return;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const adminKey = typeof body.adminKey === "string" ? body.adminKey.trim() : "";
    if (adminKey.length < 16 || !/^[A-Za-z0-9_-]+$/.test(adminKey)) {
      res.status(400).json({
        error: "ADMIN_KEY must be at least 16 characters (letters, digits, - or _).",
      });
      return;
    }

    const override: Record<string, string> = {
      ADMIN_KEY: adminKey,
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
      statusPath: "/" + encodeURIComponent(adminKey) + "/status",
    });
  });

  // ProxyGosha 核心请求分发中间件
  router.all("*", async (req: Request, res: Response, next) => {
    try {
      const cfg = getRuntime();
      const host = requestHost(req);
      const port = requestPort(req);
      const proto = requestProto(req);

      const urlObj = new URL(req.originalUrl, `${proto}://${host || "localhost"}`);
      const pathname = urlObj.pathname;

      // 放行前端静态构建资源，确保管理/初始化页面正常加载
      if (pathname.startsWith("/assets/")) {
        next();
        return;
      }

      // 1. 未配置状态：仅根路径 "/" 提供初始化配置页，其余路径一律返回 404
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

      // 2. 仅配置 SECRET 但未设置 ADMIN_KEY 时，/setup 展示初始化引导页面
      if (!cfg.adminKey && pathname === "/setup" && (req.method === "GET" || req.method === "HEAD")) {
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("X-Robots-Tag", "noindex, nofollow");
        await options.serveSpa(req, res);
        return;
      }

      // 3. 管理面板、动态配置与状态探测路由：/<ADMIN_KEY>、/<ADMIN_KEY>/status、/<ADMIN_KEY>/config、/<ADMIN_KEY>/api/*
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
        await new Promise<void>((resolve) => {
          express.json({ limit: "16kb" })(req, res, () => resolve());
        });
        const body = (req.body && typeof req.body === "object" ? req.body : {}) as Record<string, unknown>;
        if (body.action === "reset") {
          if (!hasBaseEnvRuntime()) {
            res.status(400).json({ error: "Cannot reset: .env / environment has no base ADMIN_KEY or SECRET." });
            return;
          }
          resetRuntimeOverride();
          const nextCfg = getRuntime();
          if (!nextCfg) {
            res.status(400).json({ error: "Failed to reload base environment configuration." });
            return;
          }
          logEvent("config_reset", "reverted to .env defaults");
          const basePath = "/" + encodeURIComponent(nextCfg.adminKey);
          res.status(200).setHeader("Cache-Control", "no-store").json({
            ok: true,
            adminKeyChanged: nextCfg.adminKey !== cfg.adminKey,
            panelPath: basePath,
            statusPath: basePath + "/status",
            configPath: basePath + "/config",
            state: buildPanelStatePayload(nextCfg, host, proto),
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
          state: buildPanelStatePayload(nextCfg, host, proto),
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

      // 4. 兼容旧版按域名派生 Secret 接口（需开启 GENERATOR_ENABLED 且校验 ADMIN_KEY）
      const label = generatorLabel(urlObj.searchParams);
      if (label !== null) {
        if (
          !cfg.generatorEnabled ||
          !cfg.adminKey ||
          !label ||
          !safeEqual(urlObj.searchParams.get("key") || "", cfg.adminKey)
        ) {
          await sendDecoy(req, res, cfg.decoyUrl);
          return;
        }
        sendSecretText(res, cfg, host, label, port);
        return;
      }

      // 5. 主动探测防御与真实站点静态资产（应对 GFW / TSPU 扫描探测）
      if (pathname === "/robots.txt" && (req.method === "GET" || req.method === "HEAD")) {
        res
          .status(200)
          .setHeader("Content-Type", "text/plain; charset=utf-8")
          .setHeader("Cache-Control", "public, max-age=86400");
        if (req.method === "HEAD") {
          res.end();
          return;
        }
        res.send("User-agent: *\nAllow: /\nDisallow: /api/\n");
        return;
      }

      if (pathname === "/favicon.ico" && (req.method === "GET" || req.method === "HEAD")) {
        const svgIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#1a1a1a"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" font-family="system-ui,sans-serif" font-weight="800" font-size="14" fill="#fff" letter-spacing="2">LV</text></svg>`;
        res
          .status(200)
          .setHeader("Content-Type", "image/svg+xml")
          .setHeader("Cache-Control", "public, max-age=86400")
          .setHeader("X-Content-Type-Options", "nosniff");
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
          timestamp: Math.floor(Date.now() / 1000),
        });
        res
          .status(200)
          .setHeader("Content-Type", "application/json; charset=utf-8")
          .setHeader("Cache-Control", "no-cache");
        if (req.method === "HEAD") {
          res.end();
          return;
        }
        res.send(payload);
        return;
      }

      // 6. 域名白名单校验（未命中则直接返回伪装站）
      if (!hostAllowed(cfg, host)) {
        if (urlObj.searchParams.has("bridge") || pathname === cfg.sessionPath || pathname === "/api/v1/session") {
          logEvent("host_reject", `host=${host} allowed=${cfg.hosts.join(",") || "*"}`);
        }
        await sendDecoy(req, res, cfg.decoyUrl);
        return;
      }

      // 7. Telegram WebProxy 网桥入口：GET /?bridge=<capability>
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
          typeof req.headers["x-original-host"] === "string" ? req.headers["x-original-host"] : "",
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

      // 8. 会话握手与关闭路由
      if (pathname === cfg.sessionPath || pathname === "/api/v1/session") {
        await handleSession(req, res, cfg);
        return;
      }

      // 9. 其余未知路径统一返回伪装页面
      await sendDecoy(req, res, cfg.decoyUrl);
    } catch (err) {
      next(err);
    }
  });

  return router;
}
