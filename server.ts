import "dotenv/config";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import express, { type NextFunction, type Request, type Response } from "express";
import { getRuntime, getVlessRuntime } from "./src/proxy/config.ts";
import { attachWebSocketServer } from "./src/proxy/engine.ts";
import { createProxyRouter } from "./src/proxy/router.ts";
import { sendDecoy } from "./src/proxy/templates.ts";
import { reportError } from "./src/proxy/telemetry.ts";
import { createVlessHttpMiddleware } from "./src/proxy/vless.ts";

const isDevCommand =
  Boolean(process.env.npm_lifecycle_event?.includes("dev")) ||
  process.execArgv.some((arg) => arg.includes("tsx")) ||
  Boolean(process.env._?.includes("tsx"));

const PORT =
  parseInt(process.env.PROXY_PORT || "", 10) ||
  (isDevCommand ? 3000 : parseInt(process.env.PORT || "3000", 10) || 3000);
const HOST = process.env.HOST || "0.0.0.0";

function hashFile(filePath: string): string {
  return createHash("sha256").update(fs.readFileSync(filePath)).digest("hex").slice(0, 10);
}

// 开发模式前端即时编译器（使用 esbuild + Tailwind CLI，不依赖 Vite）
async function buildDevClient(rootDir: string, clientOutDir: string): Promise<void> {
  const esbuild = await import("esbuild");
  const assetsDir = path.join(clientOutDir, "assets");
  fs.mkdirSync(assetsDir, { recursive: true });

  const jsOutFile = path.join(assetsDir, "app.js");
  await esbuild.build({
    entryPoints: [path.resolve(rootDir, "src", "main.tsx")],
    bundle: true,
    format: "esm",
    platform: "browser",
    target: ["es2022"],
    jsx: "automatic",
    sourcemap: "inline",
    outfile: jsOutFile,
    alias: {
      "@": rootDir,
    },
    define: {
      "process.env.NODE_ENV": '"development"',
    },
  });

  const cssInFile = path.resolve(rootDir, "src", "index.css");
  const cssOutFile = path.join(assetsDir, "app.css");
  const tailwindBin = path.resolve(rootDir, "node_modules", "@tailwindcss", "cli", "dist", "index.mjs");
  execFileSync(process.execPath, [tailwindBin, "-i", cssInFile, "-o", cssOutFile], {
    cwd: rootDir,
    stdio: "inherit",
  });

  const jsHash = hashFile(jsOutFile);
  const cssHash = hashFile(cssOutFile);
  const rawHtml = fs.readFileSync(path.resolve(rootDir, "index.html"), "utf8");
  const devHtml = rawHtml.replace(
    /<script\s+type="module"\s+src="\/src\/main\.tsx"><\/script>/,
    `<link rel="stylesheet" href="/assets/app.css?v=${cssHash}" />\n    <script type="module" src="/assets/app.js?v=${jsHash}"></script>`
  );
  fs.writeFileSync(path.join(clientOutDir, "index.html"), devHtml, "utf8");
}

async function bootstrapServer() {
  const app = express();
  app.disable("x-powered-by");
  // 信任反向代理透传头（X-Forwarded-Host、X-Forwarded-Proto、CF-Connecting-IP）
  app.set("trust proxy", true);

  const rootDir = process.cwd();
  const distDir = path.resolve(rootDir, "dist-client");
  const distIndexPath = path.join(distDir, "index.html");
  const isProd =
    process.env.NODE_ENV === "production" ||
    (!isDevCommand && fs.existsSync(distIndexPath));

  if (!isProd) {
    await buildDevClient(rootDir, distDir);

    // 监听前端源码变更并自动重新编译
    let rebuildTimer: ReturnType<typeof setTimeout> | null = null;
    const scheduleRebuild = () => {
      if (rebuildTimer) clearTimeout(rebuildTimer);
      rebuildTimer = setTimeout(() => {
        buildDevClient(rootDir, distDir).catch((err) => {
          console.error("[proxygosha-node] 开发前端编译失败:", err);
        });
      }, 150);
    };
    for (const watchTarget of [path.resolve(rootDir, "src"), path.resolve(rootDir, "index.html")]) {
      if (fs.existsSync(watchTarget)) {
        fs.watch(watchTarget, { recursive: true }, scheduleRebuild);
      }
    }
  }

  // 渲染前端 SPA 页面（开发/生产统一返回 dist-client/index.html）
  const serveSpa = async (_req: Request, res: Response): Promise<void> => {
    if (fs.existsSync(distIndexPath)) {
      res.status(200).setHeader("Content-Type", "text/html; charset=utf-8").sendFile(distIndexPath);
      return;
    }

    res.status(500).setHeader("Content-Type", "text/plain; charset=utf-8").send("未找到前端构建产物，请先执行 npm run build。");
  };

  let actualPort = PORT;

  // 在 MTProto 路由之前优先处理 VLESS-over-HTTP 请求（匹配 VLESS_PATH + content-type: application/vless 时接管）
  app.use(createVlessHttpMiddleware(() => getVlessRuntime()));

  // 在静态资源中间件之前挂载 ProxyGosha 核心代理路由
  app.use(createProxyRouter({ serveSpa, getListeningPort: () => actualPort }));

  if (fs.existsSync(distDir)) {
    app.use(
      express.static(distDir, {
        index: false,
        maxAge: isProd ? "7d" : 0,
      })
    );
  }

  // 兜底异常处理（始终降级返回伪装页面，避免暴露内部错误）
  app.use(async (err: unknown, req: Request, res: Response, _next: NextFunction) => {
    reportError(`http ${req.method} ${req.path}`, err);
    if (res.headersSent) return;
    try {
      await sendDecoy(req, res, (process.env.DECOY_URL || "").trim());
    } catch {
      res.status(200).send("");
    }
  });

  const httpServer = http.createServer(app);
  // 优化 HTTP/1.1 长连接保活超时
  httpServer.keepAliveTimeout = 65000;
  httpServer.headersTimeout = 66000;

  // 在同一 HTTP 服务器（统一端口）挂载原生 WebSocket 代理引擎（含 MTProto、VLESS 与 WS 连通测试）
  attachWebSocketServer(httpServer, () => getRuntime(), () => getVlessRuntime());

  httpServer.listen(PORT, HOST, () => {
    const addr = httpServer.address();
    if (addr && typeof addr === "object") {
      actualPort = addr.port;
    }
    const cfg = getRuntime();
    const vlessCfg = getVlessRuntime();
    console.log(`[proxygosha-node] Express + WS 服务已启动，监听 http://${HOST}:${actualPort}`);
    console.log(
      `[proxygosha-node] 当前状态: ${cfg ? `已配置 (carrier=${cfg.carrier}, maxStreams=${cfg.maxStreams})` : "未配置（请访问 / 完成初始化）"} | VLESS=${vlessCfg.enabled ? vlessCfg.path : "disabled"}`
    );
  });

  const shutdown = () => {
    httpServer.close(() => {
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 3000).unref();
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

bootstrapServer().catch((err) => {
  console.error("[proxygosha-node] Fatal startup error:", err);
  process.exit(1);
});
