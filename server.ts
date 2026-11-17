import "dotenv/config";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import express, { type NextFunction, type Request, type Response } from "express";
import { getRuntime } from "./src/proxy/config.ts";
import { attachWebSocketServer } from "./src/proxy/engine.ts";
import { createProxyRouter } from "./src/proxy/router.ts";
import { sendDecoy } from "./src/proxy/templates.ts";
import { reportError } from "./src/proxy/telemetry.ts";
import { startTunnelIfConfigured, stopTunnel } from "./src/proxy/tunnel.ts";

const isDevCommand =
  Boolean(process.env.npm_lifecycle_event?.includes("dev")) ||
  process.execArgv.some((arg) => arg.includes("tsx")) ||
  Boolean(process.env._?.includes("tsx"));

const PORT =
  parseInt(process.env.PROXY_PORT || "", 10) ||
  (isDevCommand ? 3000 : parseInt(process.env.PORT || "3000", 10) || 3000);
const HOST = process.env.HOST || "0.0.0.0";

async function bootstrapServer() {
  const app = express();
  app.disable("x-powered-by");
  // 信任 Cloudflare Tunnel / 反向代理透传头（X-Forwarded-Host、X-Forwarded-Proto、CF-Connecting-IP）
  app.set("trust proxy", true);

  const rootDir = process.cwd();
  const distDir = path.resolve(rootDir, "dist");
  const distIndexPath = path.join(distDir, "index.html");
  const isProd =
    process.env.NODE_ENV === "production" ||
    (!isDevCommand && fs.existsSync(distIndexPath));

  let vite: Awaited<ReturnType<typeof import("vite")["createServer"]>> | null = null;

  if (!isProd) {
    const { createServer: createViteServer } = await import("vite");
    vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "custom",
    });
  }

  // 渲染前端 SPA 页面（开发模式走 Vite 实时编译，生产模式直接返回 dist/index.html）
  const serveSpa = async (req: Request, res: Response): Promise<void> => {
    if (!isProd && vite) {
      const templatePath = path.resolve(rootDir, "index.html");
      const rawHtml = fs.readFileSync(templatePath, "utf8");
      const transformed = await vite.transformIndexHtml(req.originalUrl, rawHtml);
      res.status(200).setHeader("Content-Type", "text/html; charset=utf-8").send(transformed);
      return;
    }

    if (fs.existsSync(distIndexPath)) {
      res.status(200).setHeader("Content-Type", "text/html; charset=utf-8").sendFile(distIndexPath);
      return;
    }

    res.status(500).setHeader("Content-Type", "text/plain; charset=utf-8").send("未找到前端构建产物，请先执行 npm run build。");
  };

  // 在 Vite/静态资源中间件之前挂载 ProxyGosha 核心代理路由
  app.use(createProxyRouter({ serveSpa }));

  if (!isProd && vite) {
    app.use(vite.middlewares);
  } else if (fs.existsSync(distDir)) {
    app.use(
      express.static(distDir, {
        index: false,
        maxAge: "7d",
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
  // 针对 Cloudflare Tunnel 与 HTTP/1.1 长连接优化保活超时
  httpServer.keepAliveTimeout = 65000;
  httpServer.headersTimeout = 66000;

  // 在同一 HTTP 服务器（3000 端口）挂载原生 WebSocket 代理引擎
  attachWebSocketServer(httpServer, () => getRuntime());

  httpServer.listen(PORT, HOST, () => {
    const cfg = getRuntime();
    console.log(`[proxygosha-node] Express + WS 服务已启动，监听 http://${HOST}:${PORT}`);
    console.log(
      `[proxygosha-node] 当前状态: ${cfg ? `已配置 (carrier=${cfg.carrier}, maxStreams=${cfg.maxStreams})` : "未配置（请访问 / 完成初始化）"}`
    );
    startTunnelIfConfigured(PORT);
  });

  const shutdown = () => {
    stopTunnel();
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
