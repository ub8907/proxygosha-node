# ProxyGosha Node.js (Express + WebSocket) 中文部署指南

本项目基于 **Node.js + TypeScript + Express + ws** 实现，单端口统一承载 HTTP 管理控制台、WebProxy 网桥、Session 握手、WebSocket 代理长连接与 Telegram DC1–DC5 异步直连转发（Fast Mode 下行零重加密直通）。

---

## 一、快速启动（本地 / VPS）

```bash
npm install
cp .env.example .env
npm run build
npm run prod
```

- **开发模式**（自动编译前端 + 监听 `3000` 端口）：
  ```bash
  npm run dev
  ```
- **生产模式**（运行编译后的 `dist-client/` 与 `dist-server/server.mjs`）：
  ```bash
  npm run build
  npm run prod
  ```

> 也可直接使用 `docker compose up -d --build` 一键启动容器版服务。

---

## 二、PaaS / Railpack 平台部署（Cloudzyro / Railway 等）

项目已完全移除 Vite，采用纯 **Node.js + Express + WebSocket** 架构（前端由 `esbuild` + `@tailwindcss/cli` 编译至 `dist-client/`）。根目录内置 `railpack.json`，部署平台在构建时会自动执行 `npm ci` 与 `npm run build`，并使用 `node dist-server/server.mjs` 启动完整后端服务。

1. **上传或推送代码**：确保包含 `package.json`、`package-lock.json`、`railpack.json`、`scripts/build.mjs`、`server.ts`、`index.html` 与 `src/`（请勿在根目录放置 `nginx.conf`，也无需上传 `node_modules/`、`dist-client/`、`dist-server/`、`.env`、`storage/` 与 `bun.lock`）。
2. **环境变量配置（推荐）**：
   - 在平台控制台的环境变量（Variables / Env）中添加 `ADMIN_KEY`（至少 16 位英文、数字、`-` 或 `_`），可选设置 `SECRET`、`ALLOWED_HOSTS="*"`、`EXTRA_HOSTS` 等。
   - 若平台文件系统重启不保留本地文件，**强烈建议将 `ADMIN_KEY` 写入平台环境变量**，避免容器重启后临时配置丢失。
3. **启动后访问**：
   - 未设环境变量时，访问 `https://你的域名/` 会进入初始化页面完成激活；
   - 已设 `ADMIN_KEY` 时，直接访问 `https://你的域名/<ADMIN_KEY>` 查看代理链接，`/<ADMIN_KEY>/status` 查看状态与执行 DC 探测，`/<ADMIN_KEY>/config` 在线调整配置。

---

## 三、Nginx 反向代理参考（VPS 自建域名）

若前置使用 Nginx 绑定域名与 HTTPS 证书，直接将全站与 WebSocket 升级请求反代至 `http://127.0.0.1:3000`（详见 `docs/nginx.example.conf`）：

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 86400s;
    proxy_buffering off;
}
```
