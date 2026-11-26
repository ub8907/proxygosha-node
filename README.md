# ProxyGosha Node.js (Express + WebSocket + VLESS)

[中文文档 / Chinese Guide](./README.zh.md)

Pure **Node.js + Express + WebSocket (`ws`)** server running **MTProto WebProxy** (with a unified `SECRET` across all ports) and **V2Ray / v2rayN VLESS** (`VLESS-over-WS` + `VLESS-over-HTTP`) on a single unified port, complete with live WebSocket connectivity diagnostics and Telegram DC1–DC5 probing.

## Quick Start

```bash
npm install
cp .env.example .env
npm run build
npm run prod
```

- Development mode (Express + WebSocket + live esbuild/Tailwind on port 3000): `npm run dev`
- Docker Compose:
  ```bash
  cp .env.example .env
  docker compose up -d --build
  ```
- Nginx reverse proxy example: see `docs/nginx.example.conf` (proxy HTTP + WebSocket to `http://127.0.0.1:3000`).
