# ProxyGosha Node.js (Express + WebSocket)

[中文文档 / Chinese Guide](./README.zh.md)

Pure **Node.js + Express + WebSocket (`ws`)** MTProto WebProxy (`Fast Mode` zero re-encryption downlink) with a built-in React management console, dynamic runtime settings (`storage/runtime.json`), and live Telegram DC1–DC5 MTProto probing.

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
