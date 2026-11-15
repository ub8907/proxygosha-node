# ProxyGosha Node.js (Express Refactor)

[中文文档 / Chinese Guide](./README.zh.md)

Pure Node.js + Express refactor of [ProxyGosha](https://github.com/amirmarandidev/ProxyGosha) with native OpenSSL AES-256-CTR encryption, `ws` WebSocket transport, `node:net` direct-DC TCP pooling/failover, and first-class **Cloudflare Tunnel (`cloudflared`)** support.

## Architecture & Performance

- **Express HTTP Router** (`src/proxy/router.ts`): Handles `GET /?bridge=...` Telegram WebProxy bridge injection, `POST/DELETE /api/v1/session` handshake, anti-probing camouflage (`LUXVEIL` storefront or `DECOY_URL`), `/robots.txt`, `/favicon.ico`, `/health`, and admin routes (`/<ADMIN_KEY>`, `/<ADMIN_KEY>/status`).
- **Native WebSocket + TCP Engine** (`src/proxy/engine.ts`):
  - Uses `ws` (`perMessageDeflate: false`, zero-copy binary frames) supporting both `websocket-lanes` (one WebSocket per MTProto stream) and `websocket` (multiplexed streams with 25s heartbeat & 90s watchdog).
  - Uses persistent Node `node:crypto` OpenSSL `aes-256-ctr` stream ciphers (`ObfuscatedCtrStream`) for uplink and **Fast Mode** (zero re-encryption) for downlink.
  - Uses `node:net` TCP sockets (`setNoDelay(true)`, `setKeepAlive(true, 30000)`) with credit-windowed `pause()`/`resume()` backpressure and randomized Telegram DC failover.
- **Cloudflare Tunnel Ready** (`src/proxy/tunnel.ts`):
  - `app.set('trust proxy', true)` + `X-Forwarded-Host` / `X-Forwarded-Proto` / `CF-Visitor` / `CF-Ray` awareness.
  - Automatically adapts `wss://` vs `ws://` and generates `tg://webproxy` links for all 6 Cloudflare HTTPS ports (`443, 2053, 2083, 2087, 2096, 8443`).
  - Supports external `cloudflared` CLI, Docker Compose sidecar, or `CF_TUNNEL_AUTOSTART=true` with `CF_TUNNEL_TOKEN`.

## Quick Start

1. Install dependencies & configure `.env`:
   ```bash
   npm install
   cp .env.example .env
   # Set ADMIN_KEY (16+ chars) in .env, or configure interactively via / when starting unconfigured
   ```

2. Run in development or production:
   ```bash
   # Development (Express + Vite)
   npm run dev

   # Production build & start
   npm run build
   npm start
   ```

3. Connect via Cloudflare Tunnel:
   - **Quick Tunnel (instant test):**
     ```bash
     cloudflared tunnel --url http://127.0.0.1:3000
     ```
   - **Named Tunnel (custom domain in Cloudflare Zero Trust → Tunnels → Public Hostname → `http://127.0.0.1:3000`):**
     ```bash
     cloudflared tunnel run --token <CF_TUNNEL_TOKEN>
     ```
   - **Docker Compose (Node.js + cloudflared sidecar):**
     ```bash
     docker compose up -d --build
     ```
