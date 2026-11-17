# ProxyGosha PHP (Nginx + index.php + Workerman)

[中文文档 / Chinese Guide](./README.zh.md)

Pure **PHP 8.1+** MTProto WebProxy designed as a standard **Nginx + PHP-FPM (`public/index.php`)** website backed by a **Workerman** asynchronous WebSocket & Direct-DC TCP engine (`Fast Mode` zero re-encryption downlink) with native **Cloudflare Tunnel (`cloudflared`)** support — **zero Node.js runtime required**.

## Deployment Options

1. **Docker Compose (Nginx + PHP-FPM `index.php` + Workerman WS + cloudflared):**
   ```bash
   cp .env.example .env
   docker compose up -d --build
   ```

2. **Standard Nginx / BT Panel / LNMP Website:**
   - Install PHP dependencies: `composer install --no-dev`
   - Point Nginx document root to `public/` (`index index.php; try_files $uri $uri/ /index.php?$query_string;`) and proxy `/api/v1/ws` to `http://127.0.0.1:3001` (see `nginx.conf`).
   - Run the background Workerman WebSocket engine automatically via systemd (`deploy/proxygosha-ws.service`) or Supervisor (`deploy/supervisor-proxygosha.conf`).
