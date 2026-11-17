# ProxyGosha PHP (Nginx + index.php + Workerman) 中文部署指南

本项目采用**纯 PHP** 实现（**零 Node.js 运行时依赖**），支持直接作为 **Nginx + PHP-FPM (`public/index.php`) 标准网站** 默认启动，并搭配 **Workerman** 异步引擎承载 `/api/v1/ws` WebSocket 长连接与 Telegram DC1–DC5 直连转发。

---

## 一、核心架构说明

- **Nginx + `public/index.php`（PHP-FPM 默认网站入口）**：
  - 站点默认打开即由 `public/index.php`（或根目录 `index.php`）响应：初始化向导 `/`、管理面板 `/<ADMIN_KEY>`、状态探测 `/<ADMIN_KEY>/status`、WebProxy 网桥 `/?bridge=...`、会话握手 `/api/v1/session`、健康检查 `/health` 与内置 LUXVEIL 伪装商城。
  - `/assets/*` 静态文件直接由 Nginx 高效输出。
- **Workerman WebSocket 后台引擎（`127.0.0.1:3001`）**：
  - 由于 PHP-FPM 本身不支持持久 WebSocket 长连接与长驻异步 TCP，Nginx 只需将 `/api/v1/ws` 一条路由反代给后台托管的 Workerman 引擎（通过 systemd / Supervisor / Docker 自动随网站拉起，**无需每次手动执行 `php start.php start`**）。
  - 网页初始化激活的配置会自动保存在 `storage/runtime.json`，PHP-FPM 与 Workerman 实时共享生效。

---

## 二、部署方式 A：Nginx + PHP-FPM 标准网站部署（宝塔 / LNMP / 1Panel / 原生 Nginx）

### 1. 安装 PHP 依赖与环境
要求 **PHP >= 8.1**，启用 `openssl`、`json`、`sockets` 扩展，安装 Composer 依赖：
```bash
composer install --no-dev
cp .env.example .env
```

### 2. 配置 Nginx 网站站点
将站点**运行目录（根目录）**指向项目下的 **`public/`**（目录内已自带 `index.php` 与 `console.html`），并参考根目录 `nginx.conf` 添加如下核心规则：
```nginx
root /var/www/proxygosha/public;
index index.php;

# 禁止直接访问内部目录与配置文件
location ~* ^/(\.env|composer\.|start\.php|nginx\.conf|app/|storage/|vendor/) {
    return 404;
}

# Telegram WebSocket 长连接反代给 Workerman
location = /api/v1/ws {
    proxy_pass http://127.0.0.1:3001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 86400s;
    proxy_buffering off;
}

# 默认全部网站路由交给 index.php
location / {
    try_files $uri $uri/ /index.php?$query_string;
}
```
> 若你的面板将站点根目录设为项目根目录（而非 `public/`），根目录也内置了 `index.php`，同样可直接访问。

### 3. 后台常驻托管 Workerman WebSocket 引擎（免手动启动）
无需前台敲 `php start.php start`，使用 **systemd** 或 **Supervisor** 托管一次即可开机自启、断线自动拉起：

- **systemd 方式**（参考 `deploy/proxygosha-ws.service`）：
  ```bash
  sudo cp deploy/proxygosha-ws.service /etc/systemd/system/proxygosha-ws.service
  # 根据实际目录修改 WorkingDirectory 和 ExecStart 路径后执行：
  sudo systemctl daemon-reload
  sudo systemctl enable --now proxygosha-ws
  ```
- **Supervisor 方式**（宝塔面板「进程守护管理器」或参考 `deploy/supervisor-proxygosha.conf`）：
  - 启动命令：`/usr/bin/php /var/www/proxygosha/start.php start`
  - 运行目录：`/var/www/proxygosha`
  - 环境变量：`WORKERMAN_PORT=3001,WORKERMAN_HOST=127.0.0.1`

---

## 三、部署方式 B：Docker Compose 一键全套启动（Nginx + PHP-FPM + Workerman + Cloudflared）

仓库已内置标准多容器编排，执行一条命令即可拉起全部服务（Nginx 默认监听 `127.0.0.1:3000`）：
```bash
cp .env.example .env
# 在 .env 填入 ADMIN_KEY 和 CF_TUNNEL_TOKEN 后：
docker compose up -d --build
```

---

## 四、Cloudflare Tunnel 与 Telegram 连接

1. **Cloudflare Zero Trust → Public Hostname**：
   - Type：`HTTP`
   - URL：`127.0.0.1:3000`（或你的 Nginx 站点监听地址）
2. 打开 `https://你的域名/<你的ADMIN_KEY>` 复制 **443 / 2053 / 2083 / 2087 / 2096 / 8443** 端口对应的 `tg://webproxy?...` 链接即可在 Telegram 中连接。
3. 打开 `https://你的域名/<你的ADMIN_KEY>/status` 查看 Workerman 实时会话统计并点击 **「执行 DC 探测」**。
