# ProxyGosha Node.js 中文使用说明

本项目基于原版 [ProxyGosha](https://github.com/amirmarandidev/ProxyGosha) 重构为纯 **Node.js + Express** 架构，使用原生 OpenSSL (`node:crypto`)、高性能 WebSocket (`ws`) 与异步 TCP (`node:net`) 直连 Telegram 数据中心（DC1–DC5、DC203），并原生支持通过 **Cloudflare Tunnel (`cloudflared`)** 暴露到公网使用。

---

## 一、快速部署与启动

### 1. 环境要求
- **Node.js >= 22**（内置原生 TypeScript 运行支持）
- **cloudflared**（用于建立 Cloudflare 隧道）

### 2. 安装依赖与配置环境变量
```bash
npm install
cp .env.example .env
```

编辑 `.env` 文件（只需设置 `ADMIN_KEY` 即可运行）：
```env
PORT=3000
HOST=0.0.0.0

# 必填：管理面板路径密码（至少 16 位英文数字/字符，请妥善保管）
ADMIN_KEY="请替换为至少16位的随机高强度密码"

# 可选：固定 32 位十六进制 Secret（不填则自动从 ADMIN_KEY 派生）
# 注意：若未设置 SECRET，后续修改 ADMIN_KEY 会导致已分享的代理链接失效
SECRET=""

# 可选：传输模式，默认 websocket-lanes（单流独立连接，抗并发与稳定性更好）
CARRIER="websocket-lanes"

# 可选：伪装站 URL（留空则使用内置 LUXVEIL 时尚商城页面）
DECOY_URL=""

# 可选：允许的额外域名（逗号分隔，多个隧道域名时使用）
EXTRA_HOSTS=""
```

### 3. 启动服务
- **开发模式**（支持热加载管理界面）：
  ```bash
  npm run dev
  ```
- **生产模式**（先编译前端控制台，再用 Node.js 启动）：
  ```bash
  npm run build
  npm start
  ```
  > 若系统自带的 Node.js 报错 `ERR_UNKNOWN_FILE_EXTENSION: Unknown file extension ".ts"`，请改用内置 `tsx` 运行生产模式：
  ```bash
  npm run prod
  ```

> **提示**：如果你启动时没有在 `.env` 中配置 `ADMIN_KEY`，可以直接访问 `http://127.0.0.1:3000/` 进入**可视化初始化页面**，在网页中生成并临时激活密钥（重启后失效，生产环境请务必写入 `.env`）。

---

## 二、通过 Cloudflare Tunnel 连接

Node.js 服务默认监听在本地 `127.0.0.1:3000`（不直接对外暴露端口），通过 `cloudflared` 建立加密出站隧道即可自动获得 Cloudflare CDN 与 HTTPS/WSS 证书。

### 方式 A：零域名临时隧道（适合快速测试）
无需绑定自有域名，一条命令即可生成 `*.trycloudflare.com` 公网地址：
```bash
cloudflared tunnel --url http://127.0.0.1:3000
```
终端会输出类似 `https://xxxx-xxxx.trycloudflare.com` 的地址，直接用该域名访问你的管理面板即可。

### 方式 B：自有域名固定隧道（推荐长期稳定使用）
1. 登录 [Cloudflare Zero Trust](https://one.dash.cloudflare.com/) → **Networks** → **Tunnels** → **Create a tunnel**（选择 **Cloudflared**）。
2. 在 **Public Hostname** 中添加映射规则：
   - **Subdomain / Domain**：例如 `tg.yourdomain.com`
   - **Type**：`HTTP`
   - **URL**：`127.0.0.1:3000`
3. 在服务器运行隧道客户端：
   ```bash
   cloudflared tunnel run --token <你的_CF_TUNNEL_TOKEN>
   ```
   或者使用本仓库提供的 `docker-compose.yml` 一键拉起 Node.js + cloudflared 伴随容器：
   ```bash
   # 在 .env 中填入 ADMIN_KEY 和 CF_TUNNEL_TOKEN 后执行：
   docker compose up -d --build
   ```

> **重要提醒**：当服务配置了 `ADMIN_KEY` 后，直接访问 `https://tg.yourdomain.com/` 会显示伪装商城页面（防止主动探测），请访问 **`https://tg.yourdomain.com/<你的ADMIN_KEY>`** 打开管理面板。

---

## 三、Telegram WEB 代理连接使用指南

ProxyGosha 使用的是 Telegram 原生的 **WEB 代理协议**（底层通过浏览器引擎/WebView 走 HTTPS + WebSocket 隧道），**无需在手机或电脑上安装额外客户端软件**。

### 1. 打开管理面板获取连接信息
在浏览器访问：
- 代理链接面板：`https://tg.yourdomain.com/<你的ADMIN_KEY>`
- 状态与 DC 探测页面：`https://tg.yourdomain.com/<你的ADMIN_KEY>/status`

面板会为你的域名自动生成 **6 个 Cloudflare 标准 HTTPS 端口**（`443`、`2053`、`2083`、`2087`、`2096`、`8443`）的专属 Secret 和 `tg://webproxy?...` 链接。

### 2. 方法一：一键导入（最简单）
1. 在已安装 Telegram 的电脑或手机浏览器中打开面板地址 `https://tg.yourdomain.com/<你的ADMIN_KEY>`。
2. 点击任意端口右侧的 **「在 Telegram 中连接」**（`Connect in Telegram`）。
3. 浏览器会唤起 Telegram，在弹出的窗口中点击 **「Connect Proxy / 启用代理」** 即可。

### 3. 方法二：手动添加 Telegram WEB 代理
如果一键链接未自动唤起客户端，可手动填写（注意代理类型必须选择 **WEB**，而不是 MTProto 或 SOCKS5）：

- **Telegram Desktop（桌面端）**：
  1. 打开 **Settings（设置）** → **Advanced（高级）** → **Connection type（连接类型）**
  2. 选择 **Use custom proxy（使用自定义代理）** → **Add proxy（添加代理）**
  3. 代理类型选择 **WEB**（若界面未显示 WEB 选项，请先将 Telegram 升级至最新版）
  4. 按面板表格填写：
     - **Server（服务器）**：`tg.yourdomain.com`（不要带 `https://`）
     - **Port（端口）**：`443`（或 `2053` / `2083` / `2087` / `2096` / `8443` 中任选一个）
     - **Secret（密钥）**：填入面板表格中**该端口对应的 `dd...` 密钥**（每个端口密钥独立，切勿混用）
  5. 点击 **Save（保存）** 并启用即可。

- **Telegram 移动端（Android / iOS）**：
  1. 确保 Telegram App 已更新到支持 **WEB** 代理类型的最新版本。
  2. 打开 **设置（Settings）** → **数据和存储（Data and Storage）** → **代理设置（Proxy Settings）** → **添加代理（Add Proxy）**。
  3. 选择 **WEB** 类型，填入相同的 **Server**、**Port** 和对应端口的 **Secret** 并启用。

---

## 四、常见问题与排查

| 现象 | 排查与解决方法 |
|---|---|
| 访问根域名 `/` 只看到服装商城 | 正常现象（防探测伪装页）。请在网址末尾加上 `/<你的ADMIN_KEY>` 进入管理面板。 |
| Telegram 一直显示 Connecting | 1. 在面板换一个端口（如把 `443` 换成 `2053` 或 `8443`，注意同步更换该端口的 Secret）；<br>2. 进入 `/<ADMIN_KEY>/status` 点击 **执行 DC 探测**，确认服务器本机可连通 Telegram DC1–DC5；<br>3. 检查 Cloudflare 域名 **SSL/TLS → 边缘证书** 是否关闭了 ECH（某些网络会干扰 ECH）。 |
| 分享出去的链接突然失效 | 检查是否修改了 `ADMIN_KEY` 且未配置固定的 `SECRET`。建议在 `.env` 中显式设置 32 位十六进制 `SECRET`。 |
| 提示本地地址无法给 Telegram 连接 | Telegram 客户端要求 WEB 代理必须通过公网 HTTPS/WSS 域名连接，请通过 `cloudflared` 映射域名后再使用。 |
| 如何多端口备份防断连 | 可以把面板里的 `443`、`2053`、`8443` 等多个端口全部添加到 Telegram 代理列表中，某个端口被限速或阻断时直接在 Telegram 列表里切换即可。 |

---

## 五、安全注意事项
- **切勿泄露 `ADMIN_KEY` 和管理面板网址**，分享给他人时只发送面板中的 `tg://webproxy?...` 链接，或单独发送「服务器 + 端口 + 对应 Secret」。
- 所有流量仅在内存中做 Obfuscated2 与 WebSocket 帧转发，**不记录任何客户端 IP、会话 Token 或聊天内容**（Telegram 端到端/MTProto 加密内容代理服务器也无法解密）。
