export const VERSION = "1.2.3-node";

// Cloudflare 支持的 6 个标准 HTTPS 代理端口
export const HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443] as const;

// Middle-End 协议常量（保留以保证协议规范完整性）
export const ME_CONSTANTS = {
  RPC_NONCE: 0x7acb87aa,
  RPC_HANDSHAKE: 0x7682eef5,
  RPC_FLAGS: 0x00000000,
  CRYPTO_AES: 0x00000001,
  RPC_PROXY_REQ: 0x36cef1ee,
  RPC_PROXY_ANS: 0x0dfb190e,
  FLAG_HAS_AD_TAG: 0x00000008,
  FLAG_EXTMODE2: 0x00020000,
  FLAG_PAD: 0x08000000,
  FLAG_INTERMEDIATE: 0x20000000,
  FLAG_ABRIDGED: 0x40000000,
  FLAG_QUICKACK: 0x80000000,
} as const;

// Telegram 官方数据中心 IP 映射（DC1–DC5 及 DC203）
export const DEFAULT_DC_MAP: Record<number, string[]> = {
  1: ["149.154.175.50", "149.154.175.53", "149.154.175.54"],
  2: ["149.154.167.51", "149.154.167.50", "149.154.167.40", "149.154.167.41"],
  3: ["149.154.175.100", "149.154.175.101"],
  4: ["149.154.167.91", "149.154.167.92", "149.154.167.90"],
  5: ["91.108.56.156", "91.108.56.165", "91.108.56.170"],
  203: ["91.105.192.110"],
};

// 默认运行时配置（可通过环境变量覆盖）
export const DEFAULT_CONFIG = {
  secretHex: "",
  adTagHex: "",
  hostnames: ["*"],
  debug: false,
  generatorEnabled: false,
  generatorKey: "",
  acceptGenerated: false,
  dc: DEFAULT_DC_MAP,
  dcPort: 443,
  dcPorts: [443, 80, 5222],
  carrier: "websocket-lanes" as "websocket" | "websocket-lanes",
  sessionPath: "/api/v1/session",
  wsPath: "/api/v1/ws",
  batchBytes: 2097152,
  bootstrapTtl: 3600,
  sessionTtl: 86400,
  maxStreams: 16,
  maxQueued: 16777216,
  streamWindow: 4194304,
  dataChunk: 65536,
};

// 令牌签名域、构建印记及令牌类型常量
export const TOKEN_DOMAIN = Buffer.from("tgweb-token-v1\0", "utf8");
export const BUILD_SEAL = "Pt54F2/pkjqM1YnQmZRs3Xvqd54U1iZVSYCfYAOgf5wIRzjyeruT";
export const TOKEN_KIND_BOOTSTRAP = 1;
export const TOKEN_KIND_SESSION = 2;
export const PORT_MODE_BASE = 10;
export const REQUEST_LIMIT = 16777216;

// 握手欢迎帧与空载荷常量
export const WELCOME = Buffer.from([0x11, 0, 0, 0, 0, 0, 0, 0]);
export const EMPTY = Buffer.alloc(0);

export const PERMISSIONS_POLICY =
  "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()";
