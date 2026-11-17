<?php

declare(strict_types=1);

namespace App;

/**
 * ProxyGosha PHP (Workerman) 全局协议与默认配置常量
 */
final class Constants
{
    public const VERSION = '1.2.3-php';

    // Cloudflare 支持的 6 个标准 HTTPS 代理端口
    public const HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

    // Telegram 官方数据中心 IP 映射（DC1–DC5 及 DC203）
    public const DEFAULT_DC_MAP = [
        1 => ['149.154.175.50', '149.154.175.53', '149.154.175.54'],
        2 => ['149.154.167.51', '149.154.167.50', '149.154.167.40', '149.154.167.41'],
        3 => ['149.154.175.100', '149.154.175.101'],
        4 => ['149.154.167.91', '149.154.167.92', '149.154.167.90'],
        5 => ['91.108.56.156', '91.108.56.165', '91.108.56.170'],
        203 => ['91.105.192.110'],
    ];

    public const DEFAULT_HOSTNAMES = ['*'];
    public const DEFAULT_DC_PORTS = [443, 80, 5222];
    public const DEFAULT_CARRIER = 'websocket-lanes';
    public const DEFAULT_SESSION_PATH = '/api/v1/session';
    public const DEFAULT_WS_PATH = '/api/v1/ws';
    public const DEFAULT_BATCH_BYTES = 2097152;
    public const DEFAULT_BOOTSTRAP_TTL = 3600;
    public const DEFAULT_SESSION_TTL = 86400;
    public const DEFAULT_MAX_STREAMS = 16;
    public const DEFAULT_MAX_QUEUED = 16777216;
    public const DEFAULT_STREAM_WINDOW = 4194304;
    public const DEFAULT_DATA_CHUNK = 65536;

    // 令牌签名域、构建印记与令牌类型
    public const TOKEN_DOMAIN = "tgweb-token-v1\0";
    public const BUILD_SEAL = 'Pt54F2/pkjqM1YnQmZRs3Xvqd54U1iZVSYCfYAOgf5wIRzjyeruT';
    public const TOKEN_KIND_BOOTSTRAP = 1;
    public const TOKEN_KIND_SESSION = 2;
    public const PORT_MODE_BASE = 10;
    public const REQUEST_LIMIT = 16777216;

    // 握手欢迎帧（8 字节）
    public const WELCOME = "\x11\x00\x00\x00\x00\x00\x00\x00";

    public const PERMISSIONS_POLICY =
        'accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()';
}
