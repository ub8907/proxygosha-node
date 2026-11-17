<?php

declare(strict_types=1);

namespace App;

use Workerman\Connection\TcpConnection;
use Workerman\Protocols\Http\Request;
use Workerman\Protocols\Http\Response;

/**
 * ProxyGosha PHP (Workerman) HTTP 路由分发器
 */
final class Router
{
    private static string $staticRoot = '';

    public static function setStaticRoot(string $dir): void
    {
        self::$staticRoot = rtrim($dir, '/');
    }

    public static function handleHttp(TcpConnection $connection, Request $req): void
    {
        try {
            $cfg = Config::getRuntime();
            $host = Config::requestHost($req);
            $port = Config::requestPort($req);
            $proto = Config::requestProto($req);
            $method = strtoupper($req->method());
            $pathname = $req->path();
            $query = Config::parseRawQuery((string) $req->queryString());
            Tunnel::recordTunnelHeaders($req, $host);

            // 0. 静态前端资源（/assets/*）
            if (str_starts_with($pathname, '/assets/') && ($method === 'GET' || $method === 'HEAD')) {
                if (self::tryServeStaticAsset($connection, $pathname, $method)) {
                    return;
                }
            }

            // 初始化向导 API：仅在未配置状态开放
            if ($pathname === '/api/setup/status' && $method === 'GET') {
                if ($cfg !== null) {
                    self::sendNotFound($connection);
                    return;
                }
                $currentKey = trim(Config::env('ADMIN_KEY', ''));
                $suggested = str_replace(['-', '_'], 'x', Crypto::b64uEncode(random_bytes(18)));
                self::sendJson($connection, 200, [
                    'configured' => false,
                    'host' => $host,
                    'proto' => $proto,
                    'adminKeyTooShort' => $currentKey !== '' && strlen($currentKey) < 16,
                    'suggestedKey' => $suggested,
                    'tunnel' => Tunnel::getStatus(),
                    'version' => Constants::VERSION,
                ]);
                return;
            }

            if ($pathname === '/api/setup/activate' && $method === 'POST') {
                if ($cfg !== null) {
                    self::sendNotFound($connection);
                    return;
                }
                $rawBody = $req->rawBody();
                if (strlen($rawBody) > 8192) {
                    self::sendJson($connection, 400, ['error' => 'Request body too large.']);
                    return;
                }
                $body = json_decode($rawBody, true);
                if (!is_array($body)) {
                    $body = [];
                }
                $adminKey = is_string($body['adminKey'] ?? null) ? trim($body['adminKey']) : '';
                if (strlen($adminKey) < 16 || !preg_match('/^[A-Za-z0-9_-]+$/', $adminKey)) {
                    self::sendJson($connection, 400, [
                        'error' => 'ADMIN_KEY must be at least 16 characters (letters, digits, - or _).',
                    ]);
                    return;
                }

                $override = ['ADMIN_KEY' => $adminKey];
                if (is_string($body['secret'] ?? null) && trim($body['secret']) !== '') {
                    $override['SECRET'] = trim($body['secret']);
                }
                if (($body['carrier'] ?? '') === 'websocket' || ($body['carrier'] ?? '') === 'websocket-lanes') {
                    $override['CARRIER'] = $body['carrier'];
                }
                if (is_string($body['decoyUrl'] ?? null) && trim($body['decoyUrl']) !== '') {
                    $override['DECOY_URL'] = trim($body['decoyUrl']);
                }
                if (is_string($body['extraHosts'] ?? null) && trim($body['extraHosts']) !== '') {
                    $override['EXTRA_HOSTS'] = trim($body['extraHosts']);
                }

                Config::saveRuntimeOverride($override);
                $nextCfg = Config::getRuntime();
                if ($nextCfg === null) {
                    Config::setRuntimeOverride(null);
                    self::sendJson($connection, 400, ['error' => 'Failed to initialize runtime with supplied configuration.']);
                    return;
                }

                self::sendJson($connection, 200, [
                    'ok' => true,
                    'panelPath' => '/' . rawurlencode($adminKey),
                    'statusPath' => '/' . rawurlencode($adminKey) . '/status',
                ]);
                return;
            }

            // 1. 未配置状态：仅根路径 "/" 提供初始化页面，其余路径返回 404
            if ($cfg === null) {
                if ($pathname === '/' && ($method === 'GET' || $method === 'HEAD')) {
                    self::serveSpa($connection, $method, [
                        'Cache-Control' => 'no-store',
                        'X-Robots-Tag' => 'noindex, nofollow',
                    ]);
                    return;
                }
                self::sendNotFound($connection);
                return;
            }

            // 2. 仅配置 SECRET 但未设置 ADMIN_KEY 时，/setup 展示初始化引导页
            if (empty($cfg['adminKey']) && $pathname === '/setup' && ($method === 'GET' || $method === 'HEAD')) {
                self::serveSpa($connection, $method, [
                    'Cache-Control' => 'no-store',
                    'X-Robots-Tag' => 'noindex, nofollow',
                ]);
                return;
            }

            // 3. 管理面板、动态配置与状态探测路由：/<ADMIN_KEY>、/<ADMIN_KEY>/status、/<ADMIN_KEY>/config、/<ADMIN_KEY>/api/*
            $route = Config::panelRoute($pathname, $query['map'], $cfg);
            if ($route === 'api-state' && $method === 'GET') {
                self::sendJson($connection, 200, self::buildPanelStatePayload($cfg, $host, $proto));
                return;
            }
            if ($route === 'api-probe' && ($method === 'POST' || $method === 'GET')) {
                Engine::probeDcsAsync($cfg, static function (array $results) use ($connection): void {
                    self::sendJson($connection, 200, ['results' => $results]);
                });
                return;
            }
            if ($route === 'api-config' && $method === 'POST') {
                $rawBody = $req->rawBody();
                if (strlen($rawBody) > 16384) {
                    self::sendJson($connection, 400, ['error' => 'Request body too large.']);
                    return;
                }
                $body = json_decode($rawBody, true);
                if (!is_array($body)) {
                    $body = [];
                }
                if (($body['action'] ?? '') === 'reset') {
                    if (!Config::hasBaseEnvRuntime()) {
                        self::sendJson($connection, 400, ['error' => 'Cannot reset: .env / environment has no base ADMIN_KEY or SECRET.']);
                        return;
                    }
                    Config::resetRuntimeOverride();
                    $nextCfg = Config::getRuntime();
                    if ($nextCfg === null) {
                        self::sendJson($connection, 400, ['error' => 'Failed to reload base environment configuration.']);
                        return;
                    }
                    Telemetry::logEvent('config_reset', 'reverted to .env defaults');
                    $basePath = '/' . rawurlencode((string) $nextCfg['adminKey']);
                    self::sendJson($connection, 200, [
                        'ok' => true,
                        'adminKeyChanged' => $nextCfg['adminKey'] !== $cfg['adminKey'],
                        'panelPath' => $basePath,
                        'statusPath' => $basePath . '/status',
                        'configPath' => $basePath . '/config',
                        'state' => self::buildPanelStatePayload($nextCfg, $host, $proto),
                    ]);
                    return;
                }

                $built = Config::buildOverrideFromConfigInput($body, $cfg);
                if (!$built['ok']) {
                    self::sendJson($connection, 400, ['error' => $built['error']]);
                    return;
                }
                Config::saveRuntimeOverride($built['override']);
                $nextCfg = Config::getRuntime();
                if ($nextCfg === null) {
                    self::sendJson($connection, 400, ['error' => 'Failed to apply configuration update.']);
                    return;
                }
                $extraStr = !empty($nextCfg['extraHosts']) ? implode(',', $nextCfg['extraHosts']) : '-';
                Telemetry::logEvent('config_update', "carrier={$nextCfg['carrier']} maxStreams={$nextCfg['maxStreams']} extra={$extraStr}");
                $basePath = '/' . rawurlencode((string) $nextCfg['adminKey']);
                self::sendJson($connection, 200, [
                    'ok' => true,
                    'adminKeyChanged' => $nextCfg['adminKey'] !== $cfg['adminKey'],
                    'panelPath' => $basePath,
                    'statusPath' => $basePath . '/status',
                    'configPath' => $basePath . '/config',
                    'state' => self::buildPanelStatePayload($nextCfg, $host, $proto),
                ]);
                return;
            }
            if (($route === 'panel' || $route === 'status' || $route === 'config') && $method === 'GET') {
                if ($route === 'panel') {
                    Telemetry::$panelViews++;
                } elseif ($route === 'status') {
                    Telemetry::$statusViews++;
                }
                self::serveSpa($connection, $method, [
                    'Cache-Control' => 'no-store',
                    'X-Robots-Tag' => 'noindex, nofollow',
                    'Referrer-Policy' => 'no-referrer',
                    'X-Content-Type-Options' => 'nosniff',
                ]);
                return;
            }

            // 4. 兼容旧版按域名派生 Secret 接口
            $label = Config::generatorLabel($query['map']);
            if ($label !== null) {
                $keyParam = $query['map']['key'][0] ?? '';
                if (
                    empty($cfg['generatorEnabled']) ||
                    empty($cfg['adminKey']) ||
                    $label === '' ||
                    !Crypto::safeEqual($keyParam, (string) $cfg['adminKey'])
                ) {
                    Templates::sendDecoyAsync($connection, $method, (string) $cfg['decoyUrl']);
                    return;
                }
                self::sendSecretText($connection, $cfg, $host, $label, $port);
                return;
            }

            // 5. 主动探测防御与真实站点静态资产
            if ($pathname === '/robots.txt' && ($method === 'GET' || $method === 'HEAD')) {
                $connection->send(new Response(
                    200,
                    ['Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'public, max-age=86400'],
                    $method === 'HEAD' ? '' : "User-agent: *\nAllow: /\nDisallow: /api/\n"
                ));
                return;
            }

            if ($pathname === '/favicon.ico' && ($method === 'GET' || $method === 'HEAD')) {
                $svgIcon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#1a1a1a"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" font-family="system-ui,sans-serif" font-weight="800" font-size="14" fill="#fff" letter-spacing="2">LV</text></svg>';
                $connection->send(new Response(
                    200,
                    ['Content-Type' => 'image/svg+xml', 'Cache-Control' => 'public, max-age=86400', 'X-Content-Type-Options' => 'nosniff'],
                    $method === 'HEAD' ? '' : $svgIcon
                ));
                return;
            }

            if (($pathname === '/health' || $pathname === '/status') && ($method === 'GET' || $method === 'HEAD')) {
                $payload = json_encode([
                    'status' => 'operational',
                    'store' => 'LUXVEIL',
                    'region' => 'global',
                    'uptime' => '99.99%',
                    'timestamp' => time(),
                ], JSON_UNESCAPED_UNICODE);
                $connection->send(new Response(
                    200,
                    ['Content-Type' => 'application/json; charset=utf-8', 'Cache-Control' => 'no-cache'],
                    $method === 'HEAD' ? '' : (string) $payload
                ));
                return;
            }

            // 6. 域名白名单校验（未命中则直接返回伪装站）
            if (!Config::hostAllowed($cfg, $host)) {
                if (
                    array_key_exists('bridge', $query['map']) ||
                    $pathname === $cfg['sessionPath'] ||
                    $pathname === '/api/v1/session'
                ) {
                    $allowedStr = !empty($cfg['hosts']) ? implode(',', $cfg['hosts']) : '*';
                    Telemetry::logEvent('host_reject', "host={$host} allowed={$allowedStr}");
                }
                Templates::sendDecoyAsync($connection, $method, (string) $cfg['decoyUrl']);
                return;
            }

            // 7. Telegram WebProxy 网桥入口：GET /?bridge=<capability>
            if ($pathname === '/' && ($method === 'GET' || $method === 'HEAD')) {
                $rawBridge = $query['map']['bridge'] ?? [];
                if (empty($rawBridge)) {
                    Templates::sendDecoyAsync($connection, $method, (string) $cfg['decoyUrl']);
                    return;
                }
                if (count($query['keys']) !== 1 || $query['keys'][0] !== 'bridge' || count($rawBridge) !== 1) {
                    Telemetry::logEvent('bridge_reject', "host={$host} reason=extra_params");
                    self::sendNotFound($connection);
                    return;
                }
                $headerHosts = array_values(array_filter([
                    (string) $req->header('host', ''),
                    (string) $req->header('x-original-host', ''),
                ], static fn (string $v): bool => $v !== ''));
                $mode = Config::bridgeMode($cfg, $host, $rawBridge[0], $port, $headerHosts);
                if ($mode < 0) {
                    $dispPort = $port !== '' ? $port : '443';
                    Telemetry::logEvent('bridge_reject', "host={$host} port={$dispPort} reason=secret_mismatch");
                    self::sendNotFound($connection);
                    return;
                }
                $dispPort = $port !== '' ? $port : '443';
                Telemetry::logEvent('bridge_ok', "host={$host} port={$dispPort} mode={$mode}");
                Templates::serveBridge($connection, $method, $cfg, $host, $proto, $mode, $port);
                return;
            }

            // 8. 会话握手与关闭路由
            if ($pathname === $cfg['sessionPath'] || $pathname === '/api/v1/session') {
                self::handleSession($connection, $req, $cfg);
                return;
            }

            // 9. 其余未知路径统一返回伪装页面
            Templates::sendDecoyAsync($connection, $method, (string) $cfg['decoyUrl']);
        } catch (\Throwable $e) {
            Telemetry::reportError("http {$req->method()} {$req->path()}", $e);
            Templates::sendBuiltinDecoy($connection, $req->method());
        }
    }

    /**
     * @param array<string, mixed> $cfg
     */
    private static function handleSession(TcpConnection $connection, Request $req, array $cfg): void
    {
        $method = strtoupper($req->method());
        $auth = (string) $req->header('authorization', '');
        if (!str_starts_with($auth, 'Bearer ') || strlen($auth) <= 7) {
            Telemetry::logEvent('session_reject', "method={$method} reason=missing_bearer");
            self::sendNotFound($connection);
            return;
        }
        $token = substr($auth, 7);

        if ($method === 'DELETE') {
            if (Config::verifyToken($cfg, $token, Constants::TOKEN_KIND_SESSION) === null) {
                Telemetry::logEvent('session_reject', 'method=DELETE reason=invalid_token');
                self::sendNotFound($connection);
                return;
            }
            $connection->send(new Response(204, ['Cache-Control' => 'no-store'], ''));
            return;
        }

        if ($method !== 'POST') {
            Telemetry::logEvent('session_reject', "method={$method} reason=bad_method");
            self::sendNotFound($connection);
            return;
        }
        if ((string) $req->header('cookie', '') !== '') {
            Telemetry::logEvent('session_reject', 'reason=cookie_present');
            self::sendNotFound($connection);
            return;
        }

        $rawCt = strtolower((string) $req->header('content-type', ''));
        $ct = trim(explode(';', $rawCt)[0]);
        if ($ct !== 'application/octet-stream') {
            Telemetry::logEvent('session_reject', 'reason=bad_ct(' . ($ct !== '' ? $ct : 'empty') . ')');
            self::sendNotFound($connection);
            return;
        }

        $declaredLen = (int) $req->header('content-length', '0');
        if ($declaredLen > 4096) {
            Telemetry::logEvent('session_reject', "reason=too_large({$declaredLen})");
            self::sendNotFound($connection);
            return;
        }

        $verified = Config::verifyToken($cfg, $token, Constants::TOKEN_KIND_BOOTSTRAP);
        if ($verified === null) {
            Telemetry::logEvent('session_reject', 'reason=invalid_bootstrap');
            self::sendNotFound($connection);
            return;
        }
        $mode = $verified['mode'];
        if (($mode === 1 || $mode === 2) && empty($cfg['acceptGenerated'])) {
            Telemetry::logEvent('session_reject', "reason=generated_disabled mode={$mode}");
            self::sendNotFound($connection);
            return;
        }

        $body = $req->rawBody();
        if (strlen($body) !== 9) {
            Telemetry::logEvent('session_reject', 'reason=bad_body_len(' . strlen($body) . ')');
            self::sendNotFound($connection);
            return;
        }
        if ($body !== "\x10\x00\x00\x00\x00\x00\x00\x01\x01") {
            Telemetry::logEvent('session_reject', 'reason=bad_hello_magic');
            self::sendNotFound($connection);
            return;
        }

        $sessionToken = Config::issueToken($cfg, Constants::TOKEN_KIND_SESSION, (int) $cfg['sessionTtl'], $mode);
        Telemetry::logEvent('session_ok', "carrier={$cfg['carrier']} mode={$mode}");
        $connection->send(new Response(200, [
            'Content-Type' => 'application/octet-stream',
            'Cache-Control' => 'no-store',
            'X-Session-Token' => $sessionToken,
            'X-Down-Cursor' => '0',
            'X-Carrier-Mode' => $cfg['carrier'],
        ], Constants::WELCOME));
    }

    /**
     * @param array<string, mixed> $cfg
     * @return array<string, mixed>
     */
    private static function buildPanelStatePayload(array $cfg, string $host, string $proto): array
    {
        $baseSecret = !empty($cfg['base']) ? 'dd' . bin2hex((string) $cfg['base']) : '';
        $hosts = [];
        foreach (array_merge([$host], $cfg['extraHosts']) as $h) {
            if ($h !== '' && !in_array($h, $hosts, true)) {
                $hosts[] = $h;
            }
        }

        $hostConfigs = [];
        foreach ($hosts as $h) {
            $ports = [];
            foreach (Constants::HTTPS_PORTS as $p) {
                $secret = $cfg['portSecrets'][$p]['secretHex'] ?? $baseSecret;
                $portQuery = $p !== 443 ? "&port={$p}" : '';
                $link = 'tg://webproxy?server=' . rawurlencode($h) . $portQuery . '&secret=' . $secret;
                $ports[] = [
                    'port' => $p,
                    'isDefault' => $p === 443,
                    'secret' => $secret,
                    'link' => $link,
                ];
            }
            $hostConfigs[] = [
                'host' => $h,
                'isLocalhost' => $h === 'localhost' || $h === '127.0.0.1' || $h === '::1',
                'isWorkersDev' => str_ends_with($h, '.workers.dev'),
                'ports' => $ports,
            ];
        }

        $uptimeMs = max(0, Telemetry::nowMs() - Telemetry::$processStartMs);

        return [
            'version' => Constants::VERSION,
            'proto' => $proto,
            'currentHost' => $host,
            'ephemeralSetup' => Config::isEphemeralSetup(),
            'runtimePersisted' => Config::isRuntimePersisted(),
            'hasRuntimeOverride' => Config::hasRuntimeOverride(),
            'baseEnvConfigured' => Config::hasBaseEnvRuntime(),
            'config' => [
                'carrier' => $cfg['carrier'],
                'secretMode' => !empty($cfg['secretDerived']) ? 'derived' : (!empty($cfg['base']) ? 'fixed' : 'none'),
                'maxStreams' => $cfg['maxStreams'],
                'sessionPath' => $cfg['sessionPath'],
                'wsPath' => $cfg['wsPath'],
                'decoyUrl' => $cfg['decoyUrl'] !== '' ? $cfg['decoyUrl'] : null,
                'adTagConfigured' => !empty($cfg['adTag']),
                'extraHosts' => $cfg['extraHosts'],
                'allowedHosts' => $cfg['hosts'],
                'dcPorts' => $cfg['dcPorts'],
                'debug' => !empty($cfg['debug']),
                'generatorEnabled' => !empty($cfg['generatorEnabled']),
                'acceptGenerated' => !empty($cfg['acceptGenerated']),
            ],
            'hostConfigs' => $hostConfigs,
            'stats' => [
                'sessions' => Telemetry::$sessions,
                'sessionsActive' => Telemetry::$sessionsActive,
                'streams' => Telemetry::$streams,
                'dcAttempts' => Telemetry::$dcAttempts,
                'dcFails' => Telemetry::$dcFails,
                'dcEmptyCloses' => Telemetry::$dcEmptyCloses,
                'dcSuccess' => max(0, Telemetry::$dcAttempts - Telemetry::$dcFails),
                'bytesUp' => Telemetry::$bytesUp,
                'bytesDown' => Telemetry::$bytesDown,
                'bytesUpFormatted' => Telemetry::fmtBytes(Telemetry::$bytesUp),
                'bytesDownFormatted' => Telemetry::fmtBytes(Telemetry::$bytesDown),
                'wsRejects' => Telemetry::$wsRejects,
                'panelViews' => Telemetry::$panelViews,
                'statusViews' => Telemetry::$statusViews,
                'uptimeMs' => $uptimeMs,
                'uptimeFormatted' => Telemetry::fmtDuration($uptimeMs),
            ],
            'tunnel' => Tunnel::getStatus(),
            'logs' => Telemetry::recentLogs(60),
        ];
    }

    /**
     * @param array<string, mixed> $cfg
     */
    private static function sendSecretText(TcpConnection $connection, array $cfg, string $host, string $label, string $port): void
    {
        $cleanLabel = preg_replace('/[\x00-\x1f\x7f]/', '', preg_replace('/\/.*$/', '', preg_replace('/^https?:\/\//i', '', $label)));
        $cleanLabel = substr(strtolower(trim((string) $cleanLabel)), 0, 128);
        $isCustom = $cleanLabel !== '';
        $hex = '';
        $domainHex = '';
        $isExisting = false;

        if ($isCustom) {
            $domainHex = bin2hex($cleanLabel);
            $derived = Config::deriveSecret($cfg, $cleanLabel);
            $hex = $derived !== null ? bin2hex($derived) : bin2hex(random_bytes(16));
        } elseif (!empty($cfg['base'])) {
            $hex = bin2hex((string) $cfg['base']);
            $isExisting = true;
        } else {
            $hex = bin2hex(random_bytes(16));
        }

        $portSuffix = ($port !== '' && $port !== '443' && $port !== '80') ? "&port={$port}" : '';
        $link = 'tg://webproxy?server=' . rawurlencode($host) . $portSuffix . '&secret=' . $hex;
        $paddedSecret = 'dd' . $hex;
        $paddedLink = 'tg://webproxy?server=' . rawurlencode($host) . $portSuffix . '&secret=' . $paddedSecret;

        $lines = [
            '=== ProxyGosha PHP (Workerman) Secret Generator ===',
            $isCustom
                ? "[Mode: DOMAIN-DERIVED SECRET for \"{$cleanLabel}\"]"
                : ($isExisting ? '[Status: ACTIVE CONFIGURATION]' : '[Status: NEW SECRET GENERATED]'),
            '',
            'Server:        ' . $host . ($port !== '' && $port !== '443' && $port !== '80' ? ':' . $port : ''),
        ];
        if ($isCustom) {
            $lines[] = 'Target Domain: ' . $cleanLabel;
            $lines[] = 'Domain Hex:    ' . $domainHex;
        }
        $lines[] = 'Secret:        ' . $hex;
        $lines[] = 'Telegram Link: ' . $link;
        $lines[] = '';
        $lines[] = 'Padded Secret: ' . $paddedSecret . ' (Random padding mode - recommended)';
        $lines[] = 'Padded Link:   ' . $paddedLink;
        $lines[] = '';

        $connection->send(new Response(200, [
            'Content-Type' => 'text/plain; charset=utf-8',
            'Cache-Control' => 'no-store',
            'X-Robots-Tag' => 'noindex',
            'Referrer-Policy' => 'no-referrer',
            'X-Content-Type-Options' => 'nosniff',
        ], implode("\n", $lines)));
    }

    /**
     * @param array<string, string> $extraHeaders
     */
    private static function serveSpa(TcpConnection $connection, string $method, array $extraHeaders = []): void
    {
        $indexFile = self::$staticRoot . '/console.html';
        if (!is_file($indexFile)) {
            $indexFile = self::$staticRoot . '/index.html';
        }
        if (!is_file($indexFile)) {
            $connection->send(new Response(
                500,
                ['Content-Type' => 'text/plain; charset=utf-8'],
                '未找到前端静态资源目录（public/console.html）。请确认已包含 public/ 静态构建产物。'
            ));
            return;
        }

        $headers = array_merge(['Content-Type' => 'text/html; charset=utf-8'], $extraHeaders);
        $body = $method === 'HEAD' ? '' : (string) file_get_contents($indexFile);
        $connection->send(new Response(200, $headers, $body));
    }

    private static function tryServeStaticAsset(TcpConnection $connection, string $pathname, string $method): bool
    {
        if (self::$staticRoot === '') {
            return false;
        }
        $rootReal = realpath(self::$staticRoot);
        if ($rootReal === false) {
            return false;
        }
        $target = realpath($rootReal . $pathname);
        if ($target === false || !str_starts_with($target, $rootReal . DIRECTORY_SEPARATOR) || !is_file($target)) {
            return false;
        }

        $ext = strtolower(pathinfo($target, PATHINFO_EXTENSION));
        $mime = match ($ext) {
            'js', 'mjs' => 'application/javascript; charset=utf-8',
            'css' => 'text/css; charset=utf-8',
            'svg' => 'image/svg+xml',
            'json' => 'application/json; charset=utf-8',
            'png' => 'image/png',
            'jpg', 'jpeg' => 'image/jpeg',
            'woff2' => 'font/woff2',
            default => 'application/octet-stream',
        };

        $connection->send(new Response(
            200,
            ['Content-Type' => $mime, 'Cache-Control' => 'public, max-age=604800'],
            $method === 'HEAD' ? '' : (string) file_get_contents($target)
        ));
        return true;
    }

    private static function sendNotFound(TcpConnection $connection): void
    {
        $connection->send(new Response(404, [
            'Content-Type' => 'text/plain; charset=utf-8',
            'Cache-Control' => 'no-store',
        ], 'Not Found'));
    }

    /**
     * @param array<string, mixed> $payload
     */
    private static function sendJson(TcpConnection $connection, int $status, array $payload): void
    {
        $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $connection->send(new Response($status, [
            'Content-Type' => 'application/json; charset=utf-8',
            'Cache-Control' => 'no-store',
        ], $json !== false ? $json : '{}'));
    }
}
