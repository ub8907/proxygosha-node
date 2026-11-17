<?php

declare(strict_types=1);

namespace App;

/**
 * Nginx + PHP-FPM 默认网站模式（index.php）HTTP 内核。
 *
 * 负责直接响应所有网站路由、初始化向导、代理链接面板、Bridge 注入、Session 握手、
 * DC 实时 MTProto 探测以及 LUXVEIL 伪装页；并与后台 Workerman WebSocket 引擎共享配置与遥测。
 */
final class FpmKernel
{
    public static function dispatch(string $projectRoot, string $staticRoot): void
    {
        Telemetry::init();
        Config::loadDotEnv($projectRoot . '/.env');
        Config::setRuntimeFile($projectRoot . '/storage/runtime.json');

        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $rawUri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $qPos = strpos($rawUri, '?');
        $pathname = $qPos !== false ? substr($rawUri, 0, $qPos) : $rawUri;
        if ($pathname === '') {
            $pathname = '/';
        }
        $queryString = $qPos !== false ? substr($rawUri, $qPos + 1) : (string) ($_SERVER['QUERY_STRING'] ?? '');
        $query = Config::parseRawQuery($queryString);

        $host = self::serverHost();
        $port = self::serverPort();
        $proto = self::serverProto($host);
        $cfg = Config::getRuntime();

        // 若 Nginx 未拦截静态 /assets/*，由 PHP 兜底输出
        if (str_starts_with($pathname, '/assets/') && ($method === 'GET' || $method === 'HEAD')) {
            if (self::tryServeStaticAsset($staticRoot, $pathname, $method)) {
                return;
            }
        }

        // 禁止通过 HTTP 直接访问敏感路径或源码目录
        if (
            preg_match('#^/(app|storage|vendor)(/|$)#i', $pathname) ||
            preg_match('#^/(\.env|composer\.|start\.php|nginx\.conf|Dockerfile)#i', $pathname)
        ) {
            self::sendNotFound();
            return;
        }

        // 1. 初始化状态查询与激活
        if ($pathname === '/api/setup/status' && $method === 'GET') {
            if ($cfg !== null) {
                self::sendNotFound();
                return;
            }
            $currentKey = trim(Config::env('ADMIN_KEY', ''));
            $suggested = str_replace(['-', '_'], 'x', Crypto::b64uEncode(random_bytes(18)));
            self::sendJson(200, [
                'configured' => false,
                'host' => $host,
                'proto' => $proto,
                'adminKeyTooShort' => $currentKey !== '' && strlen($currentKey) < 16,
                'suggestedKey' => $suggested,
                'tunnel' => self::fpmTunnelStatus($host),
                'version' => Constants::VERSION,
            ]);
            return;
        }

        if ($pathname === '/api/setup/activate' && $method === 'POST') {
            if ($cfg !== null) {
                self::sendNotFound();
                return;
            }
            $rawBody = (string) file_get_contents('php://input', false, null, 0, 8193);
            if (strlen($rawBody) > 8192) {
                self::sendJson(400, ['error' => 'Request body too large.']);
                return;
            }
            $body = json_decode($rawBody, true);
            if (!is_array($body)) {
                $body = [];
            }
            $adminKey = is_string($body['adminKey'] ?? null) ? trim($body['adminKey']) : '';
            if (strlen($adminKey) < 16 || !preg_match('/^[A-Za-z0-9_-]+$/', $adminKey)) {
                self::sendJson(400, [
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

            if (!Config::saveRuntimeOverride($override) || Config::getRuntime() === null) {
                Config::setRuntimeOverride(null);
                self::sendJson(400, ['error' => 'Failed to save runtime configuration (check storage/ permission).']);
                return;
            }

            self::sendJson(200, [
                'ok' => true,
                'panelPath' => '/' . rawurlencode($adminKey),
                'statusPath' => '/' . rawurlencode($adminKey) . '/status',
            ]);
            return;
        }

        // 未配置时仅 / 展示初始化控制台
        if ($cfg === null) {
            if ($pathname === '/' && ($method === 'GET' || $method === 'HEAD')) {
                self::serveSpa($staticRoot, $method, [
                    'Cache-Control: no-store',
                    'X-Robots-Tag: noindex, nofollow',
                ]);
                return;
            }
            self::sendNotFound();
            return;
        }

        // 仅配了 SECRET 未配 ADMIN_KEY 时 /setup 展示引导页
        if (empty($cfg['adminKey']) && $pathname === '/setup' && ($method === 'GET' || $method === 'HEAD')) {
            self::serveSpa($staticRoot, $method, [
                'Cache-Control: no-store',
                'X-Robots-Tag: noindex, nofollow',
            ]);
            return;
        }

        // 2. 管理面板、动态配置与状态探测路由
        $route = Config::panelRoute($pathname, $query['map'], $cfg);
        if ($route === 'api-state' && $method === 'GET') {
            $remote = self::queryWorkermanEndpoint($pathname, $method, $host, $proto);
            if ($remote !== null) {
                self::sendJsonRaw(200, $remote);
                return;
            }
            self::sendJson(200, self::buildFallbackStatePayload($cfg, $host, $proto));
            return;
        }
        if ($route === 'api-probe' && ($method === 'POST' || $method === 'GET')) {
            $remote = self::queryWorkermanEndpoint($pathname, $method, $host, $proto);
            if ($remote !== null) {
                self::sendJsonRaw(200, $remote);
                return;
            }
            self::sendJson(200, ['results' => self::probeDcsSync($cfg)]);
            return;
        }
        if ($route === 'api-config' && $method === 'POST') {
            $rawBody = (string) file_get_contents('php://input', false, null, 0, 16385);
            if (strlen($rawBody) > 16384) {
                self::sendJson(400, ['error' => 'Request body too large.']);
                return;
            }
            $body = json_decode($rawBody, true);
            if (!is_array($body)) {
                $body = [];
            }
            if (($body['action'] ?? '') === 'reset') {
                if (!Config::hasBaseEnvRuntime()) {
                    self::sendJson(400, ['error' => 'Cannot reset: .env / environment has no base ADMIN_KEY or SECRET.']);
                    return;
                }
                Config::resetRuntimeOverride();
                $nextCfg = Config::getRuntime();
                if ($nextCfg === null) {
                    self::sendJson(400, ['error' => 'Failed to reload base environment configuration.']);
                    return;
                }
                $basePath = '/' . rawurlencode((string) $nextCfg['adminKey']);
                $remoteRaw = self::queryWorkermanEndpoint($basePath . '/api/state', 'GET', $host, $proto);
                $state = is_string($remoteRaw) ? (json_decode($remoteRaw, true) ?: self::buildFallbackStatePayload($nextCfg, $host, $proto)) : self::buildFallbackStatePayload($nextCfg, $host, $proto);
                self::sendJson(200, [
                    'ok' => true,
                    'adminKeyChanged' => $nextCfg['adminKey'] !== $cfg['adminKey'],
                    'panelPath' => $basePath,
                    'statusPath' => $basePath . '/status',
                    'configPath' => $basePath . '/config',
                    'state' => $state,
                ]);
                return;
            }

            $built = Config::buildOverrideFromConfigInput($body, $cfg);
            if (!$built['ok']) {
                self::sendJson(400, ['error' => $built['error']]);
                return;
            }
            if (!Config::saveRuntimeOverride($built['override'])) {
                self::sendJson(400, ['error' => 'Failed to save storage/runtime.json (check storage/ write permission).']);
                return;
            }
            $nextCfg = Config::getRuntime();
            if ($nextCfg === null) {
                self::sendJson(400, ['error' => 'Failed to apply configuration update.']);
                return;
            }
            $basePath = '/' . rawurlencode((string) $nextCfg['adminKey']);
            $remoteRaw = self::queryWorkermanEndpoint($basePath . '/api/state', 'GET', $host, $proto);
            $state = is_string($remoteRaw) ? (json_decode($remoteRaw, true) ?: self::buildFallbackStatePayload($nextCfg, $host, $proto)) : self::buildFallbackStatePayload($nextCfg, $host, $proto);
            self::sendJson(200, [
                'ok' => true,
                'adminKeyChanged' => $nextCfg['adminKey'] !== $cfg['adminKey'],
                'panelPath' => $basePath,
                'statusPath' => $basePath . '/status',
                'configPath' => $basePath . '/config',
                'state' => $state,
            ]);
            return;
        }
        if (($route === 'panel' || $route === 'status' || $route === 'config') && $method === 'GET') {
            self::serveSpa($staticRoot, $method, [
                'Cache-Control: no-store',
                'X-Robots-Tag: noindex, nofollow',
                'Referrer-Policy: no-referrer',
                'X-Content-Type-Options: nosniff',
            ]);
            return;
        }

        // 3. 旧版 Secret 生成器
        $label = Config::generatorLabel($query['map']);
        if ($label !== null) {
            $keyParam = $query['map']['key'][0] ?? '';
            if (
                empty($cfg['generatorEnabled']) ||
                empty($cfg['adminKey']) ||
                $label === '' ||
                !Crypto::safeEqual($keyParam, (string) $cfg['adminKey'])
            ) {
                self::sendDecoy($method, (string) $cfg['decoyUrl']);
                return;
            }
            self::sendSecretText($cfg, $host, $label, $port);
            return;
        }

        // 4. 静态伪装资产与健康检查
        if ($pathname === '/robots.txt' && ($method === 'GET' || $method === 'HEAD')) {
            http_response_code(200);
            header('Content-Type: text/plain; charset=utf-8');
            header('Cache-Control: public, max-age=86400');
            if ($method !== 'HEAD') {
                echo "User-agent: *\nAllow: /\nDisallow: /api/\n";
            }
            return;
        }

        if ($pathname === '/favicon.ico' && ($method === 'GET' || $method === 'HEAD')) {
            http_response_code(200);
            header('Content-Type: image/svg+xml');
            header('Cache-Control: public, max-age=86400');
            header('X-Content-Type-Options: nosniff');
            if ($method !== 'HEAD') {
                echo '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#1a1a1a"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" font-family="system-ui,sans-serif" font-weight="800" font-size="14" fill="#fff" letter-spacing="2">LV</text></svg>';
            }
            return;
        }

        if (($pathname === '/health' || $pathname === '/status') && ($method === 'GET' || $method === 'HEAD')) {
            http_response_code(200);
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-cache');
            if ($method !== 'HEAD') {
                echo json_encode([
                    'status' => 'operational',
                    'store' => 'LUXVEIL',
                    'region' => 'global',
                    'uptime' => '99.99%',
                    'timestamp' => time(),
                ]);
            }
            return;
        }

        // 5. 域名白名单校验
        if (!Config::hostAllowed($cfg, $host)) {
            self::sendDecoy($method, (string) $cfg['decoyUrl']);
            return;
        }

        // 6. Bridge 注入入口：GET /?bridge=<capability>
        if ($pathname === '/' && ($method === 'GET' || $method === 'HEAD')) {
            $rawBridge = $query['map']['bridge'] ?? [];
            if (empty($rawBridge)) {
                self::sendDecoy($method, (string) $cfg['decoyUrl']);
                return;
            }
            if (count($query['keys']) !== 1 || $query['keys'][0] !== 'bridge' || count($rawBridge) !== 1) {
                self::sendNotFound();
                return;
            }
            $headerHosts = array_values(array_filter([
                (string) ($_SERVER['HTTP_HOST'] ?? ''),
                (string) ($_SERVER['HTTP_X_ORIGINAL_HOST'] ?? ''),
            ], static fn (string $v): bool => $v !== ''));
            $mode = Config::bridgeMode($cfg, $host, $rawBridge[0], $port, $headerHosts);
            if ($mode < 0) {
                self::sendNotFound();
                return;
            }
            self::serveBridge($method, $cfg, $host, $proto, $mode);
            return;
        }

        // 7. Session 握手路由
        if ($pathname === $cfg['sessionPath'] || $pathname === '/api/v1/session') {
            self::handleSession($method, $cfg);
            return;
        }

        // 8. 其余路径统一返回伪装商城页面
        self::sendDecoy($method, (string) $cfg['decoyUrl']);
    }

    /**
     * 优先向本地后台 Workerman 查询真实运行遥测与日志（失败则返回 null 降级）
     */
    private static function queryWorkermanEndpoint(string $pathname, string $method, string $host, string $proto): ?string
    {
        $base = trim(Config::env('WORKERMAN_INTERNAL_URL', ''));
        if ($base === '') {
            $wsPort = (int) (Config::env('WORKERMAN_PORT', '3001') ?: 3001);
            $base = "http://127.0.0.1:{$wsPort}";
        }
        $parsed = parse_url($base);
        if (!is_array($parsed) || empty($parsed['host'])) {
            return null;
        }
        $wHost = $parsed['host'];
        $wPort = (int) ($parsed['port'] ?? 3001);

        $fp = @stream_socket_client("tcp://{$wHost}:{$wPort}", $errno, $errstr, 0.35);
        if (!is_resource($fp)) {
            return null;
        }
        stream_set_timeout($fp, str_ends_with($pathname, '/probe') ? 8 : 1);

        $cfHeaders = '';
        foreach (['HTTP_CF_RAY' => 'CF-Ray', 'HTTP_CF_CONNECTING_IP' => 'CF-Connecting-IP', 'HTTP_CF_VISITOR' => 'CF-Visitor'] as $srv => $hdr) {
            if (!empty($_SERVER[$srv])) {
                $cfHeaders .= "{$hdr}: " . str_replace(["\r", "\n"], '', (string) $_SERVER[$srv]) . "\r\n";
            }
        }

        $req = "{$method} {$pathname} HTTP/1.1\r\n"
            . "Host: {$host}\r\n"
            . "X-Forwarded-Host: {$host}\r\n"
            . "X-Forwarded-Proto: {$proto}\r\n"
            . $cfHeaders
            . "Connection: close\r\n\r\n";

        @fwrite($fp, $req);
        $raw = '';
        while (!feof($fp)) {
            $chunk = @fread($fp, 8192);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $raw .= $chunk;
        }
        @fclose($fp);

        $sep = strpos($raw, "\r\n\r\n");
        if ($sep === false) {
            return null;
        }
        $head = substr($raw, 0, $sep);
        $body = substr($raw, $sep + 4);
        if (!preg_match('/^HTTP\/\S+\s+200\b/', $head)) {
            return null;
        }
        // 处理 Chunked 传输编码（如有）
        if (stripos($head, 'transfer-encoding: chunked') !== false) {
            $decoded = '';
            $pos = 0;
            $len = strlen($body);
            while ($pos < $len) {
                $nl = strpos($body, "\r\n", $pos);
                if ($nl === false) {
                    break;
                }
                $hexSize = trim(explode(';', substr($body, $pos, $nl - $pos))[0]);
                $chunkLen = hexdec($hexSize);
                if ($chunkLen <= 0) {
                    break;
                }
                $decoded .= substr($body, $nl + 2, (int) $chunkLen);
                $pos = $nl + 2 + (int) $chunkLen + 2;
            }
            $body = $decoded;
        }
        return json_decode($body, true) !== null ? $body : null;
    }

    /**
     * @param array<string, mixed> $cfg
     * @return array<string, mixed>
     */
    private static function buildFallbackStatePayload(array $cfg, string $host, string $proto): array
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
                $ports[] = [
                    'port' => $p,
                    'isDefault' => $p === 443,
                    'secret' => $secret,
                    'link' => 'tg://webproxy?server=' . rawurlencode($h) . $portQuery . '&secret=' . $secret,
                ];
            }
            $hostConfigs[] = [
                'host' => $h,
                'isLocalhost' => $h === 'localhost' || $h === '127.0.0.1' || $h === '::1',
                'isWorkersDev' => str_ends_with($h, '.workers.dev'),
                'ports' => $ports,
            ];
        }

        $wsPort = (int) (Config::env('WORKERMAN_PORT', '3001') ?: 3001);

        return [
            'version' => Constants::VERSION . ' (nginx+fpm)',
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
                'sessions' => 0,
                'sessionsActive' => 0,
                'streams' => 0,
                'dcAttempts' => 0,
                'dcFails' => 0,
                'dcEmptyCloses' => 0,
                'dcSuccess' => 0,
                'bytesUp' => 0,
                'bytesDown' => 0,
                'bytesUpFormatted' => '0 B',
                'bytesDownFormatted' => '0 B',
                'wsRejects' => 0,
                'panelViews' => 1,
                'statusViews' => 1,
                'uptimeMs' => 0,
                'uptimeFormatted' => 'FPM',
            ],
            'tunnel' => self::fpmTunnelStatus($host, "Nginx+PHP-FPM 网站已就绪；请确认 Workerman WS 进程已监听 127.0.0.1:{$wsPort} 并配置 Nginx 反代 /api/v1/ws"),
            'logs' => [
                [
                    't' => Telemetry::nowMs(),
                    'event' => 'fpm_mode',
                    'detail' => "HTTP served by index.php (PHP-FPM); WS backend 127.0.0.1:{$wsPort} unreachable",
                ],
            ],
        ];
    }

    /**
     * PHP-FPM 同步版 Telegram DC1–DC5 + DC203 MTProto 连通性探测
     *
     * @param array<string, mixed> $cfg
     * @return array<int, array<string, mixed>>
     */
    private static function probeDcsSync(array $cfg): array
    {
        $keys = array_map('intval', array_keys($cfg['dc']));
        sort($keys);
        $configuredPorts = !empty($cfg['dcPorts']) ? $cfg['dcPorts'] : [443, 80, 5222];
        $probePort = (int) ($configuredPorts[0] ?? 443);
        $fallbackPorts = array_values(array_filter([443, 80, 5222], static fn (int $p): bool => $p !== $probePort));

        $results = [];
        foreach ($keys as $dc) {
            $ips = is_array($cfg['dc'][$dc]) ? $cfg['dc'][$dc] : [$cfg['dc'][$dc]];
            $ip = (string) $ips[array_rand($ips)];
            $r = self::probeSingleSync($dc, $ip, $probePort);
            if ($dc !== 203 && $r['mtprotoOk'] === false && !empty($fallbackPorts)) {
                $alts = [];
                foreach ($fallbackPorts as $altPort) {
                    $ar = self::probeSingleSync($dc, $ip, $altPort);
                    $alts[] = [
                        'port' => $altPort,
                        'ok' => $ar['ok'],
                        'ms' => $ar['ms'],
                        'mtprotoOk' => $ar['mtprotoOk'],
                        'reason' => $ar['reason'],
                    ];
                }
                $r['altPorts'] = $alts;
            }
            $results[] = $r;
        }
        return $results;
    }

    /**
     * @return array<string, mixed>
     */
    private static function probeSingleSync(int $dc, string $ip, int $port): array
    {
        $started = Telemetry::nowMs();
        $fp = @stream_socket_client("tcp://{$ip}:{$port}", $errno, $errstr, 2.5);
        if (!is_resource($fp)) {
            return [
                'dc' => $dc,
                'ip' => $ip,
                'port' => $port,
                'ok' => false,
                'ms' => max(0, Telemetry::nowMs() - $started),
                'mtprotoOk' => false,
                'mtprotoMs' => null,
                'reason' => $errstr !== '' ? $errstr : 'connect_failed',
            ];
        }
        $tcpMs = max(0, Telemetry::nowMs() - $started);
        if ($dc === 203) {
            @fclose($fp);
            return [
                'dc' => $dc,
                'ip' => $ip,
                'port' => $port,
                'ok' => true,
                'ms' => $tcpMs,
                'mtprotoOk' => null,
                'mtprotoMs' => $tcpMs,
                'reason' => 'cdn_tcp_ok',
            ];
        }

        stream_set_timeout($fp, 2);
        $prefix = '';
        $safe = false;
        for ($i = 0; $i < 16 && !$safe; $i++) {
            $prefix = random_bytes(56);
            $safe = Engine::safeDcHeaderPrefix($prefix);
        }
        if (!$safe) {
            $prefix = "\x12\x34\x56\x78\x9a\xbc\xde\xf0" . random_bytes(48);
        }

        $enc = new ObfuscatedCtrStream(substr($prefix, 8, 32), substr($prefix, 40, 16), 56);
        $rev = strrev(substr($prefix, 8, 48));
        $dec = new ObfuscatedCtrStream(substr($rev, 0, 32), substr($rev, 32, 16), 0);

        $tail = "\xef\xef\xef\xef" . pack('v', $dc & 0xffff) . "\x00\x00";
        $reqPq = pack('P', 0) . pack('P', time() << 32) . pack('V', 20) . pack('V', 0xbe7e8ef1) . random_bytes(16);
        @fwrite($fp, $prefix . $enc->update($tail) . $enc->update("\x0a" . $reqPq));

        $rxPlain = '';
        $rxBytes = 0;
        while ($rxBytes < 25 && !feof($fp)) {
            $chunk = @fread($fp, 1024);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $rxBytes += strlen($chunk);
            $rxPlain .= $dec->update($chunk);
        }
        $meta = stream_get_meta_data($fp);
        @fclose($fp);

        if ($rxBytes >= 25) {
            $ok = substr($rxPlain, 1, 8) === "\x00\x00\x00\x00\x00\x00\x00\x00";
            return [
                'dc' => $dc,
                'ip' => $ip,
                'port' => $port,
                'ok' => true,
                'ms' => $tcpMs,
                'mtprotoOk' => $ok,
                'mtprotoMs' => max(0, Telemetry::nowMs() - $started),
                'reason' => $ok ? 'resPQ_ok' : 'invalid_reply',
            ];
        }

        return [
            'dc' => $dc,
            'ip' => $ip,
            'port' => $port,
            'ok' => true,
            'ms' => $tcpMs,
            'mtprotoOk' => false,
            'mtprotoMs' => max(0, Telemetry::nowMs() - $started),
            'reason' => !empty($meta['timed_out']) ? 'mtproto_timeout' : "eof({$rxBytes}B)",
        ];
    }

    /**
     * @param array<string, mixed> $cfg
     */
    private static function handleSession(string $method, array $cfg): void
    {
        $auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? ''));
        if (!str_starts_with($auth, 'Bearer ') || strlen($auth) <= 7) {
            self::sendNotFound();
            return;
        }
        $token = substr($auth, 7);

        if ($method === 'DELETE') {
            if (Config::verifyToken($cfg, $token, Constants::TOKEN_KIND_SESSION) === null) {
                self::sendNotFound();
                return;
            }
            http_response_code(204);
            header('Cache-Control: no-store');
            return;
        }

        if ($method !== 'POST') {
            self::sendNotFound();
            return;
        }
        if (!empty($_SERVER['HTTP_COOKIE'])) {
            self::sendNotFound();
            return;
        }
        $rawCt = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ($_SERVER['HTTP_CONTENT_TYPE'] ?? '')));
        $ct = trim(explode(';', $rawCt)[0]);
        if ($ct !== 'application/octet-stream') {
            self::sendNotFound();
            return;
        }
        $declaredLen = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($declaredLen > 4096) {
            self::sendNotFound();
            return;
        }
        $verified = Config::verifyToken($cfg, $token, Constants::TOKEN_KIND_BOOTSTRAP);
        if ($verified === null) {
            self::sendNotFound();
            return;
        }
        $mode = $verified['mode'];
        if (($mode === 1 || $mode === 2) && empty($cfg['acceptGenerated'])) {
            self::sendNotFound();
            return;
        }
        $body = (string) file_get_contents('php://input', false, null, 0, 64);
        if (strlen($body) !== 9 || $body !== "\x10\x00\x00\x00\x00\x00\x00\x01\x01") {
            self::sendNotFound();
            return;
        }

        $sessionToken = Config::issueToken($cfg, Constants::TOKEN_KIND_SESSION, (int) $cfg['sessionTtl'], $mode);
        http_response_code(200);
        header('Content-Type: application/octet-stream');
        header('Cache-Control: no-store');
        header('X-Session-Token: ' . $sessionToken);
        header('X-Down-Cursor: 0');
        header('X-Carrier-Mode: ' . $cfg['carrier']);
        echo Constants::WELCOME;
    }

    /**
     * @param array<string, mixed> $cfg
     */
    private static function serveBridge(string $method, array $cfg, string $host, string $proto, int $mode): void
    {
        $nonce = Crypto::b64uEncode(random_bytes(18));
        $bootstrap = Config::issueToken($cfg, Constants::TOKEN_KIND_BOOTSTRAP, (int) $cfg['bootstrapTtl'], $mode);
        $body = strtr(Templates::BRIDGE_HTML, [
            '__NONCE__' => $nonce,
            '__BOOTSTRAP__' => json_encode($bootstrap, JSON_UNESCAPED_SLASHES),
            '__CARRIER_MODE__' => json_encode($cfg['carrier'], JSON_UNESCAPED_SLASHES),
            '__BATCH_LIMIT__' => (string) $cfg['batchBytes'],
            '__SESSION_PATH__' => json_encode(ltrim((string) $cfg['sessionPath'], '/'), JSON_UNESCAPED_SLASHES),
            '__WS_PATH__' => json_encode(ltrim((string) $cfg['wsPath'], '/'), JSON_UNESCAPED_SLASHES),
        ]);

        $wsProto = $proto === 'http' ? 'ws' : 'wss';
        $cspHosts = [];
        foreach (array_merge([$host], $cfg['extraHosts'], $cfg['hosts']) as $item) {
            $clean = strtolower(trim((string) $item));
            if ($clean !== '' && $clean !== '*' && $clean !== 'proxy.example.com' && !in_array($clean, $cspHosts, true)) {
                $cspHosts[] = $clean;
            }
        }
        $connectParts = ["'self'"];
        foreach ($cspHosts as $h) {
            $connectParts[] = "{$proto}://{$h}:*";
            $connectParts[] = "{$wsProto}://{$h}:*";
            $connectParts[] = "{$proto}://{$h}";
            $connectParts[] = "{$wsProto}://{$h}";
            $connectParts[] = "https://{$h}:*";
            $connectParts[] = "wss://{$h}:*";
            $connectParts[] = "https://{$h}";
            $connectParts[] = "wss://{$h}";
        }
        $connectSrc = implode(' ', array_unique($connectParts));

        $csp = implode('; ', [
            "default-src 'none'",
            "base-uri 'none'",
            "child-src 'none'",
            "connect-src {$connectSrc}",
            "font-src 'none'",
            "form-action 'none'",
            "frame-ancestors http://127.0.0.1:*",
            "frame-src 'none'",
            "img-src 'none'",
            "manifest-src 'none'",
            "media-src 'none'",
            "object-src 'none'",
            "script-src 'nonce-{$nonce}'",
            "style-src 'none'",
            "worker-src 'none'",
            "sandbox allow-same-origin allow-scripts",
        ]);

        http_response_code(200);
        header('Content-Type: text/html; charset=utf-8');
        header('Content-Security-Policy: ' . $csp);
        header('Cache-Control: no-store');
        header('Referrer-Policy: no-referrer');
        header('X-Content-Type-Options: nosniff');
        header('X-DNS-Prefetch-Control: off');
        header('Permissions-Policy: ' . Constants::PERMISSIONS_POLICY);
        if ($method !== 'HEAD') {
            echo $body;
        }
    }

    private static function sendDecoy(string $method, string $decoyUrl): void
    {
        if ($decoyUrl !== '' && (str_starts_with($decoyUrl, 'http://') || str_starts_with($decoyUrl, 'https://'))) {
            $ctx = stream_context_create([
                'http' => [
                    'method' => $method === 'HEAD' ? 'HEAD' : 'GET',
                    'timeout' => 4,
                    'header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n",
                ],
                'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
            ]);
            $body = @file_get_contents($decoyUrl, false, $ctx);
            if (is_string($body)) {
                http_response_code(200);
                header('Content-Type: text/html; charset=utf-8');
                header('Cache-Control: no-cache');
                if ($method !== 'HEAD') {
                    echo $body;
                }
                return;
            }
        }
        http_response_code(200);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-cache');
        header('X-Content-Type-Options: nosniff');
        header('Vary: Accept-Encoding');
        if ($method !== 'HEAD') {
            echo Templates::DECOY_HTML;
        }
    }

    /**
     * @param array<string, mixed> $cfg
     */
    private static function sendSecretText(array $cfg, string $host, string $label, string $port): void
    {
        $clean = preg_replace('/[\x00-\x1f\x7f]/', '', preg_replace('/\/.*$/', '', preg_replace('/^https?:\/\//i', '', $label)));
        $clean = substr(strtolower(trim((string) $clean)), 0, 128);
        $hex = '';
        $domainHex = '';
        if ($clean !== '') {
            $domainHex = bin2hex($clean);
            $derived = Config::deriveSecret($cfg, $clean);
            $hex = $derived !== null ? bin2hex($derived) : bin2hex(random_bytes(16));
        } elseif (!empty($cfg['base'])) {
            $hex = bin2hex((string) $cfg['base']);
        } else {
            $hex = bin2hex(random_bytes(16));
        }
        $portSuffix = ($port !== '' && $port !== '443' && $port !== '80') ? "&port={$port}" : '';
        $link = 'tg://webproxy?server=' . rawurlencode($host) . $portSuffix . '&secret=' . $hex;
        $padded = 'dd' . $hex;
        $paddedLink = 'tg://webproxy?server=' . rawurlencode($host) . $portSuffix . '&secret=' . $padded;
        http_response_code(200);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Robots-Tag: noindex');
        $lines = [
            '=== ProxyGosha PHP Secret Generator ===',
            'Server:        ' . $host . ($port !== '' && $port !== '443' && $port !== '80' ? ':' . $port : ''),
        ];
        if ($clean !== '') {
            $lines[] = 'Target Domain: ' . $clean;
            $lines[] = 'Domain Hex:    ' . $domainHex;
        }
        $lines[] = 'Secret:        ' . $hex;
        $lines[] = 'Telegram Link: ' . $link;
        $lines[] = 'Padded Secret: ' . $padded;
        $lines[] = 'Padded Link:   ' . $paddedLink;
        echo implode("\n", $lines) . "\n";
    }

    /**
     * @return array<string, mixed>
     */
    private static function fpmTunnelStatus(string $host, string $lastError = ''): array
    {
        $cfRay = (string) ($_SERVER['HTTP_CF_RAY'] ?? '');
        $dash = $cfRay !== '' ? strrpos($cfRay, '-') : false;
        $colo = ($dash !== false && $dash > 0) ? substr($cfRay, $dash + 1) : substr($cfRay, 0, 12);
        return [
            'binaryAvailable' => Tunnel::isCloudflaredAvailable(),
            'autostartEnabled' => false,
            'tokenConfigured' => trim(Config::env('CF_TUNNEL_TOKEN', '')) !== '',
            'running' => false,
            'pid' => null,
            'requestsViaTunnel' => $cfRay !== '' ? 1 : 0,
            'lastTunnelHost' => $cfRay !== '' ? $host : '',
            'lastRayColo' => $colo,
            'lastError' => $lastError,
        ];
    }

    /**
     * @param string[] $headers
     */
    private static function serveSpa(string $staticRoot, string $method, array $headers): void
    {
        $file = $staticRoot . '/console.html';
        if (!is_file($file)) {
            $file = $staticRoot . '/index.html';
        }
        if (!is_file($file)) {
            http_response_code(500);
            header('Content-Type: text/plain; charset=utf-8');
            echo '未找到控制台静态页面（public/console.html）。';
            return;
        }
        http_response_code(200);
        header('Content-Type: text/html; charset=utf-8');
        foreach ($headers as $h) {
            header($h);
        }
        if ($method !== 'HEAD') {
            readfile($file);
        }
    }

    private static function tryServeStaticAsset(string $staticRoot, string $pathname, string $method): bool
    {
        $rootReal = realpath($staticRoot);
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
        http_response_code(200);
        header('Content-Type: ' . $mime);
        header('Cache-Control: public, max-age=604800');
        if ($method !== 'HEAD') {
            readfile($target);
        }
        return true;
    }

    private static function serverAuthority(): string
    {
        $fwd = (string) ($_SERVER['HTTP_X_FORWARDED_HOST'] ?? '');
        if (trim($fwd) !== '') {
            return trim(explode(',', $fwd)[0]);
        }
        return trim((string) ($_SERVER['HTTP_HOST'] ?? 'localhost'));
    }

    private static function serverHost(): string
    {
        $host = rtrim(strtolower(self::serverAuthority()), '.');
        if (str_starts_with($host, '[')) {
            $end = strpos($host, ']');
            return $end !== false ? substr($host, 0, $end + 1) : $host;
        }
        $colon = strrpos($host, ':');
        if ($colon !== false && strpos($host, ':') === $colon) {
            $host = substr($host, 0, $colon);
        }
        return $host;
    }

    private static function serverPort(): string
    {
        $auth = self::serverAuthority();
        if (preg_match('/:([0-9]+)$/', $auth, $m)) {
            return $m[1];
        }
        $fwdPort = trim((string) ($_SERVER['HTTP_X_FORWARDED_PORT'] ?? ''));
        return preg_match('/^[0-9]+$/', $fwdPort) ? $fwdPort : '';
    }

    private static function serverProto(string $host): string
    {
        $cfVisitor = (string) ($_SERVER['HTTP_CF_VISITOR'] ?? '');
        if (str_contains($cfVisitor, '"https"')) {
            return 'https';
        }
        $fwdProto = (string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '');
        if ($fwdProto !== '') {
            $first = strtolower(trim(explode(',', $fwdProto)[0]));
            if ($first === 'https' || $first === 'http') {
                return $first;
            }
        }
        if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
            return 'https';
        }
        if ($host === 'localhost' || $host === '127.0.0.1' || $host === '::1') {
            return 'http';
        }
        return 'https';
    }

    private static function sendNotFound(): void
    {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
        echo 'Not Found';
    }

    /**
     * @param array<string, mixed> $payload
     */
    private static function sendJson(int $status, array $payload): void
    {
        $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        self::sendJsonRaw($status, $json !== false ? $json : '{}');
    }

    private static function sendJsonRaw(int $status, string $rawJson): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo $rawJson;
    }
}
