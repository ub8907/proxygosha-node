<?php

declare(strict_types=1);

namespace App;

use Workerman\Protocols\Http\Request;

/**
 * 运行时配置解析、.env 加载、域名白名单、Token 签发校验与 Bridge 模式认证
 */
final class Config
{
    /** @var array<string, string> */
    private static array $dotEnv = [];

    /** @var array<string, string>|null */
    private static ?array $runtimeOverrideEnv = null;

    /** @var array<string, mixed>|null */
    private static ?array $cachedRuntime = null;

    private static ?string $cachedKey = null;

    private static string $runtimeFile = '';
    private static ?string $runtimeFileHash = null;
    private static bool $runtimePersisted = false;

    public static function setRuntimeFile(string $filePath): void
    {
        self::$runtimeFile = $filePath;
        self::reloadRuntimeFileIfChanged();
    }

    public static function reloadRuntimeFileIfChanged(): void
    {
        if (self::$runtimeFile === '') {
            return;
        }
        clearstatcache(true, self::$runtimeFile);
        if (!is_file(self::$runtimeFile)) {
            if (self::$runtimeFileHash !== null) {
                self::$runtimeFileHash = null;
                self::$runtimePersisted = false;
                self::$runtimeOverrideEnv = null;
                self::$cachedRuntime = null;
                self::$cachedKey = null;
            }
            return;
        }
        $raw = @file_get_contents(self::$runtimeFile);
        if (!is_string($raw)) {
            return;
        }
        $hash = strlen($raw) . ':' . substr(sha1($raw), 0, 16);
        if ($hash === self::$runtimeFileHash) {
            return;
        }
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $clean = [];
            foreach ($decoded as $k => $v) {
                if (is_string($k) && is_string($v)) {
                    $clean[$k] = $v;
                }
            }
            self::$runtimeOverrideEnv = $clean;
            self::$runtimeFileHash = $hash;
            self::$runtimePersisted = true;
            self::$cachedRuntime = null;
            self::$cachedKey = null;
        }
    }

    /**
     * @param array<string, string> $override
     */
    public static function saveRuntimeOverride(array $override): bool
    {
        self::setRuntimeOverride($override);
        if (self::$runtimeFile === '') {
            return false;
        }
        $dir = dirname(self::$runtimeFile);
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        $json = json_encode($override, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            return false;
        }
        $payload = $json . "\n";
        $ok = @file_put_contents(self::$runtimeFile, $payload, LOCK_EX) !== false;
        if ($ok) {
            @chmod(self::$runtimeFile, 0600);
            clearstatcache(true, self::$runtimeFile);
            self::$runtimeFileHash = strlen($payload) . ':' . substr(sha1($payload), 0, 16);
            self::$runtimePersisted = true;
        } else {
            self::$runtimePersisted = false;
        }
        return $ok;
    }

    public static function resetRuntimeOverride(): bool
    {
        self::$runtimeOverrideEnv = null;
        self::$runtimeFileHash = null;
        self::$runtimePersisted = false;
        self::$cachedRuntime = null;
        self::$cachedKey = null;
        if (self::$runtimeFile !== '' && is_file(self::$runtimeFile)) {
            return @unlink(self::$runtimeFile);
        }
        return true;
    }

    /**
     * 加载项目根目录 .env 文件（不覆盖进程外部已显式设置的环境变量）
     */
    public static function loadDotEnv(string $filePath): void
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            return;
        }
        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            return;
        }
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                continue;
            }
            if (str_starts_with($trimmed, 'export ')) {
                $trimmed = trim(substr($trimmed, 7));
            }
            $eqPos = strpos($trimmed, '=');
            if ($eqPos === false || $eqPos === 0) {
                continue;
            }
            $key = trim(substr($trimmed, 0, $eqPos));
            $val = trim(substr($trimmed, $eqPos + 1));

            // 去除首尾成对引号或行尾注释
            if (
                (str_starts_with($val, '"') && str_ends_with($val, '"') && strlen($val) >= 2) ||
                (str_starts_with($val, "'") && str_ends_with($val, "'") && strlen($val) >= 2)
            ) {
                $val = substr($val, 1, -1);
            } else {
                $hashPos = strpos($val, ' #');
                if ($hashPos !== false) {
                    $val = trim(substr($val, 0, $hashPos));
                }
            }

            self::$dotEnv[$key] = $val;
        }
    }

    public static function env(string $key, string $default = '', bool $ignoreOverride = false): string
    {
        if (!$ignoreOverride && self::$runtimeOverrideEnv !== null && array_key_exists($key, self::$runtimeOverrideEnv)) {
            return self::$runtimeOverrideEnv[$key];
        }
        $sys = getenv($key);
        if ($sys !== false) {
            return (string) $sys;
        }
        if (isset($_ENV[$key])) {
            return (string) $_ENV[$key];
        }
        if (array_key_exists($key, self::$dotEnv)) {
            return self::$dotEnv[$key];
        }
        return $default;
    }

    /**
     * @param array<string, string>|null $override
     */
    public static function setRuntimeOverride(?array $override): void
    {
        self::$runtimeOverrideEnv = $override;
        self::$runtimePersisted = false;
        self::$cachedRuntime = null;
        self::$cachedKey = null;
    }

    public static function isEphemeralSetup(): bool
    {
        return self::$runtimeOverrideEnv !== null && !self::$runtimePersisted;
    }

    public static function isRuntimePersisted(): bool
    {
        return self::$runtimePersisted;
    }

    public static function hasRuntimeOverride(): bool
    {
        return self::$runtimeOverrideEnv !== null;
    }

    public static function hasBaseEnvRuntime(): bool
    {
        return self::buildRuntime(self::resolveConfig(true)) !== null;
    }

    /**
     * @return array<string, mixed>
     */
    public static function resolveConfig(bool $ignoreOverride = false): array
    {
        $secretHex = trim(self::env('SECRET', '', $ignoreOverride));
        $adTagHex = trim(self::env('AD_TAG', '', $ignoreOverride));
        $debugVal = strtolower(trim(self::env('DEBUG', 'false', $ignoreOverride)));
        $debug = $debugVal === 'true' || $debugVal === '1';
        $decoyUrl = trim(self::env('DECOY_URL', '', $ignoreOverride));

        $allowedEnv = trim(self::env('ALLOWED_HOSTS', '', $ignoreOverride));
        $rawHostnames = $allowedEnv !== '' ? $allowedEnv : trim(self::env('HOSTNAME', '', $ignoreOverride));

        $hostnames = [];
        if ($rawHostnames !== '') {
            foreach (explode(',', $rawHostnames) as $item) {
                $h = strtolower(trim($item));
                // 忽略 Linux/Docker 自动导出的无点号裸主机名（如 container_id、lsd-ProgramNoodle），仅保留 * 或真实域名
                if ($h === '*' || str_contains($h, '.')) {
                    $hostnames[] = $h;
                }
            }
        }
        if (empty($hostnames)) {
            $hostnames = Constants::DEFAULT_HOSTNAMES;
        }

        $parsedStreams = self::env('MAX_STREAMS', '', $ignoreOverride);
        $maxStreams = is_numeric($parsedStreams)
            ? min(64, max(1, (int) $parsedStreams))
            : Constants::DEFAULT_MAX_STREAMS;

        $sessionPath = trim(self::env('SESSION_PATH', '', $ignoreOverride));
        if ($sessionPath === '') {
            $sessionPath = Constants::DEFAULT_SESSION_PATH;
        } elseif (!str_starts_with($sessionPath, '/')) {
            $sessionPath = '/' . $sessionPath;
        }

        $wsPath = trim(self::env('WS_PATH', '', $ignoreOverride));
        if ($wsPath === '') {
            $wsPath = Constants::DEFAULT_WS_PATH;
        } elseif (!str_starts_with($wsPath, '/')) {
            $wsPath = '/' . $wsPath;
        }

        $adminKey = trim(self::env('ADMIN_KEY', '', $ignoreOverride));

        $extraHosts = [];
        $rawExtra = self::env('EXTRA_HOSTS', '', $ignoreOverride);
        if ($rawExtra !== '') {
            $parts = preg_split('/[,\s]+/', $rawExtra) ?: [];
            foreach ($parts as $val) {
                $clean = strtolower(trim($val));
                $clean = preg_replace('/^https?:\/\//', '', $clean) ?? $clean;
                $clean = preg_replace('/[:\/].*$/', '', $clean) ?? $clean;
                $clean = rtrim($clean, '.');
                if ($clean !== '' && preg_match('/^[a-z0-9.-]+$/', $clean) && !str_contains($clean, '..')) {
                    $extraHosts[] = $clean;
                }
            }
        }

        $carrierEnv = strtolower(trim(self::env('CARRIER', '', $ignoreOverride)));
        $carrier = ($carrierEnv === 'websocket' || $carrierEnv === 'websocket-lanes')
            ? $carrierEnv
            : Constants::DEFAULT_CARRIER;

        $dcPorts = Constants::DEFAULT_DC_PORTS;
        $rawDcPorts = trim(self::env('DC_PORTS', '', $ignoreOverride));
        if ($rawDcPorts !== '') {
            $parsed = [];
            foreach (preg_split('/[,\s]+/', $rawDcPorts) ?: [] as $p) {
                $num = (int) trim($p);
                if ($num >= 1 && $num <= 65535) {
                    $parsed[] = $num;
                }
            }
            if (!empty($parsed)) {
                $dcPorts = $parsed;
            }
        }

        $genEnabledRaw = strtolower(trim(self::env('GENERATOR_ENABLED', 'false', $ignoreOverride)));
        $acceptGenRaw = strtolower(trim(self::env('ACCEPT_GENERATED', 'false', $ignoreOverride)));

        return [
            'secretHex' => $secretHex,
            'adminKey' => $adminKey,
            'extraHosts' => $extraHosts,
            'adTagHex' => $adTagHex,
            'debug' => $debug,
            'hostnames' => $hostnames,
            'decoyUrl' => $decoyUrl,
            'maxStreams' => $maxStreams,
            'sessionPath' => $sessionPath,
            'wsPath' => $wsPath,
            'generatorEnabled' => $genEnabledRaw === 'true' || $genEnabledRaw === '1',
            'generatorKey' => trim(self::env('GENERATOR_KEY', '', $ignoreOverride)),
            'acceptGenerated' => $acceptGenRaw === 'true' || $acceptGenRaw === '1',
            'dc' => Constants::DEFAULT_DC_MAP,
            'dcPort' => $dcPorts[0] ?? 443,
            'dcPorts' => $dcPorts,
            'carrier' => $carrier,
            'batchBytes' => Constants::DEFAULT_BATCH_BYTES,
            'bootstrapTtl' => Constants::DEFAULT_BOOTSTRAP_TTL,
            'sessionTtl' => Constants::DEFAULT_SESSION_TTL,
            'maxQueued' => Constants::DEFAULT_MAX_QUEUED,
            'streamWindow' => Constants::DEFAULT_STREAM_WINDOW,
            'dataChunk' => Constants::DEFAULT_DATA_CHUNK,
            'ephemeralSetup' => self::$runtimeOverrideEnv !== null,
        ];
    }

    /**
     * @param array<string, mixed> $cfg
     * @return array<string, mixed>|null
     */
    public static function buildRuntime(array $cfg): ?array
    {
        $adminKey = strlen((string) $cfg['adminKey']) >= 16 ? (string) $cfg['adminKey'] : '';
        $seal = Crypto::unseal();
        $base = Crypto::parseSecret((string) $cfg['secretHex']);
        $secretDerived = $base === null && $adminKey !== '';

        if ($secretDerived) {
            $base = substr(
                Crypto::sha256("proxygosha-secret-from-admin-v2\n" . $seal['bytes'] . "\n" . $adminKey),
                0,
                16
            );
        }

        $generatorText = trim((string) ($cfg['generatorKey'] ?? ''));
        if ($base === null && $generatorText === '') {
            return null;
        }

        $fallback = $base ?? Crypto::sha256("tgweb-fallback-v1\0" . $generatorText);
        $generatorRaw = $generatorText !== ''
            ? Crypto::sha256("tgweb-generator-v1\0" . $generatorText)
            : $base;

        $bridgeKeys = [];
        if ($base !== null) {
            $bridgeKeys[] = $base;
            $bridgeKeys[] = "\xdd" . $base;
        }

        $portSecrets = [];
        if ($base !== null) {
            foreach (Constants::HTTPS_PORTS as $p) {
                $sBytes = $p === 443
                    ? $base
                    : substr(Crypto::sha256("proxygosha-port-secret-v1\n" . $base . "\n" . $p), 0, 16);
                $portSecrets[$p] = [
                    'secret' => $sBytes,
                    'secretHex' => 'dd' . bin2hex($sBytes),
                    'keys' => [$sBytes, "\xdd" . $sBytes],
                ];
            }
        }

        $tokenKey = Crypto::sha256("tgweb-token-key-v1\0" . $seal['bytes'] . $fallback);
        $adTag = Crypto::parseAdTag((string) $cfg['adTagHex']);

        return [
            'base' => $base,
            'portSecrets' => $portSecrets,
            'adminKey' => $adminKey,
            'secretDerived' => $secretDerived,
            'extraHosts' => $cfg['extraHosts'],
            'bridgeKeys' => $bridgeKeys,
            'generatorKeyBytes' => $generatorRaw,
            'tokenKey' => $tokenKey,
            'hosts' => $cfg['hostnames'],
            'dc' => $cfg['dc'],
            'dcPort' => $cfg['dcPort'],
            'dcPorts' => $cfg['dcPorts'],
            'adTag' => $adTag,
            'adTagHex' => $cfg['adTagHex'],
            'debug' => $cfg['debug'],
            'decoyUrl' => $cfg['decoyUrl'],
            'sessionPath' => $cfg['sessionPath'],
            'wsPath' => $cfg['wsPath'],
            'acceptGenerated' => $cfg['acceptGenerated'],
            'generatorEnabled' => $cfg['generatorEnabled'],
            'streamWindow' => $cfg['streamWindow'],
            'maxQueued' => $cfg['maxQueued'],
            'maxStreams' => $cfg['maxStreams'],
            'dataChunk' => $cfg['dataChunk'],
            'bootstrapTtl' => $cfg['bootstrapTtl'],
            'sessionTtl' => $cfg['sessionTtl'],
            'carrier' => $cfg['carrier'],
            'batchBytes' => $cfg['batchBytes'],
            'ephemeralSetup' => $cfg['ephemeralSetup'],
        ];
    }

    /**
     * @return array<string, mixed>|null
     */
    public static function getRuntime(): ?array
    {
        self::reloadRuntimeFileIfChanged();
        $resolved = self::resolveConfig();
        $cacheKey = implode(':', [
            $resolved['secretHex'],
            $resolved['generatorKey'],
            implode(',', $resolved['hostnames']),
            $resolved['adTagHex'],
            $resolved['decoyUrl'],
            $resolved['maxStreams'],
            $resolved['sessionPath'],
            $resolved['wsPath'],
            $resolved['debug'] ? '1' : '0',
            $resolved['carrier'],
            $resolved['acceptGenerated'] ? '1' : '0',
            $resolved['generatorEnabled'] ? '1' : '0',
            $resolved['adminKey'],
            implode(',', $resolved['extraHosts']),
            implode(',', $resolved['dcPorts']),
            $resolved['ephemeralSetup'] ? '1' : '0',
        ]);

        if (self::$cachedRuntime !== null && self::$cachedKey === $cacheKey) {
            return self::$cachedRuntime;
        }

        $runtime = self::buildRuntime($resolved);
        if ($runtime !== null) {
            self::$cachedRuntime = $runtime;
            self::$cachedKey = $cacheKey;
        }
        return $runtime;
    }

    public static function rawRequestAuthority(Request $req): string
    {
        $fwdHost = $req->header('x-forwarded-host');
        if (is_array($fwdHost)) {
            $fwdHost = $fwdHost[0] ?? '';
        }
        if (is_string($fwdHost) && trim($fwdHost) !== '') {
            $parts = explode(',', $fwdHost);
            return trim($parts[0]);
        }
        $host = $req->header('host', '');
        if (is_array($host)) {
            $host = $host[0] ?? '';
        }
        return trim((string) $host);
    }

    public static function requestHost(Request $req): string
    {
        $host = strtolower(self::rawRequestAuthority($req));
        $host = rtrim($host, '.');
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

    public static function requestPort(Request $req): string
    {
        $authority = self::rawRequestAuthority($req);
        if (preg_match('/:([0-9]+)$/', $authority, $m)) {
            return $m[1];
        }
        $fwdPort = $req->header('x-forwarded-port', '');
        if (is_array($fwdPort)) {
            $fwdPort = $fwdPort[0] ?? '';
        }
        $fwdPort = trim((string) $fwdPort);
        if ($fwdPort !== '' && preg_match('/^[0-9]+$/', $fwdPort)) {
            return $fwdPort;
        }
        return '';
    }

    public static function requestProto(Request $req): string
    {
        $cfVisitor = $req->header('cf-visitor', '');
        if (is_string($cfVisitor) && str_contains($cfVisitor, '"https"')) {
            return 'https';
        }
        $fwdProto = $req->header('x-forwarded-proto', '');
        if (is_array($fwdProto)) {
            $fwdProto = $fwdProto[0] ?? '';
        }
        if (is_string($fwdProto) && $fwdProto !== '') {
            $first = strtolower(trim(explode(',', $fwdProto)[0]));
            if ($first === 'https' || $first === 'http') {
                return $first;
            }
        }
        $host = self::requestHost($req);
        if ($host === 'localhost' || $host === '127.0.0.1' || $host === '::1') {
            return 'http';
        }
        return 'https';
    }

    /**
     * @param array<string, mixed> $cfg
     */
    public static function hostAllowed(array $cfg, string $host): bool
    {
        if (!preg_match('/^[a-z0-9.-]+$/', $host) || str_contains($host, '..')) {
            return false;
        }
        $hosts = $cfg['hosts'];
        if (
            empty($hosts) ||
            in_array('*', $hosts, true) ||
            (count($hosts) === 1 && $hosts[0] === 'proxy.example.com')
        ) {
            return true;
        }
        return in_array($host, $hosts, true) || in_array($host, $cfg['extraHosts'], true);
    }

    /**
     * @param array<string, mixed> $cfg
     */
    public static function deriveSecret(array $cfg, string $label): ?string
    {
        if (empty($cfg['generatorKeyBytes'])) {
            return null;
        }
        $mac = Crypto::hmacSha256((string) $cfg['generatorKeyBytes'], "tgweb-secret-v1\n" . $label);
        return substr($mac, 0, 16);
    }

    /**
     * @param array<string, mixed> $cfg
     * @param string[] $extraHeaderHosts
     */
    public static function bridgeMode(array $cfg, string $host, string $capability, string $port, array $extraHeaderHosts = []): int
    {
        $provided = Crypto::b64uDecodeStrict($capability);
        if ($provided === null || strlen($provided) !== 32) {
            return -1;
        }

        // 合并待校验域名：当前请求 Host + X-Original-Host/原始 Host + EXTRA_HOSTS + 白名单具体域名（适配 CDN 回源重写 Host 的加速域名场景）
        $baseHosts = [];
        $pushHost = static function (string $h) use (&$baseHosts): void {
            $clean = strtolower(trim($h));
            $clean = rtrim($clean, '.');
            $clean = (string) preg_replace('/:[0-9]+$/', '', $clean);
            if ($clean !== '' && $clean !== '*' && $clean !== 'proxy.example.com' && !in_array($clean, $baseHosts, true)) {
                $baseHosts[] = $clean;
            }
        };
        $pushHost($host);
        foreach ($extraHeaderHosts as $h) {
            $pushHost((string) $h);
        }
        foreach ($cfg['extraHosts'] as $h) {
            $pushHost((string) $h);
        }
        foreach ($cfg['hosts'] as $h) {
            $pushHost((string) $h);
        }

        $incomingPort = $port !== '' ? (int) $port : 443;
        $knownIdx = array_search($incomingPort, Constants::HTTPS_PORTS, true);

        foreach ($baseHosts as $candidateHost) {
            if ($knownIdx !== false && isset($cfg['portSecrets'][$incomingPort])) {
                $pKeys = $cfg['portSecrets'][$incomingPort]['keys'];
                $contexts = $incomingPort === 443
                    ? ["tdesktop-web-proxy-bridge-v1\n" . $candidateHost]
                    : [
                        "tdesktop-web-proxy-bridge-v1\n{$candidateHost}:{$incomingPort}",
                        "tdesktop-web-proxy-bridge-v1\n" . $candidateHost,
                    ];
                foreach ($contexts as $ctx) {
                    foreach ($pKeys as $key) {
                        if (Crypto::hmacVerify($key, $provided, $ctx)) {
                            return Constants::PORT_MODE_BASE + (int) $knownIdx;
                        }
                    }
                }
            }
        }

        $candidateHosts = [];
        $candidatePorts = [];
        if ($port !== '' && $port !== '443' && $port !== '80') {
            $candidatePorts[] = $port;
        }
        foreach (Constants::HTTPS_PORTS as $p) {
            if ($p !== 443 && !in_array((string) $p, $candidatePorts, true)) {
                $candidatePorts[] = (string) $p;
            }
        }
        foreach ($baseHosts as $h) {
            $candidateHosts[] = $h;
            foreach ($candidatePorts as $p) {
                $candidateHosts[] = "{$h}:{$p}";
            }
        }

        foreach ($candidateHosts as $h) {
            $context = "tdesktop-web-proxy-bridge-v1\n" . $h;
            foreach ($cfg['bridgeKeys'] as $key) {
                if (Crypto::hmacVerify($key, $provided, $context)) {
                    return Constants::PORT_MODE_BASE;
                }
            }
        }

        if (!empty($cfg['portSecrets'])) {
            foreach ($baseHosts as $candidateHost) {
                foreach (Constants::HTTPS_PORTS as $idx => $p) {
                    if ($p === $incomingPort && $candidateHost === $host) {
                        continue;
                    }
                    $pKeys = $cfg['portSecrets'][$p]['keys'] ?? null;
                    if (!$pKeys) {
                        continue;
                    }
                    $contexts = [
                        "tdesktop-web-proxy-bridge-v1\n{$candidateHost}:{$p}",
                        "tdesktop-web-proxy-bridge-v1\n" . $candidateHost,
                    ];
                    foreach ($contexts as $ctx) {
                        foreach ($pKeys as $key) {
                            if (Crypto::hmacVerify($key, $provided, $ctx)) {
                                if ($port === '' || $port === '443' || $port === (string) $p) {
                                    return Constants::PORT_MODE_BASE + $idx;
                                }
                            }
                        }
                    }
                }
            }
        }

        if (!empty($cfg['acceptGenerated'])) {
            foreach ($candidateHosts as $h) {
                $context = "tdesktop-web-proxy-bridge-v1\n" . $h;
                $secret = self::deriveSecret($cfg, $h);
                if ($secret !== null && Crypto::hmacVerify($secret, $provided, $context)) {
                    return str_contains($h, ':') ? 2 : 1;
                }
            }
        }

        return -1;
    }

    /**
     * @param array<string, mixed> $cfg
     */
    public static function issueToken(array $cfg, int $kind, int $ttl, int $mode): string
    {
        $expires = time() + $ttl;
        $modeByte = ($mode >= 0 && $mode <= 255) ? $mode : 0;
        $nonce = pack('NC', $expires, $modeByte) . random_bytes(11);
        $mac = Crypto::hmacSha256(
            (string) $cfg['tokenKey'],
            Constants::TOKEN_DOMAIN . chr($kind) . $nonce
        );
        return Crypto::b64uEncode($nonce . $mac);
    }

    /**
     * @param array<string, mixed> $cfg
     * @return array{nonce: string, mode: int}|null
     */
    public static function verifyToken(array $cfg, string $token, int $kind): ?array
    {
        $raw = Crypto::b64uDecodeStrict($token);
        if ($raw === null || strlen($raw) !== 48) {
            return null;
        }
        $nonce = substr($raw, 0, 16);
        $mac = substr($raw, 16);
        if (!Crypto::hmacVerify((string) $cfg['tokenKey'], $mac, Constants::TOKEN_DOMAIN . chr($kind) . $nonce)) {
            return null;
        }
        $unpacked = unpack('Nexpires/Cmode', substr($nonce, 0, 5));
        if (!is_array($unpacked) || $unpacked['expires'] < time()) {
            return null;
        }
        return [
            'nonce' => $nonce,
            'mode' => (int) $unpacked['mode'],
        ];
    }

    /**
     * 原样解析 Query 参数（避免 PHP parse_str 将 "." / "-" 替换为 "_"，并保留重名参数统计）
     *
     * @return array{keys: string[], map: array<string, string[]>}
     */
    public static function parseRawQuery(string $queryString): array
    {
        $keys = [];
        $map = [];
        if ($queryString === '') {
            return ['keys' => [], 'map' => []];
        }
        foreach (explode('&', $queryString) as $pair) {
            if ($pair === '') {
                continue;
            }
            $eq = strpos($pair, '=');
            if ($eq === false) {
                $k = urldecode($pair);
                $v = '';
            } else {
                $k = urldecode(substr($pair, 0, $eq));
                $v = urldecode(substr($pair, $eq + 1));
            }
            $keys[] = $k;
            $map[$k] ??= [];
            $map[$k][] = $v;
        }
        return ['keys' => $keys, 'map' => $map];
    }

    /**
     * @param array<string, mixed> $cfg
     * @param array<string, string[]> $queryMap
     */
    public static function generatorLabel(array $queryMap): ?string
    {
        foreach (['--create-secret', 'create-secret', 'create_secret'] as $k) {
            if (array_key_exists($k, $queryMap)) {
                return $queryMap[$k][0] ?? '';
            }
        }
        return null;
    }

    /**
     * @param array<string, mixed> $cfg
     * @param array<string, string[]> $queryMap
     */
    public static function panelRoute(string $pathname, array $queryMap, array $cfg): ?string
    {
        $adminKey = (string) ($cfg['adminKey'] ?? '');
        if ($adminKey === '') {
            return null;
        }
        $path = rawurldecode(substr($pathname, 1));
        $path = rtrim($path, '/');

        if ($path !== '' && Crypto::safeEqual($path, $adminKey)) {
            return 'panel';
        }
        if ($path !== '' && Crypto::safeEqual($path, $adminKey . '/status')) {
            return 'status';
        }
        if ($path !== '' && Crypto::safeEqual($path, $adminKey . '/config')) {
            return 'config';
        }
        if ($path !== '' && Crypto::safeEqual($path, $adminKey . '/api/state')) {
            return 'api-state';
        }
        if ($path !== '' && Crypto::safeEqual($path, $adminKey . '/api/probe')) {
            return 'api-probe';
        }
        if ($path !== '' && Crypto::safeEqual($path, $adminKey . '/api/config')) {
            return 'api-config';
        }
        $keyParam = $queryMap['key'][0] ?? '';
        if (self::generatorLabel($queryMap) === '' && Crypto::safeEqual($keyParam, $adminKey)) {
            return 'panel';
        }
        return null;
    }

    /**
     * @param array<string, mixed> $body
     * @param array<string, mixed> $currentCfg
     * @return array{ok: true, override: array<string, string>}|array{ok: false, error: string}
     */
    public static function buildOverrideFromConfigInput(array $body, array $currentCfg): array
    {
        $currentResolved = self::resolveConfig();

        $adminKeyRaw = is_string($body['adminKey'] ?? null)
            ? trim((string) $body['adminKey'])
            : (string) $currentCfg['adminKey'];
        if (strlen($adminKeyRaw) < 16 || !preg_match('/^[A-Za-z0-9_-]+$/', $adminKeyRaw)) {
            return ['ok' => false, 'error' => 'ADMIN_KEY must be at least 16 characters (letters, digits, - or _).'];
        }

        $secretHex = (string) $currentResolved['secretHex'];
        $secretAction = is_string($body['secretAction'] ?? null) ? $body['secretAction'] : 'keep';
        if ($secretAction === 'derive') {
            $secretHex = '';
        } elseif ($secretAction === 'set') {
            $rawSecret = is_string($body['secret'] ?? null) ? trim((string) $body['secret']) : '';
            if (Crypto::parseSecret($rawSecret) === null) {
                return ['ok' => false, 'error' => 'SECRET must be 32 hex chars or dd + 32 hex chars.'];
            }
            $secretHex = strtolower($rawSecret);
        }

        $carrier = (($body['carrier'] ?? '') === 'websocket' || ($body['carrier'] ?? '') === 'websocket-lanes')
            ? (string) $body['carrier']
            : (string) $currentCfg['carrier'];

        $rawMaxStreams = $body['maxStreams'] ?? $currentCfg['maxStreams'];
        if (!is_numeric($rawMaxStreams)) {
            return ['ok' => false, 'error' => 'MAX_STREAMS must be an integer between 1 and 64.'];
        }
        $maxStreamsNum = (int) $rawMaxStreams;
        if ($maxStreamsNum < 1 || $maxStreamsNum > 64) {
            return ['ok' => false, 'error' => 'MAX_STREAMS must be an integer between 1 and 64.'];
        }

        $allowedRaw = is_string($body['allowedHosts'] ?? null)
            ? (string) $body['allowedHosts']
            : implode(', ', $currentCfg['hosts']);
        $allowedList = [];
        foreach (preg_split('/[,\s]+/', $allowedRaw) ?: [] as $item) {
            $clean = strtolower(trim($item));
            $clean = preg_replace('/^https?:\/\//', '', $clean) ?? $clean;
            $clean = preg_replace('/[:\/].*$/', '', $clean) ?? $clean;
            $clean = rtrim($clean, '.');
            if ($clean === '') {
                continue;
            }
            if ($clean !== '*' && (!preg_match('/^[a-z0-9.-]+$/', $clean) || str_contains($clean, '..') || !str_contains($clean, '.'))) {
                return ['ok' => false, 'error' => "Invalid ALLOWED_HOSTS entry: {$clean}"];
            }
            if (!in_array($clean, $allowedList, true)) {
                $allowedList[] = $clean;
            }
        }
        $allowedHostsStr = !empty($allowedList) ? implode(',', $allowedList) : '*';

        $extraRaw = is_string($body['extraHosts'] ?? null)
            ? (string) $body['extraHosts']
            : implode(', ', $currentCfg['extraHosts']);
        $extraList = [];
        foreach (preg_split('/[,\s]+/', $extraRaw) ?: [] as $item) {
            $clean = strtolower(trim($item));
            $clean = preg_replace('/^https?:\/\//', '', $clean) ?? $clean;
            $clean = preg_replace('/[:\/].*$/', '', $clean) ?? $clean;
            $clean = rtrim($clean, '.');
            if ($clean === '') {
                continue;
            }
            if (!preg_match('/^[a-z0-9.-]+$/', $clean) || str_contains($clean, '..')) {
                return ['ok' => false, 'error' => "Invalid EXTRA_HOSTS entry: {$clean}"];
            }
            if (!in_array($clean, $extraList, true)) {
                $extraList[] = $clean;
            }
        }
        $extraHostsStr = implode(',', $extraList);

        $decoyUrlRaw = is_string($body['decoyUrl'] ?? null)
            ? trim((string) $body['decoyUrl'])
            : (string) $currentCfg['decoyUrl'];
        if ($decoyUrlRaw !== '') {
            if (!preg_match('/^https?:\/\/.+/i', $decoyUrlRaw) || filter_var($decoyUrlRaw, FILTER_VALIDATE_URL) === false) {
                return ['ok' => false, 'error' => 'DECOY_URL must be a valid http:// or https:// URL, or empty.'];
            }
        }

        $sessionPath = is_string($body['sessionPath'] ?? null)
            ? trim((string) $body['sessionPath'])
            : (string) $currentCfg['sessionPath'];
        if ($sessionPath === '') {
            $sessionPath = '/api/v1/session';
        } elseif (!str_starts_with($sessionPath, '/')) {
            $sessionPath = '/' . $sessionPath;
        }
        if (!preg_match('#^/[A-Za-z0-9/_-]+$#', $sessionPath)) {
            return ['ok' => false, 'error' => 'SESSION_PATH contains invalid characters.'];
        }

        $wsPath = is_string($body['wsPath'] ?? null)
            ? trim((string) $body['wsPath'])
            : (string) $currentCfg['wsPath'];
        if ($wsPath === '') {
            $wsPath = '/api/v1/ws';
        } elseif (!str_starts_with($wsPath, '/')) {
            $wsPath = '/' . $wsPath;
        }
        if (!preg_match('#^/[A-Za-z0-9/_-]+$#', $wsPath)) {
            return ['ok' => false, 'error' => 'WS_PATH contains invalid characters.'];
        }
        if ($wsPath === $sessionPath) {
            return ['ok' => false, 'error' => 'WS_PATH and SESSION_PATH must be different.'];
        }

        $dcPortsRaw = is_string($body['dcPorts'] ?? null)
            ? (string) $body['dcPorts']
            : implode(',', $currentCfg['dcPorts']);
        $dcPortsList = [];
        foreach (preg_split('/[,\s]+/', $dcPortsRaw) ?: [] as $p) {
            $pTrim = trim($p);
            if ($pTrim === '' || !ctype_digit($pTrim)) {
                continue;
            }
            $num = (int) $pTrim;
            if ($num >= 1 && $num <= 65535 && !in_array($num, $dcPortsList, true)) {
                $dcPortsList[] = $num;
            }
        }
        if (empty($dcPortsList)) {
            return ['ok' => false, 'error' => 'DC_PORTS must contain at least one valid port (1–65535).'];
        }
        $dcPortsStr = implode(',', $dcPortsList);

        $adTagHex = (string) $currentResolved['adTagHex'];
        $adTagAction = is_string($body['adTagAction'] ?? null) ? $body['adTagAction'] : 'keep';
        if ($adTagAction === 'clear') {
            $adTagHex = '';
        } elseif ($adTagAction === 'set') {
            $rawTag = is_string($body['adTag'] ?? null) ? trim((string) $body['adTag']) : '';
            if (Crypto::parseAdTag($rawTag) === null) {
                return ['ok' => false, 'error' => 'AD_TAG must be exactly 32 hexadecimal characters.'];
            }
            $adTagHex = strtolower($rawTag);
        }

        $debugFlag = is_bool($body['debug'] ?? null) ? (bool) $body['debug'] : !empty($currentCfg['debug']);
        $generatorEnabled = is_bool($body['generatorEnabled'] ?? null) ? (bool) $body['generatorEnabled'] : !empty($currentCfg['generatorEnabled']);
        $acceptGenerated = is_bool($body['acceptGenerated'] ?? null) ? (bool) $body['acceptGenerated'] : !empty($currentCfg['acceptGenerated']);

        return [
            'ok' => true,
            'override' => [
                'ADMIN_KEY' => $adminKeyRaw,
                'SECRET' => $secretHex,
                'CARRIER' => $carrier,
                'MAX_STREAMS' => (string) $maxStreamsNum,
                'ALLOWED_HOSTS' => $allowedHostsStr,
                'EXTRA_HOSTS' => $extraHostsStr,
                'DECOY_URL' => $decoyUrlRaw,
                'SESSION_PATH' => $sessionPath,
                'WS_PATH' => $wsPath,
                'DC_PORTS' => $dcPortsStr,
                'AD_TAG' => $adTagHex,
                'DEBUG' => $debugFlag ? 'true' : 'false',
                'GENERATOR_ENABLED' => $generatorEnabled ? 'true' : 'false',
                'ACCEPT_GENERATED' => $acceptGenerated ? 'true' : 'false',
            ],
        ];
    }
}
