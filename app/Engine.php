<?php

declare(strict_types=1);

namespace App;

use Workerman\Connection\AsyncTcpConnection;
use Workerman\Connection\TcpConnection;
use Workerman\Protocols\Http\Request;
use Workerman\Timer;

/**
 * Workerman 异步 WebSocket + Telegram DC 代理引擎与真实 MTProto DC 探测器
 */
final class Engine
{
    /** @var array<int, WsSession> 按 spl_object_id($connection) 索引的活跃 WS 会话 */
    private static array $sessions = [];

    public static function handleUpgrade(TcpConnection $connection, Request $req, ?array $cfg): void
    {
        if ($cfg === null) {
            self::rejectUpgrade($connection, 404);
            return;
        }

        $pathname = $req->path();
        if ($pathname !== $cfg['wsPath'] && $pathname !== '/api/v1/ws') {
            self::rejectUpgrade($connection, 404);
            return;
        }

        $host = Config::requestHost($req);
        $port = Config::requestPort($req);
        Tunnel::recordTunnelHeaders($req, $host);

        if (!Config::hostAllowed($cfg, $host)) {
            Telemetry::$wsRejects++;
            Telemetry::logEvent('ws_reject', "host={$host} reason=host_not_allowed");
            self::rejectUpgrade($connection, 404);
            return;
        }

        if (strtoupper($req->method()) !== 'GET') {
            Telemetry::$wsRejects++;
            Telemetry::logEvent('ws_reject', "method={$req->method()} reason=bad_method");
            self::rejectUpgrade($connection, 404);
            return;
        }

        if ((string) $req->header('authorization', '') !== '') {
            Telemetry::$wsRejects++;
            Telemetry::logEvent('ws_reject', 'reason=unexpected_auth_header');
            self::rejectUpgrade($connection, 404);
            return;
        }

        $wsKey = trim((string) $req->header('sec-websocket-key', ''));
        if ($wsKey === '') {
            Telemetry::$wsRejects++;
            Telemetry::logEvent('ws_reject', 'reason=missing_ws_key');
            self::rejectUpgrade($connection, 400, 'Bad Request');
            return;
        }

        $rawProtocols = $req->header('sec-websocket-protocol', '');
        if (is_array($rawProtocols)) {
            $rawProtocols = implode(',', $rawProtocols);
        }
        $offered = array_values(array_filter(
            array_map('trim', explode(',', (string) $rawProtocols)),
            static fn (string $v): bool => $v !== ''
        ));

        if (count($offered) !== 1) {
            Telemetry::$wsRejects++;
            Telemetry::logEvent('ws_reject', 'reason=bad_protocol_count(' . count($offered) . ')');
            self::rejectUpgrade($connection, 404);
            return;
        }

        $protocol = $offered[0];
        $token = '';
        $laneId = 0;

        if (str_starts_with($protocol, 'tproxy-v1.')) {
            $token = substr($protocol, 10);
        } elseif (str_starts_with($protocol, 'tproxy-lane-v1.')) {
            $rest = substr($protocol, 15);
            $dot = strrpos($rest, '.');
            if ($dot === false || $dot <= 0 || !preg_match('/^[1-9][0-9]{0,7}$/', substr($rest, $dot + 1))) {
                Telemetry::$wsRejects++;
                Telemetry::logEvent('ws_reject', 'reason=invalid_lane_id');
                self::rejectUpgrade($connection, 404);
                return;
            }
            $token = substr($rest, 0, $dot);
            $laneId = (int) substr($rest, $dot + 1);
            if ($laneId > 0xffffff) {
                Telemetry::$wsRejects++;
                Telemetry::logEvent('ws_reject', 'reason=lane_overflow');
                self::rejectUpgrade($connection, 404);
                return;
            }
        } else {
            Telemetry::$wsRejects++;
            Telemetry::logEvent('ws_reject', 'reason=unknown_subprotocol');
            self::rejectUpgrade($connection, 404);
            return;
        }

        $verified = Config::verifyToken($cfg, $token, Constants::TOKEN_KIND_SESSION);
        if ($verified === null) {
            Telemetry::$wsRejects++;
            Telemetry::logEvent('ws_reject', 'reason=invalid_or_expired_token');
            self::rejectUpgrade($connection, 404);
            return;
        }

        $mode = $verified['mode'];
        if (($mode === 1 || $mode === 2) && empty($cfg['acceptGenerated'])) {
            Telemetry::$wsRejects++;
            Telemetry::logEvent('ws_reject', 'reason=generated_disabled');
            self::rejectUpgrade($connection, 404);
            return;
        }

        $secret = $cfg['base'] ?? null;
        if ($mode >= Constants::PORT_MODE_BASE && $mode < Constants::PORT_MODE_BASE + count(Constants::HTTPS_PORTS)) {
            $portNum = Constants::HTTPS_PORTS[$mode - Constants::PORT_MODE_BASE];
            $secret = $cfg['portSecrets'][$portNum]['secret'] ?? $secret;
        } elseif ($mode === 1 || $mode === 2) {
            $label = ($mode === 2 && $port !== '' && $port !== '443' && $port !== '80')
                ? "{$host}:{$port}"
                : $host;
            $secret = Config::deriveSecret($cfg, $label);
        }

        if (!is_string($secret) || $secret === '') {
            self::rejectUpgrade($connection, 404);
            return;
        }

        $acceptKey = base64_encode(sha1($wsKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
        $handshake = "HTTP/1.1 101 Switching Protocols\r\n"
            . "Upgrade: websocket\r\n"
            . "Connection: Upgrade\r\n"
            . "Sec-WebSocket-Accept: {$acceptKey}\r\n"
            . "Sec-WebSocket-Protocol: {$protocol}\r\n\r\n";

        HttpWsProtocol::markUpgraded($connection);
        $connection->maxSendBufferSize = 8388608;
        $connection->send($handshake, true);

        $connId = spl_object_id($connection);
        self::$sessions[$connId] = new WsSession($connection, $cfg, $secret, $laneId);
    }

    public static function onWsMessage(TcpConnection $connection, mixed $payload): void
    {
        $connId = spl_object_id($connection);
        $session = self::$sessions[$connId] ?? null;
        if ($session === null) {
            return;
        }

        if (!is_array($payload)) {
            $session->shutdown('invalid payload');
            return;
        }

        if (isset($payload['__ws_control'])) {
            if ($payload['__ws_control'] === 'close') {
                $session->dispose();
            }
            return;
        }

        if (!empty($payload['__ws_nonbinary'])) {
            $session->shutdown('non-binary');
            return;
        }

        if (!empty($payload['__ws_binary'])) {
            $session->handle((string) ($payload['data'] ?? ''));
        }
    }

    public static function onWsClose(TcpConnection $connection): void
    {
        $connId = spl_object_id($connection);
        $session = self::$sessions[$connId] ?? null;
        if ($session !== null) {
            unset(self::$sessions[$connId]);
            $session->dispose();
        }
    }

    public static function onWsError(TcpConnection $connection): void
    {
        self::onWsClose($connection);
    }

    public static function rejectUpgrade(TcpConnection $connection, int $status = 404, string $message = 'Not Found'): void
    {
        $reason = $status === 404 ? 'Not Found' : 'Bad Request';
        $len = strlen($message);
        $raw = "HTTP/1.1 {$status} {$reason}\r\n"
            . "Content-Type: text/plain; charset=utf-8\r\n"
            . "Content-Length: {$len}\r\n"
            . "Cache-Control: no-store\r\n"
            . "Connection: close\r\n\r\n{$message}";
        $connection->send($raw, true);
        $connection->close();
    }

    /**
     * 打包 ProxyGosha 8 字节协议帧
     */
    public static function packFrame(int $type, int $id, string $payload): string
    {
        return pack(
            'CCCCN',
            $type & 0xff,
            ($id >> 16) & 0xff,
            ($id >> 8) & 0xff,
            $id & 0xff,
            strlen($payload)
        ) . $payload;
    }

    public static function packWindowFrame(int $id, int $amount): string
    {
        return pack(
            'CCCCNN',
            0x04,
            ($id >> 16) & 0xff,
            ($id >> 8) & 0xff,
            $id & 0xff,
            4,
            $amount & 0xffffffff
        );
    }

    public static function tagKind(string $tag): int
    {
        if (strlen($tag) < 4) {
            return 0;
        }
        $four = substr($tag, 0, 4);
        if ($four === "\xef\xef\xef\xef") {
            return 1; // abridged
        }
        if ($four === "\xee\xee\xee\xee") {
            return 2; // intermediate
        }
        if ($four === "\xdd\xdd\xdd\xdd") {
            return 3; // padded intermediate
        }
        return 0;
    }

    public static function safeDcHeaderPrefix(string $bytes): bool
    {
        if (strlen($bytes) < 8) {
            return false;
        }
        $b0 = ord($bytes[0]);
        if ($b0 === 0xef) {
            return false;
        }
        if (substr($bytes, 4, 4) === "\x00\x00\x00\x00") {
            return false;
        }
        $head4 = substr($bytes, 0, 4);
        if (in_array($head4, ['GET ', 'POST', 'HEAD', 'OPTI', "\xee\xee\xee\xee", "\xdd\xdd\xdd\xdd", "\x16\x03\x01\x02"], true)) {
            return false;
        }
        return true;
    }

    /**
     * 非阻塞异步探测 Telegram DC1–DC5 及 DC203 的 TCP + 真实 Obfuscated2 MTProto 握手可达性
     *
     * @param array<string, mixed> $cfg
     * @param callable(array<int, array<string, mixed>>): void $onDone
     */
    public static function probeDcsAsync(array $cfg, callable $onDone): void
    {
        $keys = array_map('intval', array_keys($cfg['dc']));
        sort($keys);

        $configuredPorts = !empty($cfg['dcPorts']) ? $cfg['dcPorts'] : [443, 80, 5222];
        $probePort = (int) ($configuredPorts[0] ?? $cfg['dcPort'] ?? 443);
        $fallbackPorts = array_values(array_filter([443, 80, 5222], static fn (int $p): bool => $p !== $probePort));

        $results = [];
        $pending = count($keys);
        if ($pending === 0) {
            $onDone([]);
            return;
        }

        foreach ($keys as $dcKey) {
            $ips = $cfg['dc'][$dcKey];
            if (!is_array($ips)) {
                $ips = [$ips];
            }
            $ip = (string) $ips[array_rand($ips)];

            self::probeSingleDcAsync($dcKey, $ip, $probePort, static function (array $r) use (
                &$results,
                &$pending,
                $dcKey,
                $ip,
                $fallbackPorts,
                $onDone
            ): void {
                // 若主端口 TCP 可达但 MTProto 握手被断开，自动并发探测 80 / 5222 备用端口
                if ($dcKey !== 203 && $r['mtprotoOk'] === false && !empty($fallbackPorts)) {
                    $altResults = [];
                    $altPending = count($fallbackPorts);
                    foreach ($fallbackPorts as $altPort) {
                        self::probeSingleDcAsync($dcKey, $ip, $altPort, static function (array $ar) use (
                            &$altResults,
                            &$altPending,
                            &$r,
                            &$results,
                            &$pending,
                            $altPort,
                            $onDone
                        ): void {
                            $altResults[] = [
                                'port' => $altPort,
                                'ok' => $ar['ok'],
                                'ms' => $ar['ms'],
                                'mtprotoOk' => $ar['mtprotoOk'],
                                'reason' => $ar['reason'],
                            ];
                            $altPending--;
                            if ($altPending === 0) {
                                usort($altResults, static fn (array $a, array $b): int => $a['port'] <=> $b['port']);
                                $r['altPorts'] = $altResults;
                                $results[] = $r;
                                $pending--;
                                if ($pending === 0) {
                                    self::finalizeProbeResults($results, $onDone);
                                }
                            }
                        });
                    }
                    return;
                }

                $results[] = $r;
                $pending--;
                if ($pending === 0) {
                    self::finalizeProbeResults($results, $onDone);
                }
            });
        }
    }

    /**
     * @param array<int, array<string, mixed>> $results
     * @param callable(array<int, array<string, mixed>>): void $onDone
     */
    private static function finalizeProbeResults(array $results, callable $onDone): void
    {
        usort($results, static fn (array $a, array $b): int => $a['dc'] <=> $b['dc']);
        $summary = [];
        foreach ($results as $r) {
            $state = !$r['ok'] ? 'fail' : ($r['mtprotoOk'] === false ? 'tcp_only_eof' : 'ok');
            $summary[] = "DC{$r['dc']}:{$state}";
        }
        Telemetry::logEvent('dc_probe', implode(' ', $summary));
        $onDone($results);
    }

    /**
     * @param callable(array<string, mixed>): void $onDone
     */
    private static function probeSingleDcAsync(int $dc, string $ip, int $port, callable $onDone): void
    {
        $started = Telemetry::nowMs();
        $tcpMs = 0;
        $tcpConnected = false;
        $settled = false;
        $rxBytes = 0;
        $rxPlain = '';
        /** @var ObfuscatedCtrStream|null $dec */
        $dec = null;

        try {
            $sock = new AsyncTcpConnection("tcp://{$ip}:{$port}");
        } catch (\Throwable $e) {
            $onDone([
                'dc' => $dc,
                'ip' => $ip,
                'port' => $port,
                'ok' => false,
                'ms' => 0,
                'mtprotoOk' => false,
                'mtprotoMs' => null,
                'reason' => $e->getMessage(),
            ]);
            return;
        }

        $timerId = null;
        $finish = static function (?bool $mtprotoOk, string $reason) use (
            &$settled,
            &$timerId,
            &$tcpConnected,
            &$tcpMs,
            $started,
            $sock,
            $dc,
            $ip,
            $port,
            $onDone
        ): void {
            if ($settled) {
                return;
            }
            $settled = true;
            if ($timerId !== null) {
                Timer::del($timerId);
                $timerId = null;
            }
            $sock->onConnect = null;
            $sock->onMessage = null;
            $sock->onClose = null;
            $sock->onError = null;
            try {
                $sock->close();
            } catch (\Throwable) {
                // ignore
            }
            $now = Telemetry::nowMs();
            $onDone([
                'dc' => $dc,
                'ip' => $ip,
                'port' => $port,
                'ok' => $tcpConnected,
                'ms' => $tcpConnected ? $tcpMs : max(0, $now - $started),
                'mtprotoOk' => $mtprotoOk,
                'mtprotoMs' => $tcpConnected ? max(0, $now - $started) : null,
                'reason' => $reason,
            ]);
        };

        $timerId = Timer::add(3.0, static function () use ($dc, &$tcpConnected, $finish): void {
            $finish(
                ($dc === 203 && $tcpConnected) ? null : false,
                $tcpConnected ? 'mtproto_timeout' : 'tcp_timeout'
            );
        }, [], false);

        $sock->onConnect = static function (AsyncTcpConnection $conn) use (
            &$tcpConnected,
            &$tcpMs,
            &$dec,
            $started,
            $dc,
            $finish
        ): void {
            $tcpConnected = true;
            $tcpMs = max(0, Telemetry::nowMs() - $started);

            if ($dc === 203) {
                $finish(null, 'cdn_tcp_ok');
                return;
            }

            // 构造无 secret 的标准 Obfuscated2 (0xef 缩写模式) + req_pq_multi 握手包
            $prefix = '';
            $safe = false;
            for ($i = 0; $i < 16 && !$safe; $i++) {
                $prefix = random_bytes(56);
                $safe = Engine::safeDcHeaderPrefix($prefix);
            }
            if (!$safe) {
                $prefix = "\x12\x34\x56\x78\x9a\xbc\xde\xf0" . random_bytes(48);
            }

            $writeKey = substr($prefix, 8, 32);
            $writeIv = substr($prefix, 40, 16);
            $rev = strrev(substr($prefix, 8, 48));
            $readKey = substr($rev, 0, 32);
            $readIv = substr($rev, 32, 16);

            $enc = new ObfuscatedCtrStream($writeKey, $writeIv, 56);
            $dec = new ObfuscatedCtrStream($readKey, $readIv, 0);

            $tail = "\xef\xef\xef\xef" . pack('v', $dc & 0xffff) . "\x00\x00";
            $nonce = $prefix . $enc->update($tail);

            $reqPq = pack('P', 0)
                . pack('P', time() << 32)
                . pack('V', 20)
                . pack('V', 0xbe7e8ef1)
                . random_bytes(16);

            $encReq = $enc->update("\x0a" . $reqPq);
            $conn->send($nonce . $encReq);
        };

        $sock->onMessage = static function (AsyncTcpConnection $conn, string $chunk) use (
            &$rxBytes,
            &$rxPlain,
            &$dec,
            $finish
        ): void {
            if ($dec === null) {
                return;
            }
            $rxBytes += strlen($chunk);
            $rxPlain .= $dec->update($chunk);
            if ($rxBytes >= 25) {
                $validUnencrypted = substr($rxPlain, 1, 8) === "\x00\x00\x00\x00\x00\x00\x00\x00";
                $finish($validUnencrypted, $validUnencrypted ? 'resPQ_ok' : 'invalid_reply');
            }
        };

        $sock->onClose = static function () use (&$rxBytes, $finish): void {
            $finish(false, "eof({$rxBytes}B)");
        };

        $sock->onError = static function ($conn, $code, $msg) use ($finish): void {
            $finish(false, (string) $msg);
        };

        $sock->connect();
    }
}

/**
 * 单个 WebSocket 会话（支持多流复用 websocket 模式与单流独立通道 websocket-lanes 模式）
 */
final class WsSession
{
    public int $laneId;
    private bool $laneUsed = false;
    private TcpConnection $ws;
    /** @var array<string, mixed> */
    public array $cfg;
    public string $secret;
    /** @var array<int, Stream> */
    public array $streams = [];
    public bool $closed = false;
    public int $queued = 0;
    /** @var array<int, bool> */
    private array $tombstones = [];
    /** @var int[] */
    private array $tombstoneOrder = [];
    public bool $loggedMeNotice = false;
    private int $lastPong;
    private int $openedAt;
    private int $bytesUp = 0;
    private int $bytesDown = 0;
    public int $streamCount = 0;
    private ?int $keepAliveTimerId = null;

    /**
     * @param array<string, mixed> $cfg
     */
    public function __construct(TcpConnection $ws, array $cfg, string $secret, int $laneId = 0)
    {
        $this->laneId = $laneId;
        $this->ws = $ws;
        $this->cfg = $cfg;
        $this->secret = $secret;
        $this->openedAt = Telemetry::nowMs();
        $this->lastPong = $this->openedAt;

        Telemetry::$sessions++;
        Telemetry::$sessionsActive++;
        Telemetry::logEvent('session_open', "lane={$laneId} carrier={$cfg['carrier']}");

        if ($laneId === 0) {
            $this->keepAliveTimerId = Timer::add(25.0, function (): void {
                if ($this->closed) {
                    if ($this->keepAliveTimerId !== null) {
                        Timer::del($this->keepAliveTimerId);
                        $this->keepAliveTimerId = null;
                    }
                    return;
                }
                if (Telemetry::nowMs() - $this->lastPong > 90000) {
                    $this->shutdown('pong watchdog');
                    return;
                }
                $this->sendFrame(Engine::packFrame(0x05, 0, pack('N', time())));
            });
        }
    }

    public function sendFrame(string $bytes): void
    {
        if ($this->closed) {
            return;
        }
        try {
            $this->ws->send($bytes);
            $len = strlen($bytes);
            $this->bytesDown += $len;
            Telemetry::$bytesDown += $len;
        } catch (\Throwable) {
            $this->dispose();
        }
    }

    public function onStreamClosed(int $id): void
    {
        if ($this->laneId === 0 || $this->closed || $id !== $this->laneId) {
            return;
        }
        $this->dispose();
        try {
            $this->ws->send(HttpWsProtocol::encodeCloseFrame(1000, 'done'), true);
            $this->ws->close();
        } catch (\Throwable) {
            // ignore
        }
    }

    public function remember(int $id): void
    {
        if (isset($this->tombstones[$id])) {
            return;
        }
        if (count($this->tombstoneOrder) >= 4096) {
            $oldest = array_shift($this->tombstoneOrder);
            if ($oldest !== null) {
                unset($this->tombstones[$oldest]);
            }
        }
        $this->tombstones[$id] = true;
        $this->tombstoneOrder[] = $id;
    }

    public function handle(string $bytes): void
    {
        if ($this->closed) {
            return;
        }
        $totalLen = strlen($bytes);
        if ($totalLen === 0 || $totalLen > Constants::REQUEST_LIMIT) {
            $this->shutdown();
            return;
        }

        $this->bytesUp += $totalLen;
        Telemetry::$bytesUp += $totalLen;

        $offset = 0;
        $frames = 0;
        while ($offset < $totalLen) {
            if ($totalLen - $offset < 8 || ++$frames > 4096) {
                $this->shutdown();
                return;
            }
            $head = unpack('Ctype/Cb1/Cb2/Cb3/Nsize', substr($bytes, $offset, 8));
            if (!is_array($head)) {
                $this->shutdown();
                return;
            }
            $type = (int) $head['type'];
            $id = ((int) $head['b1'] << 16) | ((int) $head['b2'] << 8) | (int) $head['b3'];
            $size = (int) $head['size'];
            $end = $offset + 8 + $size;
            if ($size > 1048576 || $end > $totalLen) {
                $this->shutdown();
                return;
            }
            $payload = $size > 0 ? substr($bytes, $offset + 8, $size) : '';
            $offset = $end;

            if ($this->laneId !== 0 && $id !== $this->laneId) {
                $this->shutdown();
                return;
            }

            if ($type === 0x01) {
                // OPEN
                if ($id === 0 || $size !== 0) {
                    $this->shutdown();
                    return;
                }
                if ($this->laneId !== 0) {
                    if ($this->laneUsed) {
                        $this->shutdown();
                        return;
                    }
                    $this->laneUsed = true;
                    $this->streams[$id] = new Stream($this, $id);
                    continue;
                }
                if (
                    isset($this->streams[$id]) ||
                    isset($this->tombstones[$id]) ||
                    count($this->streams) >= $this->cfg['maxStreams']
                ) {
                    $this->sendFrame(Engine::packFrame(0x03, $id, ''));
                    continue;
                }
                $this->streams[$id] = new Stream($this, $id);
            } elseif ($type === 0x02) {
                // DATA
                if ($id === 0 || $size === 0) {
                    $this->shutdown();
                    return;
                }
                $stream = $this->streams[$id] ?? null;
                if ($stream !== null) {
                    $stream->feed($payload);
                } elseif (!isset($this->tombstones[$id])) {
                    $this->sendFrame(Engine::packFrame(0x03, $id, ''));
                }
            } elseif ($type === 0x03) {
                // CLOSE
                if ($id === 0 || $size !== 0) {
                    $this->shutdown();
                    return;
                }
                $stream = $this->streams[$id] ?? null;
                if ($stream !== null) {
                    $stream->kill(false);
                }
            } elseif ($type === 0x04) {
                // WINDOW
                if ($id === 0 || $size !== 4) {
                    $this->shutdown();
                    return;
                }
                $stream = $this->streams[$id] ?? null;
                if ($stream !== null) {
                    $amt = unpack('Nval', $payload);
                    if (is_array($amt)) {
                        $stream->addCredit((int) $amt['val']);
                    }
                }
            } elseif ($type === 0x05) {
                // PING
                if ($id === 0) {
                    if ($size > 64) {
                        $this->shutdown();
                        return;
                    }
                    $this->sendFrame(Engine::packFrame(0x06, 0, $payload));
                }
            } elseif ($type === 0x06) {
                // PONG
                if ($id !== 0) {
                    $this->shutdown();
                    return;
                }
                $this->lastPong = Telemetry::nowMs();
            } else {
                $this->shutdown();
                return;
            }
        }
    }

    public function dispose(): void
    {
        if ($this->closed) {
            return;
        }
        $this->closed = true;
        Telemetry::$sessionsActive = max(0, Telemetry::$sessionsActive - 1);
        Telemetry::logEvent(
            'session_close',
            Telemetry::fmtDuration(Telemetry::nowMs() - $this->openedAt)
            . " streams={$this->streamCount}"
            . ' up=' . Telemetry::fmtBytes($this->bytesUp)
            . ' down=' . Telemetry::fmtBytes($this->bytesDown)
        );

        if ($this->keepAliveTimerId !== null) {
            Timer::del($this->keepAliveTimerId);
            $this->keepAliveTimerId = null;
        }
        foreach (array_values($this->streams) as $stream) {
            $stream->kill(false);
        }
        $this->streams = [];
        $this->tombstones = [];
        $this->tombstoneOrder = [];
        $this->queued = 0;
    }

    public function shutdown(string $reason = 'protocol'): void
    {
        Telemetry::logEvent('session_kill', $reason);
        $this->dispose();
        try {
            $this->ws->send(HttpWsProtocol::encodeCloseFrame(1011, 'closed'), true);
            $this->ws->close();
        } catch (\Throwable) {
            // ignore
        }
    }
}

/**
 * 单条 Telegram DC 加密复用流（支持 Obfuscated2 Fast-Mode 零重加密下行直通与双向流控背压）
 */
final class Stream
{
    private WsSession $session;
    public int $id;
    private string $phase = 'header'; // header | connecting | ready
    private string $header = '';
    private bool $dead = false;
    private ?AsyncTcpConnection $dcSocket = null;
    private ?int $connectTimerId = null;
    /** @var string[] */
    private array $inQueue = [];
    private int $queuedLocal = 0;
    private int $recvOutstanding = 0;
    private int $sendCredit;
    private string $pendingDown = '';
    private int $dcKey = 0;
    private string $dcTarget = '';
    private int $dcSentPayloadBytes = 0;
    private int $dcRecvBytes = 0;

    private ?ObfuscatedCtrStream $clientReadCipher = null;
    private ?ObfuscatedCtrStream $dcWriteCipher = null;

    public function __construct(WsSession $session, int $id)
    {
        $this->session = $session;
        $this->id = $id;
        $this->sendCredit = (int) $session->cfg['streamWindow'];
        Telemetry::$streams++;
        $session->streamCount++;
    }

    public function feed(string $payload): void
    {
        $len = strlen($payload);
        if ($this->dead || $len === 0) {
            return;
        }
        $this->recvOutstanding += $len;
        if ($this->recvOutstanding > $this->session->cfg['streamWindow'] + 65536) {
            $this->kill(true);
            return;
        }

        $this->inQueue[] = $payload;
        $this->queuedLocal += $len;
        $this->session->queued += $len;
        if ($this->session->queued > $this->session->cfg['maxQueued']) {
            $this->kill(true);
            return;
        }

        $this->drainInQueue();
    }

    private function drainInQueue(): void
    {
        while (!$this->dead && !empty($this->inQueue)) {
            if ($this->phase === 'header') {
                $chunk = $this->inQueue[0];
                $need = 64 - strlen($this->header);
                $take = min($need, strlen($chunk));
                $this->header .= substr($chunk, 0, $take);
                $this->queuedLocal -= $take;
                $this->session->queued -= $take;

                if ($take < strlen($chunk)) {
                    $this->inQueue[0] = substr($chunk, $take);
                } else {
                    array_shift($this->inQueue);
                }

                if (strlen($this->header) === 64) {
                    $this->initDcConnection();
                    return;
                }
                continue;
            }

            if ($this->phase === 'connecting') {
                // 等待 DC TCP 异步建连完成后再继续发送队列中的数据
                return;
            }

            // phase === 'ready'
            $payload = array_shift($this->inQueue);
            $len = strlen($payload);
            $this->queuedLocal -= $len;
            $this->session->queued -= $len;
            $this->writeToDc($payload);
        }
    }

    private function initDcConnection(): void
    {
        $this->phase = 'connecting';
        $header = $this->header;
        $readKey = Crypto::sha256(substr($header, 8, 32) . $this->session->secret);
        $readIv = substr($header, 40, 16);
        $this->clientReadCipher = new ObfuscatedCtrStream($readKey, $readIv, 56);
        $tail = $this->clientReadCipher->update(substr($header, 56, 8));

        $tag = substr($tail, 0, 4);
        if (Engine::tagKind($tag) === 0) {
            $this->kill(true);
            return;
        }

        // 16 位有符号小端 dcId
        $unpacked = unpack('vdc', substr($tail, 4, 2));
        $rawDc = $unpacked ? (int) $unpacked['dc'] : 0;
        $dcId = $rawDc >= 32768 ? $rawDc - 65536 : $rawDc;
        $dcKey = abs($dcId);
        $this->dcKey = $dcKey;

        $address = $this->session->cfg['dc'][$dcKey] ?? null;
        if ($address === null) {
            $this->kill(true);
            return;
        }

        $ips = is_array($address) ? $address : [$address];
        shuffle($ips);
        $candidatePorts = !empty($this->session->cfg['dcPorts'])
            ? $this->session->cfg['dcPorts']
            : [$this->session->cfg['dcPort'] ?? 443];

        $reversed = strrev(substr($header, 8, 48));
        $writeKey = Crypto::sha256(substr($reversed, 0, 32) . $this->session->secret);
        $clientWriteIv = substr($reversed, 32, 16);

        // FAST MODE：构造 dcHeader[8..56] = reverse(clientWriteKey || clientWriteIv)，
        // 使 Telegram DC 下行加密流与客户端解密流完全一致，服务端下行零重加密直通转发
        $dcKeyMaterial = strrev($writeKey . $clientWriteIv);
        $this->dcWriteCipher = new ObfuscatedCtrStream(
            substr($dcKeyMaterial, 0, 32),
            substr($dcKeyMaterial, 32, 16),
            56
        );

        $prefix = '';
        $safe = false;
        for ($i = 0; $i < 16 && !$safe; $i++) {
            $prefix = random_bytes(8);
            $safe = Engine::safeDcHeaderPrefix($prefix);
        }
        if (!$safe) {
            $prefix = "\x12\x34\x56\x78\x9a\xbc\xde\xf0";
        }
        $rawTail = $tag . pack('v', $dcId & 0xffff) . "\x00\x00";
        $dcHeader = $prefix . $dcKeyMaterial . $this->dcWriteCipher->update($rawTail);

        $attempts = [];
        foreach ($candidatePorts as $port) {
            foreach ($ips as $ip) {
                $attempts[] = [(string) $ip, (int) $port];
            }
        }
        $attempts = array_slice($attempts, 0, 4);

        $this->tryConnectAttempt($attempts, 0, $dcHeader);
    }

    /**
     * @param array<int, array{0: string, 1: int}> $attempts
     */
    private function tryConnectAttempt(array $attempts, int $index, string $dcHeader): void
    {
        if ($this->dead) {
            return;
        }
        if ($index >= count($attempts)) {
            Telemetry::logEvent('dc_fail', "dc={$this->dcKey}");
            $this->kill(true);
            return;
        }

        [$hostIp, $port] = $attempts[$index];
        Telemetry::$dcAttempts++;
        $connected = false;

        try {
            $sock = new AsyncTcpConnection("tcp://{$hostIp}:{$port}");
            $sock->maxSendBufferSize = 4194304;
        } catch (\Throwable) {
            Telemetry::$dcFails++;
            $this->tryConnectAttempt($attempts, $index + 1, $dcHeader);
            return;
        }

        $this->dcSocket = $sock;

        $this->connectTimerId = Timer::add(3.0, function () use (&$connected, $sock, $attempts, $index, $dcHeader): void {
            $this->connectTimerId = null;
            if ($this->dead || $connected) {
                return;
            }
            Telemetry::$dcFails++;
            $sock->onConnect = null;
            $sock->onClose = null;
            $sock->onError = null;
            try {
                $sock->close();
            } catch (\Throwable) {
                // ignore
            }
            $this->dcSocket = null;
            $this->tryConnectAttempt($attempts, $index + 1, $dcHeader);
        }, [], false);

        $sock->onConnect = function (AsyncTcpConnection $conn) use (&$connected, $hostIp, $port, $dcHeader): void {
            if ($this->dead) {
                $conn->close();
                return;
            }
            $connected = true;
            if ($this->connectTimerId !== null) {
                Timer::del($this->connectTimerId);
                $this->connectTimerId = null;
            }
            $this->dcTarget = "{$hostIp}:{$port}";

            $conn->onMessage = function (AsyncTcpConnection $c, string $chunk): void {
                if (!$this->dead) {
                    $this->handleDcData($chunk);
                }
            };
            $conn->onClose = function (): void {
                $this->kill(true);
            };
            $conn->onError = function (): void {
                $this->kill(true);
            };

            $conn->send($dcHeader);
            $this->phase = 'ready';
            $this->grant(64);
            $this->drainInQueue();
        };

        $failBeforeConnect = function () use (&$connected, $sock, $attempts, $index, $dcHeader): void {
            if ($this->dead || $connected) {
                return;
            }
            if ($this->connectTimerId !== null) {
                Timer::del($this->connectTimerId);
                $this->connectTimerId = null;
            }
            Telemetry::$dcFails++;
            $sock->onConnect = null;
            $sock->onClose = null;
            $sock->onError = null;
            try {
                $sock->close();
            } catch (\Throwable) {
                // ignore
            }
            $this->dcSocket = null;
            $this->tryConnectAttempt($attempts, $index + 1, $dcHeader);
        };

        $sock->onClose = $failBeforeConnect;
        $sock->onError = $failBeforeConnect;
        $sock->connect();
    }

    private function writeToDc(string $payload): void
    {
        if ($this->dead || $this->clientReadCipher === null || $this->dcWriteCipher === null || $this->dcSocket === null) {
            return;
        }
        $plain = $this->clientReadCipher->update($payload);
        if ($this->dead) {
            return;
        }
        $encrypted = $this->dcWriteCipher->update($plain);
        $this->dcSentPayloadBytes += strlen($encrypted);
        $this->dcSocket->send($encrypted);
        $this->grant(strlen($payload));
    }

    private function handleDcData(string $chunk): void
    {
        $this->dcRecvBytes += strlen($chunk);
        $combined = $this->pendingDown !== '' ? ($this->pendingDown . $chunk) : $chunk;
        $this->pendingDown = '';

        $total = strlen($combined);
        $offset = 0;
        $dataChunk = (int) $this->session->cfg['dataChunk'];

        while ($offset < $total && !$this->dead) {
            if ($this->sendCredit <= 0) {
                $this->pendingDown = substr($combined, $offset);
                if ($this->dcSocket !== null) {
                    $this->dcSocket->pauseRecv();
                }
                return;
            }
            $size = min($total - $offset, $this->sendCredit, $dataChunk);
            if ($size <= 0) {
                break;
            }
            $slice = substr($combined, $offset, $size);
            $this->sendCredit -= $size;
            $this->session->sendFrame(Engine::packFrame(0x02, $this->id, $slice));
            $offset += $size;
        }

        if ($this->sendCredit <= 0 && $this->dcSocket !== null) {
            $this->dcSocket->pauseRecv();
        }
    }

    public function addCredit(int $amount): void
    {
        if ($this->dead || $amount <= 0) {
            return;
        }
        $this->sendCredit = min(0xffffffff, $this->sendCredit + $amount);
        if ($this->pendingDown !== '' && $this->sendCredit > 0) {
            $rem = $this->pendingDown;
            $this->pendingDown = '';
            $this->handleDcData($rem);
        }
        if ($this->sendCredit > 0 && $this->pendingDown === '' && $this->dcSocket !== null) {
            $this->dcSocket->resumeRecv();
        }
    }

    private function grant(int $amount): void
    {
        if ($this->dead || $amount <= 0) {
            return;
        }
        $this->recvOutstanding = max(0, $this->recvOutstanding - $amount);
        $this->session->sendFrame(Engine::packWindowFrame($this->id, $amount));
    }

    public function kill(bool $notify): void
    {
        if ($this->dead) {
            return;
        }
        $this->dead = true;
        unset($this->session->streams[$this->id]);
        $this->session->remember($this->id);
        $this->session->queued = max(0, $this->session->queued - $this->queuedLocal);
        $this->queuedLocal = 0;
        $this->inQueue = [];
        $this->pendingDown = '';

        if ($this->connectTimerId !== null) {
            Timer::del($this->connectTimerId);
            $this->connectTimerId = null;
        }

        if ($this->dcSocket !== null) {
            if ($this->dcSentPayloadBytes > 0 && $this->dcRecvBytes === 0) {
                Telemetry::$dcEmptyCloses++;
                Telemetry::logEvent(
                    'dc_eof_empty',
                    "dc={$this->dcKey} target={$this->dcTarget} up={$this->dcSentPayloadBytes}B down=0B"
                );
            }
            $this->dcSocket->onConnect = null;
            $this->dcSocket->onMessage = null;
            $this->dcSocket->onClose = null;
            $this->dcSocket->onError = null;
            try {
                $this->dcSocket->close();
            } catch (\Throwable) {
                // ignore
            }
            $this->dcSocket = null;
        }

        if ($notify && !$this->session->closed) {
            $this->session->sendFrame(Engine::packFrame(0x03, $this->id, ''));
        }
        $this->session->onStreamClosed($this->id);
    }
}
