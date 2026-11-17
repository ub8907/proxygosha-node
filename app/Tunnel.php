<?php

declare(strict_types=1);

namespace App;

use Workerman\Protocols\Http\Request;
use Workerman\Timer;

/**
 * Cloudflare Tunnel 状态统计与可选内置 cloudflared 子进程托管
 */
final class Tunnel
{
    private static ?bool $binaryChecked = null;
    /** @var resource|null */
    private static $process = null;
    /** @var array<int, resource> */
    private static array $pipes = [];
    private static ?int $pid = null;
    private static bool $running = false;
    private static string $lastError = '';
    private static ?int $pollTimerId = null;
    private static ?int $restartTimerId = null;
    private static bool $stopping = false;
    private static int $targetPort = 3000;

    public static function isCloudflaredAvailable(): bool
    {
        if (self::$binaryChecked !== null) {
            return self::$binaryChecked;
        }
        $out = [];
        $code = 1;
        @exec('command -v cloudflared 2>/dev/null', $out, $code);
        self::$binaryChecked = ($code === 0 && !empty($out));
        return self::$binaryChecked;
    }

    public static function recordTunnelHeaders(Request $req, string $resolvedHost): bool
    {
        $cfRay = $req->header('cf-ray', '');
        $cfConnectingIp = $req->header('cf-connecting-ip', '');
        $cfVisitor = $req->header('cf-visitor', '');
        $viaTunnel = ($cfRay !== '' && $cfRay !== null)
            || ($cfConnectingIp !== '' && $cfConnectingIp !== null)
            || ($cfVisitor !== '' && $cfVisitor !== null);

        if ($viaTunnel) {
            Telemetry::$tunnelRequests++;
            if (is_string($cfRay) && $cfRay !== '') {
                $dash = strrpos($cfRay, '-');
                Telemetry::$lastTunnelRay = $dash !== false && $dash > 0
                    ? substr($cfRay, $dash + 1)
                    : substr($cfRay, 0, 12);
            }
            if ($resolvedHost !== '') {
                Telemetry::$lastTunnelHost = $resolvedHost;
            }
        }
        return $viaTunnel;
    }

    public static function startTunnelIfConfigured(int $port): void
    {
        self::$targetPort = $port;
        $token = trim(Config::env('CF_TUNNEL_TOKEN', ''));
        $autostart = strtolower(trim(Config::env('CF_TUNNEL_AUTOSTART', '')));
        if ($token === '' || ($autostart !== 'true' && $autostart !== '1')) {
            return;
        }

        if (!self::isCloudflaredAvailable()) {
            self::$lastError = "未在系统 PATH 中找到 cloudflared 二进制文件；请在外部手动运行 cloudflared 指向 http://127.0.0.1:{$port}";
            Telemetry::logEvent('tunnel_skip', 'cloudflared binary missing');
            return;
        }

        if (self::$process !== null || self::$stopping) {
            return;
        }

        $cmd = 'cloudflared tunnel --no-autoupdate run --token ' . escapeshellarg($token);
        $descriptors = [
            0 => ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $proc = @proc_open($cmd, $descriptors, $pipes);
        if (!is_resource($proc)) {
            self::$lastError = '启动 cloudflared 进程失败';
            Telemetry::logEvent('tunnel_error', 'proc_open failed');
            return;
        }

        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $status = proc_get_status($proc);
        self::$process = $proc;
        self::$pipes = $pipes;
        self::$pid = is_array($status) ? ($status['pid'] ?? null) : null;
        self::$running = true;
        self::$lastError = '';

        Telemetry::logEvent('tunnel_start', 'pid=' . (self::$pid ?? '?') . " target=127.0.0.1:{$port}");

        self::$pollTimerId = Timer::add(1.0, static function () use ($port): void {
            if (!is_resource(self::$process)) {
                return;
            }
            $errOut = @stream_get_contents(self::$pipes[2]);
            if (is_string($errOut) && trim($errOut) !== '') {
                $lines = explode("\n", trim($errOut));
                foreach ($lines as $line) {
                    if (str_contains($line, 'ERR') || str_contains($line, 'failed')) {
                        self::$lastError = substr($line, -180);
                    }
                }
            }
            @stream_get_contents(self::$pipes[1]);

            $st = proc_get_status(self::$process);
            if (!is_array($st) || !$st['running']) {
                $exitCode = is_array($st) ? ($st['exitcode'] ?? -1) : -1;
                self::cleanupProcess();
                Telemetry::logEvent('tunnel_exit', "code={$exitCode}");
                if (!self::$stopping) {
                    $again = strtolower(trim(Config::env('CF_TUNNEL_AUTOSTART', '')));
                    if ($again === 'true' || $again === '1') {
                        self::$restartTimerId = Timer::add(5.0, static function () use ($port): void {
                            self::$restartTimerId = null;
                            self::startTunnelIfConfigured($port);
                        }, [], false);
                    }
                }
            }
        });
    }

    private static function cleanupProcess(): void
    {
        if (self::$pollTimerId !== null) {
            Timer::del(self::$pollTimerId);
            self::$pollTimerId = null;
        }
        foreach (self::$pipes as $pipe) {
            if (is_resource($pipe)) {
                @fclose($pipe);
            }
        }
        self::$pipes = [];
        if (is_resource(self::$process)) {
            @proc_close(self::$process);
        }
        self::$process = null;
        self::$pid = null;
        self::$running = false;
    }

    public static function stopTunnel(): void
    {
        self::$stopping = true;
        if (self::$restartTimerId !== null) {
            Timer::del(self::$restartTimerId);
            self::$restartTimerId = null;
        }
        if (is_resource(self::$process)) {
            @proc_terminate(self::$process, 15);
        }
        self::cleanupProcess();
    }

    /**
     * @return array<string, mixed>
     */
    public static function getStatus(): array
    {
        $token = trim(Config::env('CF_TUNNEL_TOKEN', ''));
        $autostart = strtolower(trim(Config::env('CF_TUNNEL_AUTOSTART', '')));
        return [
            'binaryAvailable' => self::isCloudflaredAvailable(),
            'autostartEnabled' => $autostart === 'true' || $autostart === '1',
            'tokenConfigured' => $token !== '',
            'running' => self::$running,
            'pid' => self::$pid,
            'requestsViaTunnel' => Telemetry::$tunnelRequests,
            'lastTunnelHost' => Telemetry::$lastTunnelHost,
            'lastRayColo' => Telemetry::$lastTunnelRay,
            'lastError' => self::$lastError,
        ];
    }
}
