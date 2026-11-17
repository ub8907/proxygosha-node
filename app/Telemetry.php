<?php

declare(strict_types=1);

namespace App;

/**
 * 内存实时遥测与环形事件日志（不记录任何客户端 IP、Token 或 Secret）
 */
final class Telemetry
{
    public static int $processStartMs = 0;

    public static int $sessions = 0;
    public static int $sessionsActive = 0;
    public static int $streams = 0;
    public static int $dcAttempts = 0;
    public static int $dcFails = 0;
    public static int $dcEmptyCloses = 0;
    public static int $bytesUp = 0;
    public static int $bytesDown = 0;
    public static int $wsRejects = 0;
    public static int $panelViews = 0;
    public static int $statusViews = 0;
    public static int $tunnelRequests = 0;
    public static string $lastTunnelRay = '';
    public static string $lastTunnelHost = '';

    private const LOG_LIMIT = 150;

    /** @var array<int, array{t: int, event: string, detail: string}> */
    private static array $logs = [];

    public static function init(): void
    {
        if (self::$processStartMs === 0) {
            self::$processStartMs = self::nowMs();
        }
    }

    public static function nowMs(): int
    {
        return (int) floor(microtime(true) * 1000);
    }

    public static function logEvent(string $event, string $detail = ''): void
    {
        self::$logs[] = [
            't' => self::nowMs(),
            'event' => substr($event, 0, 28),
            'detail' => substr($detail, 0, 140),
        ];
        if (count(self::$logs) > self::LOG_LIMIT) {
            self::$logs = array_slice(self::$logs, -self::LOG_LIMIT);
        }
    }

    public static function reportError(string $where, \Throwable|string $error): void
    {
        $msg = $error instanceof \Throwable ? $error->getMessage() : (string) $error;
        fwrite(STDERR, "[proxygosha-php] {$where}: {$msg}\n");
        self::logEvent('error', "{$where}: {$msg}");
    }

    /**
     * @return array<int, array{t: int, event: string, detail: string}>
     */
    public static function recentLogs(int $limit = 60): array
    {
        return array_reverse(array_slice(self::$logs, -$limit));
    }

    public static function fmtBytes(int $value): string
    {
        if ($value < 1024) {
            return $value . ' B';
        }
        if ($value < 1048576) {
            return number_format($value / 1024, 1, '.', '') . ' KB';
        }
        if ($value < 1073741824) {
            return number_format($value / 1048576, 1, '.', '') . ' MB';
        }
        return number_format($value / 1073741824, 2, '.', '') . ' GB';
    }

    public static function fmtDuration(int $milliseconds): string
    {
        $total = max(0, intdiv($milliseconds, 1000));
        $days = intdiv($total, 86400);
        $hours = intdiv($total % 86400, 3600);
        $minutes = intdiv($total % 3600, 60);
        if ($days > 0) {
            return "{$days}d {$hours}h";
        }
        if ($hours > 0) {
            return "{$hours}h {$minutes}m";
        }
        return "{$minutes}m " . ($total % 60) . 's';
    }
}
