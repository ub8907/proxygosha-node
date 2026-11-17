<?php

declare(strict_types=1);

/**
 * ProxyGosha PHP (Workerman) 单端口统一入口
 *
 * 启动方式：
 *   php start.php start       # 前台启动
 *   php start.php start -d    # 后台守护进程模式启动
 *   php start.php stop        # 优雅停止
 *   php start.php status      # 查看工作进程状态
 */

require_once __DIR__ . '/vendor/autoload.php';

use App\Config;
use App\Engine;
use App\HttpWsProtocol;
use App\Router;
use App\Telemetry;
use App\Tunnel;
use Workerman\Connection\TcpConnection;
use Workerman\Protocols\Http\Request;
use Workerman\Worker;

// 加载根目录 .env 配置及网页初始化持久化配置
Config::loadDotEnv(__DIR__ . '/.env');
Config::setRuntimeFile(__DIR__ . '/storage/runtime.json');

// 定位静态前端产物目录（优先使用 public/，兼容 dist/）
$staticRoot = (is_file(__DIR__ . '/public/console.html') || is_file(__DIR__ . '/public/index.html'))
    ? __DIR__ . '/public'
    : __DIR__ . '/dist';
Router::setStaticRoot($staticRoot);

$portRaw = Config::env('WORKERMAN_PORT', '') ?: Config::env('PORT', '3000');
$port = (int) ($portRaw ?: 3000);
if ($port <= 0 || $port > 65535) {
    $port = 3000;
}
$host = Config::env('WORKERMAN_HOST', '') ?: (Config::env('HOST', '0.0.0.0') ?: '0.0.0.0');
$workerCount = max(1, (int) (Config::env('WORKER_COUNT', '1') ?: 1));

// 创建单端口监听服务，通过 HttpWsProtocol 在同一端口承载 HTTP 与 RFC 6455 WebSocket
$worker = new Worker("tcp://{$host}:{$port}");
$worker->name = 'ProxyGosha-PHP';
$worker->count = $workerCount;
$worker->protocol = HttpWsProtocol::class;

$worker->onWorkerStart = static function (Worker $w) use ($host, $port): void {
    Telemetry::init();

    // 默认按 1 个 Worker 运行以保证内存遥测与日志全局一致；仅在 0 号进程启动隧道边车
    if ($w->id === 0) {
        $cfg = Config::getRuntime();
        $state = $cfg !== null
            ? "已配置 (carrier={$cfg['carrier']}, maxStreams={$cfg['maxStreams']})"
            : '未配置（请访问 / 完成初始化）';
        echo "[proxygosha-php] Workerman HTTP+WS 服务已启动，监听 http://{$host}:{$port} (workers={$w->count})\n";
        echo "[proxygosha-php] 当前状态: {$state}\n";
        Tunnel::startTunnelIfConfigured($port);
    }
};

$worker->onWorkerStop = static function (Worker $w): void {
    if ($w->id === 0) {
        Tunnel::stopTunnel();
    }
};

$worker->onMessage = static function (TcpConnection $connection, mixed $data): void {
    if (HttpWsProtocol::isUpgraded($connection)) {
        Engine::onWsMessage($connection, $data);
        return;
    }

    if (!$data instanceof Request) {
        Engine::rejectUpgrade($connection, 400, 'Bad Request');
        return;
    }

    $upgrade = strtolower((string) $data->header('upgrade', ''));
    if ($upgrade === 'websocket') {
        Engine::handleUpgrade($connection, $data, Config::getRuntime());
        return;
    }

    Router::handleHttp($connection, $data);
};

$worker->onClose = static function (TcpConnection $connection): void {
    Engine::onWsClose($connection);
    HttpWsProtocol::clearState($connection);
};

$worker->onError = static function (TcpConnection $connection): void {
    Engine::onWsError($connection);
    HttpWsProtocol::clearState($connection);
};

Worker::runAll();
