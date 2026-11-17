<?php

declare(strict_types=1);

/**
 * 项目根目录通用入口：
 * - 若通过 Nginx + PHP-FPM 访问（站点根目录指向项目根目录时），直接分发 HTTP 网站请求；
 * - 若通过命令行（php index.php start）调用，自动委托给 Workerman 服务启动脚本。
 */

if (PHP_SAPI === 'cli') {
    require __DIR__ . '/start.php';
    return;
}

require_once __DIR__ . '/vendor/autoload.php';

$staticRoot = is_dir(__DIR__ . '/public') ? (__DIR__ . '/public') : (__DIR__ . '/dist');
\App\FpmKernel::dispatch(__DIR__, $staticRoot);
