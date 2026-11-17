<?php

declare(strict_types=1);

/**
 * Nginx 默认网站入口（当站点根目录指向 public/ 时由 PHP-FPM 执行本文件）
 */

$root = dirname(__DIR__);
require_once $root . '/vendor/autoload.php';

\App\FpmKernel::dispatch($root, __DIR__);
