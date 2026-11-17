<?php

declare(strict_types=1);

namespace App;

use Workerman\Connection\ConnectionInterface;
use Workerman\Connection\TcpConnection;
use Workerman\Protocols\Http;
use Workerman\Protocols\ProtocolInterface;

/**
 * Workerman 单端口 HTTP + RFC 6455 WebSocket 混合协议适配器。
 *
 * 兼容 Workerman 4.x 与 5.x，不依赖任何 Connection 动态属性（完全兼容 PHP 8.2/8.3/8.4）。
 * 连接升级前完全委托给 \Workerman\Protocols\Http 解析与响应；
 * 当鉴权通过并发出 101 Switching Protocols 后，同一 TCP 连接立即无缝切换为 RFC 6455 二进制帧编解码。
 */
final class HttpWsProtocol implements ProtocolInterface
{
    /**
     * 每个已升级连接的 WebSocket 分片重组状态（按 spl_object_id 存储）
     *
     * @var array<int, array{
     *   upgraded: bool,
     *   fragOpcode: int,
     *   fragBuffer: string,
     *   currentFrameLen: int
     * }>
     */
    private static array $states = [];

    public static function isUpgraded(ConnectionInterface $connection): bool
    {
        $id = spl_object_id($connection);
        return !empty(self::$states[$id]['upgraded']);
    }

    public static function markUpgraded(ConnectionInterface $connection): void
    {
        $id = spl_object_id($connection);
        self::$states[$id] = [
            'upgraded' => true,
            'fragOpcode' => 0,
            'fragBuffer' => '',
            'currentFrameLen' => 0,
        ];
    }

    public static function clearState(ConnectionInterface $connection): void
    {
        unset(self::$states[spl_object_id($connection)]);
    }

    public static function input($recv_buffer, ConnectionInterface $connection): int
    {
        $id = spl_object_id($connection);
        if (empty(self::$states[$id]['upgraded'])) {
            return Http::input($recv_buffer, $connection);
        }

        $recvLen = strlen($recv_buffer);
        if ($recvLen < 2) {
            return 0;
        }

        $firstByte = ord($recv_buffer[0]);
        $secondByte = ord($recv_buffer[1]);
        $opcode = $firstByte & 0x0f;
        $masked = ($secondByte & 0x80) !== 0;
        $payloadLen = $secondByte & 0x7f;
        $headLen = 2;

        if ($payloadLen === 126) {
            if ($recvLen < 4) {
                return 0;
            }
            $unpacked = unpack('nlen', substr($recv_buffer, 2, 2));
            $payloadLen = $unpacked ? (int) $unpacked['len'] : 0;
            $headLen = 4;
        } elseif ($payloadLen === 127) {
            if ($recvLen < 10) {
                return 0;
            }
            $unpacked = unpack('Jlen', substr($recv_buffer, 2, 8));
            $payloadLen = $unpacked ? (int) $unpacked['len'] : 0;
            $headLen = 10;
        }

        if ($masked) {
            $headLen += 4;
        }

        // RFC 6455 校验与最大载荷限制（16MB），防止恶意超大帧耗尽内存
        if ($payloadLen < 0 || $payloadLen > Constants::REQUEST_LIMIT) {
            $connection->close();
            return 0;
        }

        // 控制帧载荷不能超过 125 字节
        if ($opcode >= 8 && $payloadLen > 125) {
            $connection->close();
            return 0;
        }

        $totalLen = $headLen + $payloadLen;
        if ($recvLen < $totalLen) {
            return 0;
        }

        // 处理分片帧或直接返回单帧长度，支持控制帧穿插于分片中间（RFC 6455 Section 5.4）
        if ($opcode >= 8) {
            return $totalLen;
        }

        $fin = ($firstByte & 0x80) !== 0;
        if (!$fin) {
            $fragLen = strlen(self::$states[$id]['fragBuffer']) + $payloadLen;
            if ($fragLen > Constants::REQUEST_LIMIT) {
                $connection->close();
                return 0;
            }
        }

        return $totalLen;
    }

    public static function decode($recv_buffer, ConnectionInterface $connection): mixed
    {
        $id = spl_object_id($connection);
        if (empty(self::$states[$id]['upgraded'])) {
            return Http::decode($recv_buffer, $connection);
        }

        $firstByte = ord($recv_buffer[0]);
        $secondByte = ord($recv_buffer[1]);
        $fin = ($firstByte & 0x80) !== 0;
        $opcode = $firstByte & 0x0f;
        $masked = ($secondByte & 0x80) !== 0;
        $payloadLen = $secondByte & 0x7f;
        $offset = 2;

        if ($payloadLen === 126) {
            $unpacked = unpack('nlen', substr($recv_buffer, 2, 2));
            $payloadLen = $unpacked ? (int) $unpacked['len'] : 0;
            $offset = 4;
        } elseif ($payloadLen === 127) {
            $unpacked = unpack('Jlen', substr($recv_buffer, 2, 8));
            $payloadLen = $unpacked ? (int) $unpacked['len'] : 0;
            $offset = 10;
        }

        $payload = '';
        if ($masked) {
            $maskKey = substr($recv_buffer, $offset, 4);
            $offset += 4;
            if ($payloadLen > 0) {
                $raw = substr($recv_buffer, $offset, $payloadLen);
                // C 层高速字符串异或解掩码
                $maskFull = substr(str_repeat($maskKey, (int) ceil($payloadLen / 4)), 0, $payloadLen);
                $payload = $raw ^ $maskFull;
            }
        } elseif ($payloadLen > 0) {
            $payload = substr($recv_buffer, $offset, $payloadLen);
        }

        // 处理控制帧
        if ($opcode === 0x8) {
            // Close 帧
            if ($connection instanceof TcpConnection) {
                $connection->send(self::encodeControlFrame(0x8, ''), true);
                $connection->close();
            }
            return ['__ws_control' => 'close'];
        }
        if ($opcode === 0x9) {
            // Ping -> 自动回复 Pong
            if ($connection instanceof TcpConnection) {
                $connection->send(self::encodeControlFrame(0xA, $payload), true);
            }
            return ['__ws_control' => 'ping'];
        }
        if ($opcode === 0xA) {
            // Pong
            return ['__ws_control' => 'pong'];
        }

        // 分片消息重组
        if ($opcode !== 0x0) {
            // 新消息起始帧
            if (!$fin) {
                self::$states[$id]['fragOpcode'] = $opcode;
                self::$states[$id]['fragBuffer'] = $payload;
                return ['__ws_control' => 'fragment'];
            }
            return [
                '__ws_binary' => ($opcode === 0x2),
                '__ws_nonbinary' => ($opcode !== 0x2),
                'data' => $payload,
            ];
        }

        // 续传帧 (opcode === 0x0)
        $combined = self::$states[$id]['fragBuffer'] . $payload;
        if (strlen($combined) > Constants::REQUEST_LIMIT) {
            $connection->close();
            return ['__ws_control' => 'close'];
        }

        if (!$fin) {
            self::$states[$id]['fragBuffer'] = $combined;
            return ['__ws_control' => 'fragment'];
        }

        $origOpcode = self::$states[$id]['fragOpcode'];
        self::$states[$id]['fragOpcode'] = 0;
        self::$states[$id]['fragBuffer'] = '';

        return [
            '__ws_binary' => ($origOpcode === 0x2),
            '__ws_nonbinary' => ($origOpcode !== 0x2),
            'data' => $combined,
        ];
    }

    public static function encode($data, ConnectionInterface $connection): string
    {
        $id = spl_object_id($connection);
        if (empty(self::$states[$id]['upgraded'])) {
            return Http::encode($data, $connection);
        }

        $payload = (string) $data;
        return self::encodeBinaryFrame($payload);
    }

    public static function encodeBinaryFrame(string $payload): string
    {
        $len = strlen($payload);
        if ($len <= 125) {
            return "\x82" . chr($len) . $payload;
        }
        if ($len <= 65535) {
            return "\x82\x7e" . pack('n', $len) . $payload;
        }
        return "\x82\x7f" . pack('J', $len) . $payload;
    }

    public static function encodeCloseFrame(int $code = 1000, string $reason = ''): string
    {
        $body = pack('n', $code) . $reason;
        return self::encodeControlFrame(0x8, $body);
    }

    private static function encodeControlFrame(int $opcode, string $payload): string
    {
        $len = min(125, strlen($payload));
        $body = $len > 0 ? substr($payload, 0, $len) : '';
        return chr(0x80 | ($opcode & 0x0f)) . chr($len) . $body;
    }
}
