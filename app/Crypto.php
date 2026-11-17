<?php

declare(strict_types=1);

namespace App;

/**
 * 密码学工具集：Base64URL、SHA-256、HMAC-SHA256、构建印记解封与连续 AES-256-CTR 流密码
 */
final class Crypto
{
    private static ?array $sealCache = null;

    public static function reverse(string $bytes): string
    {
        return strrev($bytes);
    }

    public static function b64uEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function b64uDecodeStrict(string $value): ?string
    {
        if ($value === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $value)) {
            return null;
        }
        $remainder = strlen($value) % 4;
        if ($remainder === 1) {
            return null;
        }
        $padded = $value . ($remainder > 0 ? str_repeat('=', 4 - $remainder) : '');
        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);
        if ($decoded === false) {
            return null;
        }
        return self::b64uEncode($decoded) === $value ? $decoded : null;
    }

    public static function sha256(string $bytes): string
    {
        return hash('sha256', $bytes, true);
    }

    public static function hmacSha256(string $key, string $data): string
    {
        return hash_hmac('sha256', $data, $key, true);
    }

    public static function hmacVerify(string $key, string $signature, string $data): bool
    {
        $expected = self::hmacSha256($key, $data);
        if (strlen($expected) !== strlen($signature)) {
            return false;
        }
        return hash_equals($expected, $signature);
    }

    public static function safeEqual(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }

    /**
     * 解封构建印记（与 Node/Workers 版本保持完全一致的密钥派生盐值）
     *
     * @return array{bytes: string, name: string, mail: string}
     */
    public static function unseal(): array
    {
        if (self::$sealCache !== null) {
            return self::$sealCache;
        }
        $data = base64_decode(Constants::BUILD_SEAL, true);
        if ($data === false) {
            $data = '';
        }
        $salt = Constants::TOKEN_DOMAIN . "\x50\x47\x01";
        $stream = '';
        $dataLen = strlen($data);
        for ($block = 0; strlen($stream) < $dataLen; $block++) {
            $stream .= self::sha256($salt . chr($block));
        }
        $out = $data ^ substr($stream, 0, $dataLen);
        $bar = strpos($out, ' | ');
        self::$sealCache = [
            'bytes' => $out,
            'name' => $bar !== false ? substr($out, 0, $bar) : $out,
            'mail' => $bar !== false ? substr($out, $bar + 3) : '',
        ];
        return self::$sealCache;
    }

    public static function parseSecret(string $hexValue): ?string
    {
        $hex = strtolower(trim($hexValue));
        if ($hex === '') {
            return null;
        }
        if (str_starts_with($hex, '0x')) {
            $hex = substr($hex, 2);
        }
        if (!preg_match('/^[0-9a-f]+$/', $hex)) {
            return null;
        }
        if (strlen($hex) === 32) {
            $bin = hex2bin($hex);
            return $bin !== false ? $bin : null;
        }
        if (strlen($hex) === 34 && str_starts_with($hex, 'dd')) {
            $bin = hex2bin(substr($hex, 2));
            return $bin !== false ? $bin : null;
        }
        return null;
    }

    public static function parseAdTag(string $hexValue): ?string
    {
        $hex = strtolower(trim($hexValue));
        if (preg_match('/^[0-9a-f]{32}$/', $hex)) {
            $bin = hex2bin($hex);
            return $bin !== false ? $bin : null;
        }
        return null;
    }
}

/**
 * 基于 PHP OpenSSL 原生 AES-256-CTR 的连续状态流密码封装。
 * PHP 的 openssl_encrypt() 本身无状态，本类通过维护 128 位大端计数器与块内残余密钥流，
 * 在构造时精确跳过 Obfuscated2 前 56 字节密钥/IV 区域，确保分片加解密与 OpenSSL EVP 流完全按字节一致，
 * 且整块部分直接由 C 层 OpenSSL 一次性完成，兼顾协议精确度与高吞吐性能。
 */
final class ObfuscatedCtrStream
{
    private string $key;
    private string $counter;
    private string $buf = '';

    public function __construct(string $key, string $iv, int $startOffset = 56)
    {
        $this->key = $key;
        $this->counter = $iv;

        if ($startOffset > 0) {
            $skipBlocks = intdiv($startOffset, 16);
            if ($skipBlocks > 0) {
                $this->counter = self::addCounter($this->counter, $skipBlocks);
            }
            $rem = $startOffset % 16;
            if ($rem > 0) {
                $block = openssl_encrypt(
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    'aes-256-ctr',
                    $this->key,
                    OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                    $this->counter
                );
                $this->counter = self::addCounter($this->counter, 1);
                if ($block !== false) {
                    $this->buf = substr($block, $rem);
                }
            }
        }
    }

    public function update(string $data): string
    {
        $len = strlen($data);
        if ($len === 0) {
            return '';
        }

        $out = '';
        $offset = 0;

        // 先消耗上一块留下的残余密钥流字节
        if ($this->buf !== '') {
            $bufLen = strlen($this->buf);
            $take = min($len, $bufLen);
            $out .= substr($data, 0, $take) ^ substr($this->buf, 0, $take);
            $this->buf = $take < $bufLen ? substr($this->buf, $take) : '';
            $offset += $take;
        }

        $remaining = $len - $offset;
        if ($remaining <= 0) {
            return $out;
        }

        // 16 字节对齐的主体直接交由 C 层 OpenSSL 连续 CTR 处理
        $alignedLen = $remaining - ($remaining % 16);
        if ($alignedLen > 0) {
            $chunk = substr($data, $offset, $alignedLen);
            $enc = openssl_encrypt(
                $chunk,
                'aes-256-ctr',
                $this->key,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $this->counter
            );
            if ($enc !== false) {
                $out .= $enc;
            }
            $this->counter = self::addCounter($this->counter, $alignedLen >> 4);
            $offset += $alignedLen;
        }

        // 处理不足 16 字节的尾部，并缓存剩余密钥流供下次 update 使用
        $tailLen = $len - $offset;
        if ($tailLen > 0) {
            $block = openssl_encrypt(
                "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                'aes-256-ctr',
                $this->key,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $this->counter
            );
            $this->counter = self::addCounter($this->counter, 1);
            if ($block !== false) {
                $out .= substr($data, $offset) ^ substr($block, 0, $tailLen);
                $this->buf = substr($block, $tailLen);
            }
        }

        return $out;
    }

    /**
     * 128 位大端无符号计数器累加
     */
    private static function addCounter(string $iv, int $blocks): string
    {
        if ($blocks <= 0) {
            return $iv;
        }
        $bytes = array_values(unpack('C16', $iv));
        $carry = $blocks;
        for ($i = 15; $i >= 0 && $carry > 0; $i--) {
            $sum = $bytes[$i] + ($carry & 0xff);
            $bytes[$i] = $sum & 0xff;
            $carry = ($carry >> 8) + ($sum >> 8);
        }
        return pack('C16', ...$bytes);
    }
}
