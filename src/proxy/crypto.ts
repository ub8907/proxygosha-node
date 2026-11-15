import { createCipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { BUILD_SEAL, TOKEN_DOMAIN } from "./constants.ts";

export interface SealInfo {
  bytes: Buffer;
  name: string;
  mail: string;
}

let sealCache: SealInfo | null = null;

export function concat(...parts: Uint8Array[]): Buffer {
  return Buffer.concat(parts);
}

export function reverse(bytes: Uint8Array): Buffer {
  const out = Buffer.allocUnsafe(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = bytes[bytes.length - 1 - i];
  }
  return out;
}

export function hexToBytes(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("hex");
}

export function b64uEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64url");
}

export function b64uDecodeStrict(value: string): Buffer | null {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const remainder = value.length % 4;
  if (remainder === 1) return null;
  try {
    const out = Buffer.from(value, "base64url");
    return b64uEncode(out) === value ? out : null;
  } catch {
    return null;
  }
}

export function sha256(bytes: Uint8Array): Buffer {
  return createHash("sha256").update(bytes).digest();
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Buffer {
  return createHmac("sha256", key).update(data).digest();
}

export function hmacVerify(key: Uint8Array, signature: Uint8Array, data: Uint8Array): boolean {
  const expected = hmacSha256(key, data);
  if (expected.length !== signature.length) return false;
  return timingSafeEqual(expected, signature);
}

export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(String(a), "utf8");
  const y = Buffer.from(String(b), "utf8");
  const len = Math.max(x.length, y.length);
  const px = Buffer.alloc(len);
  const py = Buffer.alloc(len);
  x.copy(px);
  y.copy(py);
  return timingSafeEqual(px, py) && x.length === y.length;
}

export function unseal(): SealInfo {
  if (sealCache) return sealCache;
  const data = Buffer.from(BUILD_SEAL, "base64");
  const salt = Buffer.concat([TOKEN_DOMAIN, Buffer.of(0x50, 0x47, 0x01)]);
  let stream = Buffer.alloc(0);
  for (let block = 0; stream.length < data.length; block++) {
    stream = Buffer.concat([stream, sha256(Buffer.concat([salt, Buffer.of(block)]))]);
  }
  const out = Buffer.allocUnsafe(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i] ^ stream[i];
  }
  const text = out.toString("utf8");
  const bar = text.indexOf(" | ");
  sealCache = {
    bytes: out,
    name: bar > 0 ? text.slice(0, bar) : text,
    mail: bar > 0 ? text.slice(bar + 3) : "",
  };
  return sealCache;
}

export function parseSecret(hexValue: string): Buffer | null {
  if (!hexValue) return null;
  let hex = String(hexValue).trim().toLowerCase();
  if (hex.startsWith("0x")) hex = hex.substring(2);
  if (!/^[0-9a-f]+$/.test(hex)) return null;
  if (hex.length === 32) return hexToBytes(hex);
  if (hex.length === 34 && hex.startsWith("dd")) return hexToBytes(hex.substring(2));
  return null;
}

export function parseAdTag(hexValue: string): Buffer | null {
  const hex = String(hexValue || "").trim().toLowerCase();
  if (/^[0-9a-f]{32}$/.test(hex)) return hexToBytes(hex);
  return null;
}

export function randomTokenBytes(size: number): Buffer {
  return randomBytes(size);
}

/**
 * 基于 Node.js 原生 OpenSSL 的高性能连续 AES-256-CTR 流密码封装。
 * 在构造时一次性跳过 Obfuscated2 头部前 56 字节的密钥/IV 区域，
 * 使得后续头部尾部（56..63 字节）与所有数据包加解密均可同步原地执行，无额外计数器重算开销。
 */
export class ObfuscatedCtrStream {
  private cipher;

  constructor(key: Uint8Array, iv: Uint8Array, startOffset = 56) {
    this.cipher = createCipheriv("aes-256-ctr", key, iv);
    if (startOffset > 0) {
      this.cipher.update(Buffer.alloc(startOffset));
    }
  }

  update(data: Uint8Array): Buffer {
    return this.cipher.update(data);
  }
}
