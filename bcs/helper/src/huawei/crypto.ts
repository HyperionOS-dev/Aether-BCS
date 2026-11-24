// BCS helper — Phase 3 (trust/auth): the crypto primitives the Huawei auth flow needs. Pure code:
// no socket, no process, no timer, no file, and — deliberately — no persistence of any key.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7 (GitHub mirror,
// frozen 2024-12-22), read-only:
//   util/CryptoUtils.java
//     encryptAES / decryptAES                     lines 44-56   AES/ECB/NoPadding
//     encryptAES_CBC_Pad / decryptAES_CBC_Pad     lines 58-72   AES/CBC/PKCS5Padding
//     encryptAES_GCM_NoPad / decryptAES_GCM_NoPad lines 74-94   AES/GCM/NoPadding, 128-bit tag
//     calcHmacSha256                              lines 96-101  HmacSHA256
//     digest                                      lines 103-106 SHA-256
//     hkdfSha256                                  lines 108-135 extract+expand, HMAC-SHA256
//     pbkdf2Sha256                                lines 137-141 PBKDF2WithHmacSHA256
//   devices/huawei/HuaweiCrypto.java
//     SECRET_KEY_* / DIGEST_SECRET_* / MESSAGE_*  lines 48-79
//     generateNonce                               lines 99-104  16 random bytes
//     getDigestSecret                             lines 106-116
//     computeDigest                               lines 117-129
//     computeDigestHiChainLite                    lines 131-152
//     digestChallenge / digestResponse            lines 154-192
//     decryptPinCode                              lines 243-252
//
// Deliberate divergences from upstream (all recorded in docs/BCS_PHASE3.md):
//  1. Every failure is a typed error, never an exception: upstream throws
//     HuaweiCrypto.CryptoException / NoSuchAlgorithmException / InvalidKeyException.
//  2. Nothing here logs. Upstream logs digests and hexdumps at debug level (e.g. GetHiChainRequest
//     logs the sessionKey); this port never passes key material to a logger, and no function in this
//     file takes one.
//  3. Key material is wiped where a buffer is ours to wipe (see zeroBytes) — best effort only,
//     because the runtime keeps its own internal copies that JavaScript cannot reach.
//  4. `HuaweiCrypto.createSecretKey(macAddress)` (lines 207-229) is NOT ported: it belongs to the
//     bonding path (GetBondRequest), which Phase 3 does not implement.
//
// On the static secrets below: they are upstream constants, published in Gadgetbridge's own source,
// and they are NOT the user's key. The user's key (the auth token) never appears in this file.

import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";

import { codecFail, codecOk, type CodecResult } from "./errors.ts";
import type { HuaweiAuthErrorCode } from "./authErrors.ts";

/** Wipe a buffer we own, best effort. Returns the same buffer, to allow `key = zeroBytes(key)`. */
export function zeroBytes(buffer: Uint8Array): Uint8Array {
  buffer.fill(0);
  return buffer;
}

/** Constant-time equality for MAC comparisons. Upstream uses Arrays.equals (:222), which is not. */
export function bytesEqualConstantTime(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

const fail = (code: HuaweiAuthErrorCode, message: string, detail: string | null = null): CodecResult<never> =>
  codecFail(code, message, null, detail) as CodecResult<never>;

/** SHA-256 (CryptoUtils.digest, :103). */
export function sha256(message: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(message).digest());
}

/** HmacSHA256 (CryptoUtils.calcHmacSha256, :96). `key` is the HMAC key, `message` the data. */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac("sha256", key).update(message).digest());
}

/**
 * HKDF-SHA256 (CryptoUtils.hkdfSha256, :109-135): extract is HMAC with `salt` as the key over
 * `secretKey`, then expand with `info` and a 1-based counter byte. Node's hkdf does exactly that,
 * and every upstream call site asks for 32 bytes.
 */
export function hkdfSha256(
  secretKey: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  outputLength: number,
): CodecResult<Uint8Array> {
  try {
    return codecOk(new Uint8Array(hkdfSync("sha256", secretKey, salt, info, outputLength)));
  } catch (error) {
    return fail("crypto-failed", "hkdf-sha256 failed", error instanceof Error ? error.message : null);
  }
}

/**
 * PBKDF2WithHmacSHA256 (CryptoUtils.pbkdf2Sha256, :137). Upstream passes *hexdump strings* as both
 * the password and the salt, so this takes strings and uses them as UTF-8. Only reached on the
 * HiChainLite path (authAlgo == 0x01).
 */
export function pbkdf2Sha256(
  key: string,
  salt: string,
  count: number,
  keyLengthBits: number,
): CodecResult<Uint8Array> {
  try {
    return codecOk(new Uint8Array(pbkdf2Sync(key, salt, count, Math.ceil(keyLengthBits / 8), "sha256")));
  } catch (error) {
    return fail("crypto-failed", "pbkdf2-sha256 failed", error instanceof Error ? error.message : null);
  }
}

function aesAlgorithm(mode: "gcm" | "cbc" | "ecb", keyLength: number): string | null {
  if (keyLength === 16) return `aes-128-${mode}`;
  if (keyLength === 24) return `aes-192-${mode}`;
  if (keyLength === 32) return `aes-256-${mode}`;
  return null;
}

/** AES-GCM/NoPadding, tag appended (CryptoUtils.encryptAES_GCM_NoPad, :74). */
export function aesGcmEncryptNoPad(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array | null,
): CodecResult<Uint8Array> {
  const algorithm = aesAlgorithm("gcm", key.length);
  if (!algorithm) return fail("bad-key", "aes-gcm needs a 16, 24 or 32 byte key", `got ${key.length}`);
  try {
    const cipher = createCipheriv(algorithm, key, iv, { authTagLength: 16 });
    if (aad) cipher.setAAD(Buffer.from(aad));
    const body = Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()]);
    return codecOk(new Uint8Array(Buffer.concat([body, cipher.getAuthTag()])));
  } catch (error) {
    return fail("crypto-failed", "aes-gcm encrypt failed", error instanceof Error ? error.message : null);
  }
}

/** AES-GCM/NoPadding, tag = last 16 bytes (CryptoUtils.decryptAES_GCM_NoPad, :85). */
export function aesGcmDecryptNoPad(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array | null,
): CodecResult<Uint8Array> {
  const algorithm = aesAlgorithm("gcm", key.length);
  if (!algorithm) return fail("bad-key", "aes-gcm needs a 16, 24 or 32 byte key", `got ${key.length}`);
  if (data.length < 16) return fail("bad-length", "aes-gcm input is shorter than its 16 byte tag");
  try {
    const decipher = createDecipheriv(algorithm, key, iv, { authTagLength: 16 });
    if (aad) decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(Buffer.from(data.subarray(data.length - 16)));
    const body = data.subarray(0, data.length - 16);
    return codecOk(new Uint8Array(Buffer.concat([decipher.update(Buffer.from(body)), decipher.final()])));
  } catch (error) {
    // A wrong key fails the tag check and lands here; the message must stay key-free.
    return fail("crypto-failed", "aes-gcm decrypt failed (wrong key or corrupt input)",
      error instanceof Error ? error.message : null);
  }
}

/** AES-CBC/PKCS5Padding (CryptoUtils.{en,de}cryptAES_CBC_Pad, :58-72); Node pads PKCS#7 by default. */
export function aesCbcPadEncrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): CodecResult<Uint8Array> {
  const algorithm = aesAlgorithm("cbc", key.length);
  if (!algorithm) return fail("bad-key", "aes-cbc needs a 16, 24 or 32 byte key", `got ${key.length}`);
  if (iv.length !== 16) return fail("bad-argument", "aes-cbc needs a 16 byte iv", `got ${iv.length}`);
  try {
    const cipher = createCipheriv(algorithm, key, iv);
    return codecOk(new Uint8Array(Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()])));
  } catch (error) {
    return fail("crypto-failed", "aes-cbc encrypt failed", error instanceof Error ? error.message : null);
  }
}

export function aesCbcPadDecrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): CodecResult<Uint8Array> {
  const algorithm = aesAlgorithm("cbc", key.length);
  if (!algorithm) return fail("bad-key", "aes-cbc needs a 16, 24 or 32 byte key", `got ${key.length}`);
  if (iv.length !== 16) return fail("bad-argument", "aes-cbc needs a 16 byte iv", `got ${iv.length}`);
  try {
    const decipher = createDecipheriv(algorithm, key, iv);
    return codecOk(new Uint8Array(Buffer.concat([decipher.update(Buffer.from(data)), decipher.final()])));
  } catch (error) {
    return fail("crypto-failed", "aes-cbc decrypt failed (wrong key or corrupt padding)",
      error instanceof Error ? error.message : null);
  }
}

/** AES/ECB/NoPadding (CryptoUtils.{en,de}cryptAES, :44-56). No IV by definition. */
export function aesEcbNoPadEncrypt(data: Uint8Array, key: Uint8Array): CodecResult<Uint8Array> {
  const algorithm = aesAlgorithm("ecb", key.length);
  if (!algorithm) return fail("bad-key", "aes-ecb needs a 16, 24 or 32 byte key", `got ${key.length}`);
  if (data.length % 16 !== 0) return fail("bad-length", "aes-ecb/NoPadding needs a multiple of 16 bytes");
  try {
    const cipher = createCipheriv(algorithm, key, null);
    cipher.setAutoPadding(false);
    return codecOk(new Uint8Array(Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()])));
  } catch (error) {
    return fail("crypto-failed", "aes-ecb encrypt failed", error instanceof Error ? error.message : null);
  }
}

export function aesEcbNoPadDecrypt(data: Uint8Array, key: Uint8Array): CodecResult<Uint8Array> {
  const algorithm = aesAlgorithm("ecb", key.length);
  if (!algorithm) return fail("bad-key", "aes-ecb needs a 16, 24 or 32 byte key", `got ${key.length}`);
  if (data.length % 16 !== 0) return fail("bad-length", "aes-ecb/NoPadding needs a multiple of 16 bytes");
  try {
    const decipher = createDecipheriv(algorithm, key, null);
    decipher.setAutoPadding(false);
    return codecOk(new Uint8Array(Buffer.concat([decipher.update(Buffer.from(data)), decipher.final()])));
  } catch (error) {
    return fail("crypto-failed", "aes-ecb decrypt failed", error instanceof Error ? error.message : null);
  }
}

/**
 * Upstream's hex alphabet is UPPERCASE — GB.java:368 `HEX_CHARS = "0123456789ABCDEF"` — and
 * `StringUtils.bytesToHex` is `GB.hexdump` (StringUtils.java:189). Every hex string that goes into a
 * HiChain JSON payload, and every hexdump fed to a digest, is therefore uppercase. Getting this wrong
 * would silently change MAC inputs, so it is a named constant here rather than a `toString(16)`.
 */
export const HEX_CHARS = "0123456789ABCDEF";

/** GB.hexdump (:369-383): uppercase, no separators. */
export function hexdumpUpper(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += HEX_CHARS[byte >>> 4] + HEX_CHARS[byte & 0x0f];
  return out;
}

/** StringUtils.hexToBytes (:193): accepts either case, rejects anything else. */
export function hexToBytes(hex: string): CodecResult<Uint8Array> {
  const trimmed = hex.trim();
  if (trimmed.length % 2 !== 0) return fail("bad-argument", "hex string has an odd length");
  const out = new Uint8Array(trimmed.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const pair = trimmed.slice(i * 2, i * 2 + 2);
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) {
      return fail("bad-argument", "hex string contains a non-hex character", `at offset ${i * 2}`);
    }
    out[i] = Number.parseInt(pair, 16);
  }
  return codecOk(out);
}

/** HuaweiCrypto.MESSAGE_RESPONSE / MESSAGE_CHALLENGE (:78-79). */
export const MESSAGE_RESPONSE = Uint8Array.of(0x01, 0x10);
export const MESSAGE_CHALLENGE = Uint8Array.of(0x01, 0x00);

/** HuaweiCrypto.DIGEST_SECRET_v1/v2/v3 (:65-76). Static upstream constants, not anyone's key. */
export const DIGEST_SECRET_V1 = Uint8Array.from([
  0x70, 0xfb, 0x6c, 0x24, 0x03, 0x5f, 0xdb, 0x55, 0x2f, 0x38, 0x89, 0x8a, 0xee, 0xde, 0x3f, 0x69,
]);
export const DIGEST_SECRET_V2 = Uint8Array.from([
  0x93, 0xac, 0xde, 0xf7, 0x6a, 0xcb, 0x09, 0x85, 0x7d, 0xbf, 0xe5, 0x26, 0x1a, 0xab, 0xcd, 0x78,
]);
export const DIGEST_SECRET_V3 = Uint8Array.from([
  0x9c, 0x27, 0x63, 0xa9, 0xcc, 0xe1, 0x34, 0x76, 0x6d, 0xe3, 0xff, 0x61, 0x18, 0x20, 0x05, 0x53,
]);

/** HuaweiCrypto.generateNonce (:99-104): 16 random bytes. `random` is injectable for tests. */
export function generateNonce(
  length = 16,
  random: (n: number) => Uint8Array = (n) => new Uint8Array(randomBytes(n)),
): Uint8Array {
  return random(length);
}

/** The four link parameters upstream carries on `HuaweiCrypto` (:83-97). */
export interface HuaweiCryptoContext {
  authVersion: number;
  deviceSupportType: number;
  authAlgo: number;
  authMode: number;
}

/**
 * The stateful half of `HuaweiCrypto` (:83-192, :243-252), as a factory over the four parameters the
 * device reports. Only the HiChain digest and pin-code helpers are here: the encrypt/decrypt wrappers
 * are plain functions above, and `createSecretKey(macAddress)` is the bonding path, not ported.
 */
export function createHuaweiCrypto(context: HuaweiCryptoContext) {
  const { authVersion, authAlgo, authMode } = context;

  /** getDigestSecret (:106-116): v1 for authVersion 1, v2 for 2, v3 otherwise. */
  const digestSecret = authVersion === 1
    ? DIGEST_SECRET_V1
    : authVersion === 2 ? DIGEST_SECRET_V2 : DIGEST_SECRET_V3;

  /**
   * computeDigest (:117-129): HMAC-SHA256(key=nonce, digestSecret‖message) = step1, then
   * HMAC-SHA256(key=step1, nonce) ‖ step1 — 64 bytes. This is the keyless path.
   */
  function computeDigest(message: Uint8Array, nonce: Uint8Array): Uint8Array {
    const msgToDigest = new Uint8Array(digestSecret.length + message.length);
    msgToDigest.set(digestSecret, 0);
    msgToDigest.set(message, digestSecret.length);
    const digestStep1 = hmacSha256(nonce, msgToDigest);
    const challenge = new Uint8Array(0x40);
    challenge.set(hmacSha256(digestStep1, nonce), 0);
    challenge.set(digestStep1, 0x20);
    zeroBytes(msgToDigest);
    zeroBytes(digestStep1);
    return challenge;
  }

  /**
   * computeDigestHiChainLite (:131-152): the digest secret is XOR-ed with SHA-256(hexdump(key)) and
   * the HMAC (or, when authAlgo == 0x01, PBKDF2 over the *hexdump strings*) uses the key's digest.
   * Note that upstream feeds `GB.hexdump` output — uppercase — into both the digest and the PBKDF2
   * password/salt, which is why hexdumpUpper exists.
   */
  function computeDigestHiChainLite(
    message: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
  ): CodecResult<Uint8Array> {
    const hashKey = sha256(Buffer.from(hexdumpUpper(key), "utf8"));
    const mixed = Uint8Array.from(digestSecret, (byte, index) => (hashKey[index] ^ byte) & 0xff);
    const msgToDigest = new Uint8Array(mixed.length + message.length);
    msgToDigest.set(mixed, 0);
    msgToDigest.set(message, mixed.length);

    let digestStep1: Uint8Array;
    if (authAlgo === 0x01) {
      const derived = pbkdf2Sha256(hexdumpUpper(msgToDigest), hexdumpUpper(nonce), 0x3e8, 0x100);
      if (!derived.ok) return derived;
      digestStep1 = derived.value;
    } else {
      digestStep1 = hmacSha256(nonce, msgToDigest);
    }

    const challenge = new Uint8Array(0x40);
    challenge.set(hmacSha256(digestStep1, nonce), 0);
    challenge.set(digestStep1, 0x20);
    zeroBytes(hashKey);
    zeroBytes(mixed);
    zeroBytes(msgToDigest);
    zeroBytes(digestStep1);
    return codecOk(challenge);
  }

  /**
   * digestChallenge (:154-172) / digestResponse (:174-192), which differ only in the message tag:
   * 0x0100 for the challenge, 0x0110 for the response. When authMode is 0x02 the key participates:
   * for authVersion 0x02 the challenge is HMAC-SHA256(key=key‖message, nonce) ‖ key‖message, else the
   * HiChainLite digest. With no authMode 0x02 the static digest chain is used and `secretKey` is
   * ignored. A missing key in authMode 0x02 yields null, exactly as upstream.
   */
  function digestWith(message: Uint8Array, secretKey: Uint8Array | null, nonce: Uint8Array): CodecResult<Uint8Array | null> {
    if (authMode !== 0x02) return codecOk(computeDigest(message, nonce));
    if (!secretKey || secretKey.length === 0) return codecOk(null);
    if (authVersion === 0x02) {
      const key = new Uint8Array(secretKey.length + message.length);
      key.set(secretKey, 0);
      key.set(message, secretKey.length);
      const challenge = new Uint8Array(0x40);
      challenge.set(hmacSha256(key, nonce), 0);
      challenge.set(key, 0x20);
      zeroBytes(key);
      return codecOk(challenge);
    }
    return computeDigestHiChainLite(message, secretKey, nonce);
  }

  return {
    digestSecret,
    computeDigest,
    computeDigestHiChainLite,
    digestChallenge: (secretKey: Uint8Array | null, nonce: Uint8Array) =>
      digestWith(MESSAGE_CHALLENGE, secretKey, nonce),
    digestResponse: (secretKey: Uint8Array | null, nonce: Uint8Array) =>
      digestWith(MESSAGE_RESPONSE, secretKey, nonce),
    /**
     * decryptPinCode (:243-252): the pin code the watch displays is AES-encrypted with the *static*
     * digest secret (not the user's key), GCM when encryptMethod is 1, CBC-Pad otherwise.
     * PinCode.Response (:1419-1462) is the only caller.
     */
    decryptPinCode(encryptMethod: number, message: Uint8Array, iv: Uint8Array): CodecResult<Uint8Array> {
      const useGcm = encryptMethod === 0x01;
      return useGcm
        ? aesGcmDecryptNoPad(message, digestSecret, iv, null)
        : aesCbcPadDecrypt(message, digestSecret, iv);
    },
  };
}

export type HuaweiCrypto = ReturnType<typeof createHuaweiCrypto>;
