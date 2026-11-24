// BCS helper — Phase 3 (trust/auth) tests: the crypto primitives.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7 (GitHub mirror, frozen
// 2024-12-22), read-only: util/CryptoUtils.java :44-141, devices/huawei/HuaweiCrypto.java :48-252.
//
// Upstream ships exactly one crypto test (TestHuaweiCrypto.java: nonce length and spread, 1000 rounds)
// and no vectors at all, so every value asserted below comes from a published standard instead of from
// upstream: FIPS-197 (AES-128 ECB), NIST SP 800-38A F.2.1 (AES-128-CBC), RFC 4231 case 1 (HMAC-SHA256),
// RFC 5869 case 1 (HKDF-SHA256) and the well-known PBKDF2-HMAC-SHA256 vectors. Where no vector exists,
// the test recomputes the value a second way — a hand-rolled extract/expand loop, a manual PBKDF2
// loop — and compares the two.
//
// No radio, no watch, no real key, no health data, and nothing is ever sent anywhere. Every key below
// is a published test vector or a fixed byte pattern.

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { createHash, createHmac, hkdfSync, pbkdf2Sync } from "node:crypto";

import {
  DIGEST_SECRET_V1,
  DIGEST_SECRET_V2,
  DIGEST_SECRET_V3,
  HEX_CHARS,
  MESSAGE_CHALLENGE,
  MESSAGE_RESPONSE,
  aesCbcPadDecrypt,
  aesCbcPadEncrypt,
  aesEcbNoPadDecrypt,
  aesEcbNoPadEncrypt,
  aesGcmDecryptNoPad,
  aesGcmEncryptNoPad,
  bytesEqualConstantTime,
  createHuaweiCrypto,
  generateNonce,
  hexdumpUpper,
  hexToBytes,
  hkdfSha256,
  hmacSha256,
  pbkdf2Sha256,
  sha256,
  zeroBytes,
} from "../src/huawei/crypto.ts";

type Result<T> = { ok: true; value: T } | { ok: false; error: { code: string; message: string; detail: string | null } };
const ok = <T>(result: Result<T>): T => {
  if (!result.ok) throw new Error(`expected success, got ${result.error.code}: ${result.error.message}`);
  return result.value;
};
const bad = <T>(result: Result<T>): { code: string; message: string; detail: string | null } => {
  if (result.ok) throw new Error("expected a typed failure");
  return result.error;
};
const bytes = (...values: number[]): Uint8Array => Uint8Array.from(values);
const hex = (text: string): Uint8Array => new Uint8Array(Buffer.from(text.replace(/\s/g, ""), "hex"));
const hexOf = (value: Uint8Array): string => Buffer.from(value).toString("hex");
const repeat = (byte: number, count: number): Uint8Array => new Uint8Array(count).fill(byte);
const utf8 = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "utf8"));

const AES_128_KEY = hex("000102030405060708090a0b0c0d0e0f");
const ZERO_IV = repeat(0x00, 16);

// A second, hand-rolled HKDF (RFC 5869 extract then expand) and PBKDF2, so the wrapper is checked
// against an implementation that shares no code with it — neither the port's nor Node's convenience one.
const manualHkdf = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array => {
  const prk = createHmac("sha256", salt).update(ikm).digest();
  const blocks: Buffer[] = [];
  let previous = Buffer.alloc(0);
  for (let counter = 1; previous.length < length; counter += 1) {
    previous = createHmac("sha256", prk)
      .update(Buffer.concat([previous, Buffer.from(info), Buffer.from([counter])]))
      .digest();
    blocks.push(previous);
  }
  return new Uint8Array(Buffer.concat(blocks).subarray(0, length));
};

const manualPbkdf2 = (password: string, salt: string, count: number, length: number): Uint8Array => {
  const pass = Buffer.from(password, "utf8");
  let u = createHmac("sha256", pass)
    .update(Buffer.concat([Buffer.from(salt, "utf8"), Buffer.from([0, 0, 0, 1])]))
    .digest();
  const out = Buffer.from(u);
  for (let round = 1; round < count; round += 1) {
    u = createHmac("sha256", pass).update(u).digest();
    for (let index = 0; index < out.length; index += 1) out[index] ^= u[index];
  }
  return new Uint8Array(out.subarray(0, length));
};

describe("crypto — digests, HMAC, HKDF and PBKDF2, against published vectors", () => {
  test("sha256 reproduces the empty- and short-message vectors", () => {
    assert.equal(hexOf(sha256(new Uint8Array(0))),
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert.equal(hexOf(sha256(utf8("abc"))),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  test("hmacSha256 reproduces RFC 4231 case 1, key first and message second", () => {
    const mac = hmacSha256(repeat(0x0b, 20), utf8("Hi There"));
    assert.equal(hexOf(mac), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert.equal(mac.length, 32);
    // The argument order is easy to get backwards; reversing it must not give the same MAC.
    assert.notEqual(hexOf(hmacSha256(utf8("Hi There"), repeat(0x0b, 20))), hexOf(mac));
  });

  test("hkdfSha256 reproduces RFC 5869 case 1 and agrees with a hand-rolled extract/expand", () => {
    const ikm = repeat(0x0b, 22);
    const salt = hex("000102030405060708090a0b0c");
    const info = hex("f0f1f2f3f4f5f6f7f8f9");
    const okm = ok(hkdfSha256(ikm, salt, info, 32));
    assert.equal(hexOf(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");
    assert.deepEqual(ok(hkdfSha256(ikm, salt, info, 32)), manualHkdf(ikm, salt, info, 32));
    // The HiChain strings are the real call sites: info is always one of these two, length always 32.
    for (const label of ["hichain_iso_session_key", "hichain_return_key"]) {
      const psk = hmacSha256(repeat(0x41, 32), repeat(0x42, 16));
      const salt2 = new Uint8Array([...repeat(0x11, 16), ...repeat(0x22, 16)]);
      assert.deepEqual(ok(hkdfSha256(psk, salt2, utf8(label), 32)), manualHkdf(psk, salt2, utf8(label), 32));
    }
    // node's hkdfSync caps expansion at 255 * 32 bytes; that must surface as a typed failure.
    assert.equal(bad(hkdfSha256(ikm, salt, info, 9000)).code, "crypto-failed");
  });

  test("pbkdf2Sha256 reproduces the standard c=1 and c=2 vectors, and a hand-rolled loop at 1000", () => {
    // The length argument is in bits, as upstream's KeySpec takes it: 256 bits is 32 bytes.
    assert.equal(hexOf(ok(pbkdf2Sha256("password", "salt", 1, 256))),
      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    assert.equal(hexOf(ok(pbkdf2Sha256("password", "salt", 2, 256))),
      "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    assert.equal(ok(pbkdf2Sha256("password", "salt", 1, 32)).length, 4);
    // Upstream's HiChainLite call site: 0x3e8 rounds for 0x100 bits, over hexdump *strings*.
    const hexPass = "000102030405060708090A0B0C0D0E0F";
    const hexSalt = "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    const derived = ok(pbkdf2Sha256(hexPass, hexSalt, 0x3e8, 0x100));
    assert.equal(derived.length, 32);
    assert.deepEqual(derived, manualPbkdf2(hexPass, hexSalt, 0x3e8, 32));
    assert.equal(bad(pbkdf2Sha256("a", "b", 0, 32)).code, "crypto-failed");
  });
});

describe("crypto — hex, buffer hygiene and the nonce", () => {
  test("hexdumpUpper is uppercase, and matches Buffer's lowercase render, byte for byte", () => {
    const sample = bytes(0x00, 0x01, 0x0a, 0x0f, 0x10, 0x7f, 0x80, 0xff);
    assert.equal(hexdumpUpper(sample), "00010A0F107F80FF");
    assert.equal(hexdumpUpper(sample), hexOf(sample).toUpperCase());
    assert.equal(HEX_CHARS, "0123456789ABCDEF");
    assert.equal(hexdumpUpper(new Uint8Array(0)), "");
    // All 256 values, so no nibble mapping can be off by one.
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    assert.equal(hexdumpUpper(all), hexOf(all).toUpperCase());
  });

  test("hexToBytes accepts either case and reports what is wrong with the rest", () => {
    assert.deepEqual(ok(hexToBytes("00ffFF")), bytes(0x00, 0xff, 0xff));
    assert.deepEqual(ok(hexToBytes(" 0A0b ")), bytes(0x0a, 0x0b));
    assert.deepEqual(ok(hexToBytes("")), new Uint8Array(0));
    assert.equal(bad(hexToBytes("abc")).code, "bad-argument");
    assert.equal(bad(hexToBytes("zz")).detail, "at offset 0");
    assert.equal(bad(hexToBytes("00ZZ")).detail, "at offset 2");
    // The round trip is what matters: every key hex string in the flow goes through both.
    const key = Uint8Array.from({ length: 32 }, (_, i) => (i * 7) & 0xff);
    assert.deepEqual(ok(hexToBytes(hexdumpUpper(key))), key);
  });

  test("zeroBytes wipes in place and returns the same buffer, and equality is length-aware", () => {
    const secret = bytes(1, 2, 3, 4);
    assert.equal(zeroBytes(secret), secret);
    assert.deepEqual(secret, bytes(0, 0, 0, 0));
    assert.equal(bytesEqualConstantTime(bytes(1, 2, 3), bytes(1, 2, 3)), true);
    assert.equal(bytesEqualConstantTime(bytes(1, 2, 3), bytes(1, 2, 4)), false);
    assert.equal(bytesEqualConstantTime(bytes(1, 2, 3), bytes(1, 2)), false);
    assert.equal(bytesEqualConstantTime(new Uint8Array(0), new Uint8Array(0)), true);
  });

  test("generateNonce is 16 bytes by default and takes its randomness from the caller", () => {
    assert.equal(generateNonce().length, 16);
    assert.equal(generateNonce(12).length, 12);
    let asked: number | null = null;
    const injected = generateNonce(16, (n) => {
      asked = n;
      return new Uint8Array(n).fill(0x5a);
    });
    assert.equal(asked, 16);
    assert.deepEqual(injected, repeat(0x5a, 16));
    // The one upstream crypto test (TestHuaweiCrypto.java): 1000 nonces, all 16 bytes, not all equal.
    const seen = new Set<string>();
    for (let round = 0; round < 1000; round += 1) {
      const nonce = generateNonce();
      assert.equal(nonce.length, 16);
      seen.add(hexdumpUpper(nonce));
    }
    assert.ok(seen.size > 990, `nonces look repetitive: ${seen.size} distinct of 1000`);
  });
});

describe("crypto — AES, against published vectors", () => {
  test("AES/ECB/NoPadding reproduces FIPS-197's worked example, and round-trips", () => {
    const plain = hex("00112233445566778899aabbccddeeff");
    const cipher = ok(aesEcbNoPadEncrypt(plain, AES_128_KEY));
    assert.equal(hexOf(cipher), "69c4e0d86a7b0430d8cdb78070b4c55a");
    assert.deepEqual(ok(aesEcbNoPadDecrypt(cipher, AES_128_KEY)), plain);
  });

  test("AES/CBC/PKCS5Padding reproduces NIST SP 800-38A F.2.1's first block and pads fully", () => {
    const key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    const iv = hex("000102030405060708090a0b0c0d0e0f");
    const plain = hex("6bc1bee22e409f96e93d7e117393172a"
      + "ae2d8a571e03ac9c9eb76fac45af8e51"
      + "30c81c46a35ce411e5fbc1191a0a52ef"
      + "f69f2445df4f9b17ad2b417be66c3710");
    const cipher = ok(aesCbcPadEncrypt(plain, key, iv));
    // Four blocks in, five out: PKCS#7 always appends a whole block when the input is a multiple of 16.
    assert.equal(cipher.length, 80);
    assert.equal(hexOf(cipher.subarray(0, 16)), "7649abac8119b246cee98e9b12e9197d");
    assert.deepEqual(ok(aesCbcPadDecrypt(cipher, key, iv)), plain);
  });

  test("AES/GCM keeps the 128-bit tag in the last 16 bytes and round-trips with and without AAD", () => {
    const key = hex("feffe9928665731c6d6a8f9467308308");
    const iv = hex("cafebabefacedbaddecaf888");
    const plain = hex("00112233445566778899aabbccddeeff");
    const aad = utf8("hichain_iso_result");
    const sealed = ok(aesGcmEncryptNoPad(plain, key, iv, aad));
    assert.equal(sealed.length, plain.length + 16);
    assert.deepEqual(ok(aesGcmDecryptNoPad(sealed, key, iv, aad)), plain);
    // A different AAD is a different transaction: the tag must not verify.
    const noAad = ok(aesGcmEncryptNoPad(plain, key, iv, null));
    assert.deepEqual(ok(aesGcmDecryptNoPad(noAad, key, iv, null)), plain);
    assert.equal(bad(aesGcmDecryptNoPad(noAad, key, iv, aad)).code, "crypto-failed");
  });

  test("AES/GCM fails, and says nothing about the key, on a flipped bit, a wrong key or a short input", () => {
    const key = hex("feffe9928665731c6d6a8f9467308308");
    const iv = hex("cafebabefacedbaddecaf888");
    const sealed = ok(aesGcmEncryptNoPad(hex("00112233445566778899aabbccddeeff"), key, iv, null));
    for (const index of [0, 3, sealed.length - 1, sealed.length - 16]) {
      const tampered = Uint8Array.from(sealed);
      tampered[index] ^= 0x01;
      const error = bad(aesGcmDecryptNoPad(tampered, key, iv, null));
      assert.equal(error.code, "crypto-failed", `flipping byte ${index} must fail the tag check`);
      assert.match(error.message, /wrong key or corrupt input/);
      assert.equal(error.message.includes("feffe992"), false);
    }
    const wrongKey = hex("00112233445566778899aabbccddee00");
    assert.equal(bad(aesGcmDecryptNoPad(sealed, wrongKey, iv, null)).code, "crypto-failed");
    // 15 bytes cannot even hold the tag, so it is a length error before the cipher is built.
    assert.equal(bad(aesGcmDecryptNoPad(sealed.subarray(0, 15), key, iv, null)).code, "bad-length");
  });

  test("all three AES key sizes are accepted, and anything else is a bad-key before the cipher runs", () => {
    for (const keyLength of [16, 24, 32]) {
      const key = Uint8Array.from({ length: keyLength }, (_, i) => i + 1);
      const sealed = ok(aesGcmEncryptNoPad(bytes(1, 2, 3), key, ZERO_IV, null));
      assert.deepEqual(ok(aesGcmDecryptNoPad(sealed, key, ZERO_IV, null)), bytes(1, 2, 3));
      const padded = ok(aesCbcPadEncrypt(bytes(1, 2, 3), key, ZERO_IV));
      assert.deepEqual(ok(aesCbcPadDecrypt(padded, key, ZERO_IV)), bytes(1, 2, 3));
      const block = hex("00112233445566778899aabbccddeeff");
      assert.deepEqual(ok(aesEcbNoPadDecrypt(ok(aesEcbNoPadEncrypt(block, key)), key)), block);
    }
    assert.equal(bad(aesGcmEncryptNoPad(bytes(1), repeat(0, 15), ZERO_IV, null)).detail, "got 15");
    assert.equal(bad(aesGcmDecryptNoPad(bytes(...new Array(20).fill(0)), repeat(0, 15), ZERO_IV, null)).code, "bad-key");
    assert.equal(bad(aesCbcPadEncrypt(bytes(1), AES_128_KEY, repeat(0, 12))).code, "bad-argument");
    // ECB is the only mode with a block-alignment requirement of its own.
    assert.equal(bad(aesEcbNoPadEncrypt(bytes(1, 2, 3), AES_128_KEY)).code, "bad-length");
    assert.equal(bad(aesEcbNoPadDecrypt(bytes(...new Array(20).fill(0)), AES_128_KEY)).code, "bad-length");
  });
});
describe("crypto — the stateful HiChain digest helpers (HuaweiCrypto :83-192, :243-252)", () => {
  const context = (
    over: Partial<{ authVersion: number; deviceSupportType: number; authAlgo: number; authMode: number }> = {},
  ) => ({ authVersion: 2, deviceSupportType: 0x04, authAlgo: 0, authMode: 0x04, ...over });

  test("the digest secret follows authVersion: v1, v2, and v3 for anything else", () => {
    assert.equal(createHuaweiCrypto(context({ authVersion: 1 })).digestSecret, DIGEST_SECRET_V1);
    assert.equal(createHuaweiCrypto(context({ authVersion: 2 })).digestSecret, DIGEST_SECRET_V2);
    assert.equal(createHuaweiCrypto(context({ authVersion: 0 })).digestSecret, DIGEST_SECRET_V3);
    assert.equal(createHuaweiCrypto(context({ authVersion: 9 })).digestSecret, DIGEST_SECRET_V3);
    const secrets = [DIGEST_SECRET_V1, DIGEST_SECRET_V2, DIGEST_SECRET_V3];
    for (const secret of secrets) assert.equal(secret.length, 16);
    assert.equal(new Set(secrets.map(hexOf)).size, 3);
  });

  test("computeDigest is the keyless chain HMAC(step1, nonce) then step1 (CryptoUtils :117-129)", () => {
    const huawei = createHuaweiCrypto(context({ authVersion: 2 }));
    const nonce = repeat(0x11, 16);
    const message = MESSAGE_CHALLENGE;
    const step1 = createHmac("sha256", nonce)
      .update(Buffer.concat([Buffer.from(DIGEST_SECRET_V2), Buffer.from(message)]))
      .digest();
    const expected = Buffer.concat([createHmac("sha256", step1).update(nonce).digest(), step1]);
    const digest = huawei.computeDigest(message, nonce);
    assert.equal(digest.length, 0x40);
    assert.deepEqual(digest, new Uint8Array(expected));
    // The key is nowhere in this path: computeDigest takes a message and a nonce and nothing else.
    assert.equal(huawei.computeDigest.length, 2);
  });


  test("computeDigestHiChainLite XORs the secret with SHA-256(hexdump(key)) (:131-152)", () => {
    const key = hex("00112233445566778899AABBCCDDEEFF");
    const nonce = repeat(0x33, 16);
    const message = MESSAGE_RESPONSE;
    const hashKey = createHash("sha256").update(hexdumpUpper(key), "utf8").digest();
    const mixed = Buffer.from(DIGEST_SECRET_V2.map((byte, index) => byte ^ hashKey[index]));
    const msgToDigest = Buffer.concat([mixed, Buffer.from(message)]);
    const step1 = createHmac("sha256", nonce).update(msgToDigest).digest();
    const hmacBranch = createHuaweiCrypto(context({ authMode: 0x02, authAlgo: 0x00 }));
    assert.deepEqual(ok(hmacBranch.computeDigestHiChainLite(message, key, nonce)),
      new Uint8Array(Buffer.concat([createHmac("sha256", step1).update(nonce).digest(), step1])));
    // authAlgo 0x01 replaces that first HMAC with PBKDF2 over the *hexdump strings* (note the case).
    const pbkdf2 = createHuaweiCrypto(context({ authMode: 0x02, authAlgo: 0x01 }));
    const derived = ok(pbkdf2Sha256(hexdumpUpper(msgToDigest), hexdumpUpper(nonce), 0x3e8, 0x100));
    assert.deepEqual(ok(pbkdf2.computeDigestHiChainLite(message, key, nonce)),
      new Uint8Array(Buffer.concat([createHmac("sha256", derived).update(nonce).digest(), derived])));
  });

  test("digestChallenge and digestResponse differ only in the message tag, and ignore the key at mode 4", () => {
    const keyless = createHuaweiCrypto(context());
    const nonce = repeat(0x44, 16);
    const key = repeat(0x55, 32);
    assert.deepEqual(MESSAGE_CHALLENGE, bytes(0x01, 0x00));
    assert.deepEqual(MESSAGE_RESPONSE, bytes(0x01, 0x10));
    assert.deepEqual(ok(keyless.digestChallenge(key, nonce)), keyless.computeDigest(MESSAGE_CHALLENGE, nonce));
    assert.deepEqual(ok(keyless.digestResponse(key, nonce)), keyless.computeDigest(MESSAGE_RESPONSE, nonce));
    assert.notDeepEqual(ok(keyless.digestResponse(key, nonce)), ok(keyless.digestChallenge(key, nonce)));
    const otherKey = repeat(0x00, 32);
    assert.deepEqual(ok(keyless.digestChallenge(otherKey, nonce)), ok(keyless.digestChallenge(key, nonce)));
  });

  test("at authMode 0x02 the key joins the transaction, and a missing key is null (:154-192)", () => {
    const joined = createHuaweiCrypto(context({ authMode: 0x02, authVersion: 0x02 }));
    const key = repeat(0x77, 16);
    const nonce = repeat(0x66, 16);
    const payload = new Uint8Array([...key, ...MESSAGE_CHALLENGE]);
    const expected = new Uint8Array(0x40);
    expected.set(hmacSha256(payload, nonce), 0);
    expected.set(payload, 0x20);
    assert.deepEqual(ok(joined.digestChallenge(key, nonce)), expected);
    assert.equal(ok(joined.digestChallenge(null, nonce)), null);
    assert.equal(ok(joined.digestChallenge(new Uint8Array(0), nonce)), null);
    // authMode 0x02 with an authVersion that is not 0x02 falls through to the HiChainLite digest.
    const lite = createHuaweiCrypto(context({ authMode: 0x02, authVersion: 0x03 }));
    assert.deepEqual(ok(lite.digestChallenge(key, nonce)), ok(lite.computeDigestHiChainLite(MESSAGE_CHALLENGE, key, nonce)));
  });

  test("decryptPinCode uses the static digest secret of the negotiated version (:243-252)", () => {
    const version2 = createHuaweiCrypto(context({ authVersion: 0x02 }));
    const pin = utf8("123456");
    const iv = repeat(0x88, 16);
    const gcm = ok(aesGcmEncryptNoPad(pin, DIGEST_SECRET_V2, iv, null));
    assert.deepEqual(ok(version2.decryptPinCode(1, gcm, iv)), pin);
    const cbc = ok(aesCbcPadEncrypt(pin, DIGEST_SECRET_V2, iv));
    assert.deepEqual(ok(version2.decryptPinCode(0, cbc, iv)), pin);
    // Anything that is not 1 takes the CBC branch, exactly as upstream's ternary does.
    assert.deepEqual(ok(version2.decryptPinCode(9, cbc, iv)), pin);
    // A different authVersion means a different secret: v3 cannot open a v2 transaction.
    const version3 = createHuaweiCrypto(context({ authVersion: 0x03 }));
    assert.equal(bad(version3.decryptPinCode(1, gcm, iv)).code, "crypto-failed");
    const gcmV3 = ok(aesGcmEncryptNoPad(pin, DIGEST_SECRET_V3, iv, null));
    assert.deepEqual(ok(version3.decryptPinCode(1, gcmV3, iv)), pin);
  });
});

