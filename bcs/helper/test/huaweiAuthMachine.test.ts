// BCS helper — Phase 3 (trust/auth) tests: the auth state machine, driven by synthetic frames only.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7 (GitHub mirror, frozen
// 2024-12-22), read-only: service/devices/huawei/requests/GetHiChainRequest.java :38-262 and
// service/devices/huawei/HuaweiSupportProvider.java :405-578, :677-699.
//
// There is no radio, no watch, no real key and no health data anywhere in this file. The watch is
// simulated by building the reply TLVs by hand; the key is a synthetic 32-byte constant; the RNG and
// the request id are injected so every run produces the same bytes. Nothing here opens a socket, and
// nothing here is ever sent anywhere.
//
// What these tests are for: the *sequence* (which frame is expected in which state), the *arithmetic*
// (which token is sent, which is verified, which message id each step carries, which key is derived
// from what), and the *refusals* (every way the flow can stop, and the promise that a stop carries no
// key material).

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { createAuthMachine, DEFAULT_PHONE_MODEL, validatePhoneModel, type AuthMachine, type AuthOutput } from "../src/huawei/authMachine.ts";
import { HI_CHAIN_GROUP_ID } from "../src/huawei/authPackets.ts";
import { DEVICE_CONFIG } from "../src/huawei/constants.ts";
import {
  DIGEST_SECRET_V2,
  aesGcmDecryptNoPad,
  aesGcmEncryptNoPad,
  hexToBytes,
  hexdumpUpper,
  hkdfSha256,
  hmacSha256,
  sha256,
} from "../src/huawei/crypto.ts";
import type { HuaweiFrame } from "../src/huawei/frame.ts";
import { decodeFrames } from "../src/huawei/stream.ts";
import { HuaweiTlv } from "../src/huawei/tlv.ts";

type Result<T> =
  | { ok: true; value: T }
  | { ok: false; error: { code: string; message: string; detail: string | null } };

const ok = <T>(result: Result<T>): T => {
  if (!result.ok) throw new Error(`expected success, got ${result.error.code}: ${result.error.message}`);
  return result.value;
};
const failure = <T>(result: Result<T>): { code: string; message: string; detail: string | null } => {
  if (result.ok) throw new Error("expected a typed failure");
  return result.error;
};
const bytes = (...values: number[]): Uint8Array => Uint8Array.from(values);
const hex = (text: string): Uint8Array => ok(hexToBytes(text));
const utf8 = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "utf8"));
const hexOf = (value: Uint8Array): string => hexdumpUpper(value);
const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

/** A synthetic 32-byte auth key. Not a real key, not derived from one, and never printed by the code. */
const AUTH_KEY = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
/** selfAuthId: 32 UTF-8 characters, the shape upstream's getAndroidId() produces. */
const ANDROID_ID = utf8("0123456789abcdef0123456789abcdef");
/** Fixed request id, so the step-1 JSON is byte-stable across runs. */
const FIXED_REQUEST_ID = 1730000000000n;

/** Counter-based RNG: deterministic, and different for every call, as a real RNG would be. */
function deterministicRandom(): (n: number) => Uint8Array {
  let call = 0;
  return (n: number) => {
    call += 1;
    return Uint8Array.from({ length: n }, (_, index) => (call * 0x11 + index * 7) & 0xff);
  };
}

function machineWith(over: Partial<Parameters<typeof createAuthMachine>[0]> = {}): AuthMachine {
  return createAuthMachine({
    key: AUTH_KEY,
    androidId: ANDROID_ID,
    random: deterministicRandom(),
    requestId: () => FIXED_REQUEST_ID,
    ...over,
  });
}

/** A LinkParams reply shaped like a real watch's (DeviceConfig.java:50-123). */
function linkParamsTlv(input: {
  deviceSupportType?: number;
  authVersion?: number;
  encryptMethod?: number;
  sliceSize?: number;
  serverNonce?: Uint8Array;
} = {}): HuaweiTlv {
  const nonce = input.serverNonce ?? Uint8Array.from({ length: 16 }, (_, i) => i + 1);
  return new HuaweiTlv()
    .putByte(0x01, 0x02)
    .putShort(0x02, input.sliceSize ?? 0x00f4)
    .putShort(0x03, 0x0014)
    .putShort(0x04, 0x0000)
    .putBytes(0x05, bytes(0x00, input.authVersion ?? 0x02, ...nonce))
    .putByte(0x07, input.deviceSupportType ?? 0x04)
    .putByte(0x08, 0x00)
    .putByte(0x09, 0x00)
    .putByte(0x0c, input.encryptMethod ?? 0x00);
}

/** DeviceStatus reply: tag 0x01 is the status byte (DeviceConfig.java:886-892). */
function statusTlv(status: number): HuaweiTlv {
  return new HuaweiTlv().putByte(0x01, status);
}

/** SecurityNegotiation reply carrying `authType` (DeviceConfig.java:1598-1637). */
function negotiationTlv(value = 0x01, tag: 0x01 | 0x02 | 0x7f = 0x01): HuaweiTlv {
  return new HuaweiTlv().putByte(tag, value);
}

/**
 * PinCode reply: the encrypted code in tag 0x01 and its IV in tag 0x02 (DeviceConfig.java:1449-1460).
 * The AES key is the static digest secret of the negotiated authVersion, never the user's key.
 */
function pincodeTlv(pin: Uint8Array, iv: Uint8Array): HuaweiTlv {
  const ciphertext = ok(aesGcmEncryptNoPad(pin, DIGEST_SECRET_V2, iv, null));
  return new HuaweiTlv().putBytes(0x01, ciphertext).putBytes(0x02, iv);
}

/** A HiChain reply: type 0x00 means the tag 0x01 value is JSON (DeviceConfig.java:1229-1279). */
function hiChainJsonReply(payload: Record<string, unknown>): HuaweiTlv {
  return new HuaweiTlv()
    .putByte(0x04, 0x00)
    .putString(0x01, JSON.stringify({ payload }));
}

/** A step-4 reply: a non-zero type, and the tag 0x01 value is raw data, not JSON. */
function hiChainStep4Reply(data = "ok"): HuaweiTlv {
  return new HuaweiTlv().putByte(0x04, 0x01).putString(0x01, data);
}

function reply(serviceId: number, commandId: number, tlv: HuaweiTlv | null): HuaweiFrame {
  return {
    serviceId,
    commandId,
    tlv,
    payload: new Uint8Array(0),
    encryptedEnvelope: false,
    sliceType: 0,
    sliceFlags: [],
    sliceCount: 1,
  };
}

const hiChainFrame = (tlv: HuaweiTlv | null): HuaweiFrame =>
  reply(DEVICE_CONFIG.serviceId, DEVICE_CONFIG.hiChain, tlv);
const deviceFrame = (commandId: number, tlv: HuaweiTlv | null): HuaweiFrame =>
  reply(DEVICE_CONFIG.serviceId, commandId, tlv);

/** Decode the bytes the machine asked us to send, exactly as the watch would have to. */
function framesOf(out: Uint8Array[]): HuaweiFrame[] {
  assert.ok(out.length > 0, "the machine emitted no frames");
  return ok(decodeFrames(concat(...out)));
}

/** The single frame a step produces: a sliced request reassembles into one frame. */
function onlyFrame(out: Uint8Array[]): HuaweiFrame {
  const frames = framesOf(out);
  assert.equal(frames.length, 1, "expected exactly one reassembled frame");
  return frames[0];
}

/** The HiChain envelope's JSON, as the watch parses it. */
function jsonOf(frame: HuaweiFrame): Record<string, unknown> {
  const text = frame.tlv?.tryGetString(0x01);
  assert.ok(text?.ok, "the HiChain frame has no JSON in tag 0x01");
  return JSON.parse(text.value) as Record<string, unknown>;
}

const payloadOf = (frame: HuaweiFrame): Record<string, unknown> =>
  jsonOf(frame).payload as Record<string, unknown>;

/** A hex string field of the HiChain payload, decoded. */
const field = (frame: HuaweiFrame, key: string): Uint8Array => hex(payloadOf(frame)[key] as string);
/**
 * Walk the machine from start() to the security negotiation's answer, which is where the HiChain
 * operation begins. Every intermediate state is asserted, so a reordering in the machine fails here
 * rather than in a later test with a confusing symptom.
 */
function driveToHiChain(
  machine: AuthMachine,
  input: {
    deviceSupportType?: number;
    authVersion?: number;
    encryptMethod?: number;
    status?: number;
    authType?: number;
    /** parseSecurityNegotiation reads tag 0x01 for 0x01/0x04 and tag 0x02 for everything else. */
    authTypeTag?: 0x01 | 0x02 | 0x7f;
  } = {},
): AuthOutput {
  const started = ok(machine.start());
  assert.equal(started.state, "link-params");
  const afterLink = ok(machine.onFrame(deviceFrame(
    DEVICE_CONFIG.linkParams,
    linkParamsTlv({
      deviceSupportType: input.deviceSupportType,
      authVersion: input.authVersion,
      encryptMethod: input.encryptMethod,
    }),
  )));
  assert.equal(afterLink.state, "device-status");
  const afterStatus = ok(machine.onFrame(deviceFrame(
    DEVICE_CONFIG.deviceStatus,
    statusTlv(input.status ?? 0x01),
  )));
  assert.equal(afterStatus.state, "security-negotiation");
  const afterNegotiation = ok(machine.onFrame(deviceFrame(
    DEVICE_CONFIG.securityNegotiation,
    negotiationTlv(input.authType ?? 0x01, input.authTypeTag ?? 0x01),
  )));
  return afterNegotiation;
}

/** A 16-byte randPeer and a 32-char peerAuthId, i.e. what the watch contributes at step 1. */
const WATCH_SALT = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
const WATCH_AUTH_ID = utf8("fedcba9876543210fedcba9876543210");
/** The IV of the pin-code reply. The key is the static digest secret, not the user's key. */
const PIN_IV = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");

/**
 * The watch's step-1 reply. The token it sends is HMAC(psk, randPeer ‖ randSelf ‖ authIdSelf ‖
 * authIdPeer) — the *verified* order, which is the mirror of the token the phone sends at step 2.
 */
function step1Reply(
  psk: Uint8Array,
  randSelf: Uint8Array,
  watchSalt = WATCH_SALT,
  watchAuthId = WATCH_AUTH_ID,
): HuaweiTlv {
  const token = hmacSha256(psk, concat(watchSalt, randSelf, ANDROID_ID, watchAuthId));
  return hiChainJsonReply({
    isoSalt: hexOf(watchSalt),
    peerAuthId: hexOf(watchAuthId),
    peerUserType: 0x00,
    token: hexOf(token),
  });
}

describe("authMachine — start and the link parameters", () => {
  test("start() asks for the link parameters and refuses to start twice", () => {
    const machine = machineWith();
    assert.equal(machine.state, "start");
    assert.equal(machine.timeoutMs, 5_000);
    assert.equal(machine.finished, false);
    assert.equal(machine.finalKey, null);

    const started = ok(machine.start());
    assert.equal(started.state, "link-params");
    assert.equal(started.done, false);
    const frame = onlyFrame(started.out);
    assert.equal(frame.serviceId, DEVICE_CONFIG.serviceId);
    assert.equal(frame.commandId, DEVICE_CONFIG.linkParams);
    assert.equal(frame.encryptedEnvelope, false);
    assert.equal(machine.state, "link-params");

    const twice = failure(machine.start());
    assert.equal(twice.code, "auth-state");
    assert.equal(twice.detail, "link-params");
    assert.equal(machine.state, "failed");
    assert.equal(machine.finished, true);
    assert.equal(machine.timeoutMs, 0);
  });

  test("a frame with no TLV is auth-truncated, not a guess", () => {
    const machine = machineWith();
    ok(machine.start());
    const err = failure(machine.onFrame(deviceFrame(DEVICE_CONFIG.linkParams, null)));
    assert.equal(err.code, "auth-truncated");
    assert.equal(err.detail, "link-params");
    assert.equal(machine.state, "failed");
  });

  test("a frame from the wrong service or command is auth-state, and names both ids", () => {
    const machine = machineWith();
    ok(machine.start());
    const err = failure(machine.onFrame(hiChainFrame(hiChainJsonReply({ payload: {} }))));
    assert.equal(err.code, "auth-state");
    assert.equal(err.detail, "service 0x1 command 0x28 in link-params");
    assert.equal(machine.state, "failed");
  });

  test("HiChainLite and the devices with no HiChain at all stop at link params", () => {
    for (const [deviceSupportType, path] of [[0x02, "hichain-lite"], [0x00, "normal"], [0x05, "normal"]] as const) {
      const machine = machineWith();
      ok(machine.start());
      const err = failure(machine.onFrame(deviceFrame(
        DEVICE_CONFIG.linkParams,
        linkParamsTlv({ deviceSupportType }),
      )));
      assert.equal(err.code, "auth-unsupported", `deviceSupportType ${deviceSupportType} is ${path}`);
      assert.equal(err.detail, `deviceSupportType ${deviceSupportType}`);
      assert.equal(machine.state, "failed");
    }
  });

  test("the three HiChain deviceSupportTypes are all accepted, and device status is asked next", () => {
    for (const deviceSupportType of [0x01, 0x03, 0x04]) {
      const machine = machineWith();
      ok(machine.start());
      const out = ok(machine.onFrame(deviceFrame(
        DEVICE_CONFIG.linkParams,
        linkParamsTlv({ deviceSupportType }),
      )));
      assert.equal(out.state, "device-status");
      assert.equal(machine.timeoutMs, 5_000);
      const frame = onlyFrame(out.out);
      assert.equal(frame.commandId, DEVICE_CONFIG.deviceStatus);
      // DeviceStatus.Request is one empty tag 0x01, unencrypted and unsliced (DeviceConfig.java:861-875).
      const tag = frame.tlv?.tryGetBytes(0x01);
      assert.ok(tag?.ok);
      assert.equal(tag.value.length, 0);
      assert.equal(frame.sliceCount, 1);
    }
  });
});

describe("authMachine — device status and the security negotiation", () => {
  test("statuses other than -1, 0 and 1 refuse to continue", () => {
    for (const status of [0x05, 0x02, 0x10]) {
      const machine = machineWith();
      ok(machine.start());
      ok(machine.onFrame(deviceFrame(DEVICE_CONFIG.linkParams, linkParamsTlv())));
      const err = failure(machine.onFrame(deviceFrame(DEVICE_CONFIG.deviceStatus, statusTlv(status))));
      assert.equal(err.code, "auth-refused");
      assert.equal(err.detail, `status ${status}`);
      assert.equal(machine.state, "failed");
    }
    // 0xFF is -1 as a java byte: "authenticate now" on every device Huawei ships.
    for (const status of [0xff, 0x00, 0x01]) {
      const machine = machineWith();
      ok(machine.start());
      ok(machine.onFrame(deviceFrame(DEVICE_CONFIG.linkParams, linkParamsTlv())));
      const out = ok(machine.onFrame(deviceFrame(DEVICE_CONFIG.deviceStatus, statusTlv(status))));
      assert.equal(out.state, "security-negotiation");
    }
  });

  test("the negotiation request carries the authMode the link params selected", () => {
    const hiChain3 = machineWith();
    ok(hiChain3.start());
    ok(hiChain3.onFrame(deviceFrame(DEVICE_CONFIG.linkParams, linkParamsTlv({ deviceSupportType: 0x04 }))));
    const afterStatus = ok(hiChain3.onFrame(deviceFrame(
      DEVICE_CONFIG.deviceStatus,
      statusTlv(0x01),
    )));
    const frame = onlyFrame(afterStatus.out);
    assert.equal(frame.commandId, DEVICE_CONFIG.securityNegotiation);
    assert.equal(ok(frame.tlv!.tryGetByte(0x01)), 0x04);
    assert.deepEqual(ok(frame.tlv!.tryGetBytes(0x05)), ANDROID_ID);
    assert.equal(ok(frame.tlv!.tryGetByte(0x03)), 0x01);
    assert.equal(ok(frame.tlv!.tryGetByte(0x04)), 0x00);
    // Mode 4 adds the two device-level tags, mode 2 does not (DeviceConfig.java:1595-1607).
    assert.ok(frame.tlv!.tryGetBytes(0x06).ok);
    assert.equal(ok(frame.tlv!.tryGetString(0x07)), "Aether Health BCS");

    const hiChain2 = machineWith();
    ok(hiChain2.start());
    ok(hiChain2.onFrame(deviceFrame(DEVICE_CONFIG.linkParams, linkParamsTlv({ deviceSupportType: 0x01 }))));
    const mode2 = ok(hiChain2.onFrame(deviceFrame(
      DEVICE_CONFIG.deviceStatus,
      statusTlv(0x01),
    )));
    const frame2 = onlyFrame(mode2.out);
    assert.equal(ok(frame2.tlv!.tryGetByte(0x01)), 0x02);
    assert.equal(frame2.tlv!.tryGetBytes(0x06).ok, false);
  });

  test("0x186A0 and the two HiChain3 types start the bind operation; anything else is refused", () => {
    for (const authType of [0x01]) {
      const machine = machineWith();
      const { state } = driveToHiChain(machine, { authType });
      assert.equal(state, "hichain-bind-step1");
      assert.equal(machine.timeoutMs, 5_000);
    }
    // isHiChain3: (authType ^ 1) == 4 or (authType ^ 2) == 4, i.e. 5 and 6 — carried in tag 0x02.
    for (const authType of [0x05, 0x06]) {
      const machine = machineWith();
      const out = driveToHiChain(machine, { authType, authTypeTag: 0x02 });
      assert.equal(out.state, "hichain-bind-step1", `authType ${authType} is HiChain3`);
    }
    const refused = machineWith();
    ok(refused.start());
    ok(refused.onFrame(deviceFrame(DEVICE_CONFIG.linkParams, linkParamsTlv())));
    ok(refused.onFrame(deviceFrame(DEVICE_CONFIG.deviceStatus, statusTlv(0x01))));
    const err = failure(refused.onFrame(deviceFrame(
      DEVICE_CONFIG.securityNegotiation,
      new HuaweiTlv().putByte(0x02, 0x00),
    )));
    assert.equal(err.code, "auth-unsupported");
    assert.equal(err.detail, "authType 0x0");
    assert.match(err.message, /HiChainLite/);
    assert.equal(refused.state, "failed");
  });

  test("the bind operation's step 1 is message 0x11, with the three bind-only keys", () => {
    const machine = machineWith();
    const step1Out = driveToHiChain(machine);
    assert.equal(step1Out.state, "hichain-bind-step1");

    const frame = onlyFrame(step1Out.out);
    assert.equal(frame.commandId, DEVICE_CONFIG.hiChain);
    const json = jsonOf(frame);
    const payload = payloadOf(frame);
    assert.equal(json.message, 0x11);
    assert.equal(json.authForm, 0x00);
    assert.equal(json.groupAndModuleVersion, "2.0.1");
    // isDeviceLevel is added by StepOne and StepTwo of the bind operation only (DeviceConfig.java:1146).
    assert.equal(json.isDeviceLevel, false);
    assert.deepEqual(payload.version, { minVersion: "1.0.0", currentVersion: "2.0.16" });
    assert.equal(payload.operationCode, 0x02);
    assert.equal(payload.pkgName, "com.huawei.devicegroupmanage");
    assert.equal(payload.serviceType, HI_CHAIN_GROUP_ID);
    assert.equal(payload.keyLength, 0x20);
    assert.equal(payload.peerAuthId, hexOf(ANDROID_ID));
    assert.equal(payload.peerUserType, 0x00);
    assert.equal(field(frame, "isoSalt").length, 16);
    assert.equal(field(frame, "seed").length, 32);
    // Only the auth operation adds the requestId/group block; the bind operation must not ().
    for (const key of ["requestId", "groupId", "groupName", "groupOp", "groupType", "appId", "ownerName",
      "peerDeviceId", "connDeviceId"]) {
      assert.equal(key in json, false, `the bind envelope must not carry ${key}`);
    }
    // The envelope's own tags: 0x02 operationCode, 0x03 the request id as a big-endian long.
    assert.equal(ok(frame.tlv!.tryGetByte(0x02)), 0x02);
    const expectedRequestId = new Uint8Array(8);
    new DataView(expectedRequestId.buffer).setBigUint64(0, FIXED_REQUEST_ID, false);
    assert.deepEqual(ok(frame.tlv!.tryGetBytes(0x03)), expectedRequestId);
  });
});

describe("authMachine — the bind operation, step by step", () => {
  test("the whole flow: the verified token, the sent token, the session key, step 4 as 0x13, the key", () => {
    const machine = machineWith();
    const step1Out = driveToHiChain(machine);
    const step1 = onlyFrame(step1Out.out);
    const randSelf = field(step1, "isoSalt");
    const seed = field(step1, "seed");
    // The bind operation's psk is HMAC(authKey, seed) — no pin code involved (GetHiChainRequest.java:113-120).
    const psk = hmacSha256(AUTH_KEY, seed);

    const step2Out = ok(machine.onFrame(hiChainFrame(step1Reply(psk, randSelf))));
    assert.equal(step2Out.state, "hichain-bind-step2");
    const step2 = onlyFrame(step2Out.out);
    assert.equal(jsonOf(step2).message, 0x12);
    assert.equal(jsonOf(step2).isDeviceLevel, false);
    assert.equal(payloadOf(step2).peerAuthId, hexOf(ANDROID_ID));
    // What we send is the mirror order of what we verified: both orders are upstream's (:115-123, :214-220).
    const sentToken = hmacSha256(psk, concat(randSelf, WATCH_SALT, WATCH_AUTH_ID, ANDROID_ID));
    assert.equal(payloadOf(step2).token, hexOf(sentToken));
    assert.notEqual(
      hexOf(sentToken),
      hexOf(hmacSha256(psk, concat(WATCH_SALT, randSelf, ANDROID_ID, WATCH_AUTH_ID))),
    );

    const sessionKey = ok(hkdfSha256(psk, concat(randSelf, WATCH_SALT), utf8("hichain_iso_session_key"), 32));
    const returnCodeMac = hmacSha256(psk, Uint8Array.of(0, 0, 0, 0));
    const step4Out = ok(machine.onFrame(hiChainFrame(hiChainJsonReply({ returnCodeMac: hexOf(returnCodeMac) }))));
    // The bind operation never sends step 3: it increments the step and falls through to step 4 (:143-155).
    assert.equal(step4Out.state, "hichain-bind-step4");
    const step4 = onlyFrame(step4Out.out);
    // The ported upstream quirk: message 0x13, not 0x14, because upstream captured the step before
    // incrementing it (GetHiChainRequest.java:105, :144, :154).
    assert.equal(jsonOf(step4).message, 0x13);
    assert.equal(payloadOf(step4).operationCode, 0x02);
    const nonce = field(step4, "nonce");
    assert.equal(nonce.length, 12);
    assert.deepEqual(
      ok(aesGcmDecryptNoPad(field(step4, "encResult"), sessionKey, nonce, utf8("hichain_iso_result"))),
      Uint8Array.of(0, 0, 0, 0),
    );

    const done = ok(machine.onFrame(hiChainFrame(hiChainStep4Reply())));
    assert.equal(done.state, "done");
    assert.equal(done.done, true);
    assert.deepEqual(done.out, []);
    assert.equal(machine.finished, true);
    assert.equal(machine.timeoutMs, 0);
    const expectedKey = ok(hkdfSha256(sessionKey, concat(randSelf, WATCH_SALT), utf8("hichain_return_key"), 32));
    assert.equal(machine.finalKey?.length, 32);
    assert.deepEqual(machine.finalKey, expectedKey);
    assert.notDeepEqual(machine.finalKey, AUTH_KEY);

    // Nothing may follow a completed flow.
    const late = failure(machine.onFrame(hiChainFrame(hiChainStep4Reply())));
    assert.equal(late.code, "auth-state");
    assert.equal(late.detail, "done");
  });
});

describe("authMachine — every way the flow refuses", () => {
  test("a wrong key stops at step 1 as auth-token-mismatch, and the error carries no key material", () => {
    const machine = machineWith();
    const step1Out = driveToHiChain(machine);
    const step1 = onlyFrame(step1Out.out);
    const randSelf = field(step1, "isoSalt");
    const seed = field(step1, "seed");
    // The watch's token computed with a key that is not ours: what a wrong auth key looks like on air.
    const otherKey = hex("ff".repeat(32));
    const otherPsk = hmacSha256(otherKey, seed);
    const err = failure(machine.onFrame(hiChainFrame(step1Reply(otherPsk, randSelf))));
    assert.equal(err.code, "auth-token-mismatch");
    assert.equal(machine.state, "failed");
    assert.equal(machine.finished, true);
    const text = `${err.message} ${err.detail ?? ""}`;
    for (const secret of [AUTH_KEY, otherKey, otherPsk]) {
      assert.equal(text.includes(hexOf(secret)), false, "no uppercase key hex in the error");
      assert.equal(text.includes(hexOf(secret).toLowerCase()), false, "no lowercase key hex in the error");
      assert.equal(text.includes(Buffer.from(secret).toString("base64")), false, "no base64 of the key");
    }
  });

  test("a tampered return-code MAC stops at step 2 as auth-mac-mismatch", () => {
    const machine = machineWith();
    const step1Out = driveToHiChain(machine);
    const step1 = onlyFrame(step1Out.out);
    const psk = hmacSha256(AUTH_KEY, field(step1, "seed"));
    ok(machine.onFrame(hiChainFrame(step1Reply(psk, field(step1, "isoSalt")))));
    const wrongMac = hmacSha256(psk, Uint8Array.of(0, 0, 0, 1));
    const err = failure(machine.onFrame(hiChainFrame(hiChainJsonReply({ returnCodeMac: hexOf(wrongMac) }))));
    assert.equal(err.code, "auth-mac-mismatch");
    assert.equal(machine.state, "failed");
  });

  test("a reply for a later step is auth-state, and names what was expected", () => {
    const machine = machineWith();
    driveToHiChain(machine);
    const err = failure(machine.onFrame(hiChainFrame(
      hiChainJsonReply({ returnCodeMac: hexOf(hex("00".repeat(32))) }),
    )));
    assert.equal(err.code, "auth-state");
    assert.equal(err.detail, "waiting for 1, got 2");
    assert.equal(machine.state, "failed");
  });

  test("a non-zero errorCode is auth-refused, and no payload is parsed after it", () => {
    const machine = machineWith();
    driveToHiChain(machine);
    const err = failure(machine.onFrame(hiChainFrame(hiChainJsonReply({ errorCode: 7 }))));
    assert.equal(err.code, "auth-refused");
    assert.equal(err.detail, "errorCode 7 in hichain-bind-step1");
    assert.equal(machine.state, "failed");
  });

  test("a step-1 reply missing one of its fields is auth-truncated, and names the field", () => {
    const machine = machineWith();
    driveToHiChain(machine);
    const err = failure(machine.onFrame(hiChainFrame(
      hiChainJsonReply({ isoSalt: hexOf(WATCH_SALT) }),
    )));
    assert.equal(err.code, "auth-truncated");
    assert.equal(err.detail, "peerAuthId");
    assert.match(err.message, /peerAuthId/);
    assert.equal(machine.state, "failed");
  });

  test("bind mode with an empty key stops before any HiChain request is built", () => {
    const machine = machineWith({ key: new Uint8Array(0) });
    ok(machine.start());
    ok(machine.onFrame(deviceFrame(DEVICE_CONFIG.linkParams, linkParamsTlv())));
    ok(machine.onFrame(deviceFrame(DEVICE_CONFIG.deviceStatus, statusTlv(0x01))));
    const err = failure(machine.onFrame(deviceFrame(DEVICE_CONFIG.securityNegotiation, negotiationTlv())));
    assert.equal(err.code, "bad-key");
    assert.equal(machine.state, "failed");
  });
});

describe("authMachine — the auth-then-bind path", () => {
  test("without a pin code the machine asks the watch for one, and waits 30s for it", () => {
    const machine = machineWith({ mode: "auth-then-bind" });
    const afterNegotiation = driveToHiChain(machine, { encryptMethod: 1 });
    assert.equal(afterNegotiation.state, "pincode");
    assert.equal(machine.timeoutMs, 30_000);
    const frame = onlyFrame(afterNegotiation.out);
    assert.equal(frame.commandId, DEVICE_CONFIG.pinCode);
    assert.equal(ok(frame.tlv!.tryGetBytes(0x01)).length, 0);
    assert.equal(frame.sliceCount, 1);
  });

  test("with a pin code supplied the pin request is skipped and the auth operation starts", () => {
    const machine = machineWith({ mode: "auth-then-bind", pinCode: utf8("123456") });
    const step1 = driveToHiChain(machine);
    assert.equal(step1.state, "hichain-auth-step1");
    assert.equal(machine.timeoutMs, 30_000);
    const frame = onlyFrame(step1.out);
    const json = jsonOf(frame);
    // The auth operation's messages are 1..4, with no 0x10 mask, and it carries the group block.
    assert.equal(json.message, 0x01);
    assert.equal("isDeviceLevel" in json, false);
    assert.equal(json.requestId, FIXED_REQUEST_ID.toString());
    assert.equal(json.groupId, HI_CHAIN_GROUP_ID);
    assert.equal(json.groupName, "health_group_name");
    assert.equal(json.groupOp, 2);
    assert.equal(json.groupType, 256);
    assert.equal(json.appId, "com.huawei.health");
    assert.equal(json.peerDeviceId, "0123456789abcdef0123456789abcdef");
    // The three bind-only keys must not appear here (DeviceConfig.java:1146-1157).
    for (const key of ["pkgName", "serviceType", "keyLength"]) {
      assert.equal(key in payloadOf(frame), false, `the auth envelope must not carry ${key}`);
    }
    assert.equal(ok(frame.tlv!.tryGetByte(0x02)), 0x01);
  });

  test("the pin reply starts the auth operation, and the pin is digested, never used raw", () => {
    const machine = machineWith({ mode: "auth-then-bind" });
    const afterNegotiation = driveToHiChain(machine, { encryptMethod: 1 });
    assert.equal(afterNegotiation.state, "pincode");
    const pin = utf8("123456");
    const pinOut = ok(machine.onFrame(deviceFrame(DEVICE_CONFIG.pinCode, pincodeTlv(pin, PIN_IV))));
    assert.equal(pinOut.state, "hichain-auth-step1");
    const step1 = onlyFrame(pinOut.out);
    // Upstream digests the *hex string* of the pin code, not the pin code (GetHiChainRequest.java:207-209).
    const psk = hmacSha256(sha256(utf8(hexOf(pin))), field(step1, "seed"));
    const step2Out = ok(machine.onFrame(hiChainFrame(step1Reply(psk, field(step1, "isoSalt")))));
    assert.equal(step2Out.state, "hichain-auth-step2");
    // Using the raw pin would not verify, which is the point: the digest is what the watch expects.
    const rawPsk = hmacSha256(sha256(pin), field(step1, "seed"));
    assert.notEqual(hexOf(rawPsk), hexOf(psk));
  });

  test("the whole auth-then-bind flow: pin, auth steps 1-4, then a fresh bind operation", () => {
    const pin = utf8("123456");
    const machine = machineWith({ mode: "auth-then-bind", pinCode: pin });
    const authStep1Out = driveToHiChain(machine, { encryptMethod: 1 });
    assert.equal(authStep1Out.state, "hichain-auth-step1");
    const authStep1 = onlyFrame(authStep1Out.out);
    const randSelf = field(authStep1, "isoSalt");
    const psk = hmacSha256(sha256(utf8(hexOf(pin))), field(authStep1, "seed"));

    const authStep2Out = ok(machine.onFrame(hiChainFrame(step1Reply(psk, randSelf))));
    assert.equal(authStep2Out.state, "hichain-auth-step2");
    assert.equal(jsonOf(onlyFrame(authStep2Out.out)).message, 0x02);
    const sessionKey = ok(hkdfSha256(psk, concat(randSelf, WATCH_SALT), utf8("hichain_iso_session_key"), 32));

    const returnCodeMac = hmacSha256(psk, Uint8Array.of(0, 0, 0, 0));
    const authStep3Out = ok(machine.onFrame(hiChainFrame(hiChainJsonReply({ returnCodeMac: hexOf(returnCodeMac) }))));
    assert.equal(authStep3Out.state, "hichain-auth-step3");
    const authStep3 = onlyFrame(authStep3Out.out);
    assert.equal(jsonOf(authStep3).message, 0x03);
    // Our challenge, sealed under the session key with the "exchange" AAD.
    const challenge = ok(aesGcmDecryptNoPad(
      field(authStep3, "encData"),
      sessionKey,
      field(authStep3, "nonce"),
      utf8("hichain_iso_exchange"),
    ));
    assert.equal(challenge.length, 16);

    // The watch answers with the auth token it just minted, bound to that challenge.
    const authToken = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    const deviceNonce = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    const encAuthToken = ok(aesGcmEncryptNoPad(authToken, sessionKey, deviceNonce, challenge));
    const authStep4Out = ok(machine.onFrame(hiChainFrame(hiChainJsonReply({
      nonce: hexOf(deviceNonce),
      encAuthToken: hexOf(encAuthToken),
    }))));
    assert.equal(authStep4Out.state, "hichain-auth-step4");
    const authStep4 = onlyFrame(authStep4Out.out);
    assert.equal(jsonOf(authStep4).message, 0x04);
    assert.deepEqual(
      ok(aesGcmDecryptNoPad(field(authStep4, "encResult"), sessionKey, field(authStep4, "nonce"),
        utf8("hichain_iso_result"))),
      Uint8Array.of(0, 0, 0, 0),
    );

    // Finishing the auth operation starts a *new* bind operation, keyed by the auth token.
    const bindStep1Out = ok(machine.onFrame(hiChainFrame(hiChainStep4Reply())));
    assert.equal(bindStep1Out.state, "hichain-bind-step1");
    assert.equal(machine.timeoutMs, 5_000);
    const bindStep1 = onlyFrame(bindStep1Out.out);
    assert.equal(jsonOf(bindStep1).message, 0x11);
    const bindRandSelf = field(bindStep1, "isoSalt");
    const bindPsk = hmacSha256(authToken, field(bindStep1, "seed"));

    ok(machine.onFrame(hiChainFrame(step1Reply(bindPsk, bindRandSelf))));
    const bindMac = hmacSha256(bindPsk, Uint8Array.of(0, 0, 0, 0));
    const bindStep4Out = ok(machine.onFrame(hiChainFrame(hiChainJsonReply({ returnCodeMac: hexOf(bindMac) }))));
    assert.equal(bindStep4Out.state, "hichain-bind-step4");
    assert.equal(jsonOf(onlyFrame(bindStep4Out.out)).message, 0x13);
    const bindSessionKey = ok(hkdfSha256(bindPsk, concat(bindRandSelf, WATCH_SALT),
      utf8("hichain_iso_session_key"), 32));

    const done = ok(machine.onFrame(hiChainFrame(hiChainStep4Reply())));
    assert.equal(done.state, "done");
    assert.deepEqual(machine.finalKey, ok(hkdfSha256(bindSessionKey, concat(bindRandSelf, WATCH_SALT),
      utf8("hichain_return_key"), 32)));
    // The key the tool came for is derived from the *second* handshake, not the first.
    assert.notDeepEqual(machine.finalKey, authToken);
    assert.notDeepEqual(machine.finalKey, AUTH_KEY);
  });
});

describe("authMachine — timeouts and destroy", () => {
  test("the timeout follows the state: 30s for the two user-facing waits, 5s elsewhere, 0 at the end", () => {
    const pin = utf8("123456");
    const machine = machineWith({ mode: "auth-then-bind" });
    assert.equal(machine.timeoutMs, 5_000);
    const pinState = driveToHiChain(machine, { encryptMethod: 1 });
    assert.equal(pinState.state, "pincode");
    assert.equal(machine.timeoutMs, 30_000);
    const pinOut = ok(machine.onFrame(deviceFrame(DEVICE_CONFIG.pinCode, pincodeTlv(pin, PIN_IV))));
    assert.equal(pinOut.state, "hichain-auth-step1");
    assert.equal(machine.timeoutMs, 30_000);
    const step1 = onlyFrame(pinOut.out);
    const psk = hmacSha256(sha256(utf8(hexOf(pin))), field(step1, "seed"));
    const step2 = ok(machine.onFrame(hiChainFrame(step1Reply(psk, field(step1, "isoSalt")))));
    assert.equal(step2.state, "hichain-auth-step2");
    assert.equal(machine.timeoutMs, 5_000);

    const err = failure(machine.onFrame(hiChainFrame(hiChainJsonReply({ errorCode: 3 }))));
    assert.equal(err.code, "auth-refused");
    assert.equal(machine.timeoutMs, 0);
  });

  test("destroy() zeroes the final key, keeps the caller's buffer, and is safe twice", () => {
    const machine = machineWith();
    const step1Out = driveToHiChain(machine);
    const step1 = onlyFrame(step1Out.out);
    const psk = hmacSha256(AUTH_KEY, field(step1, "seed"));
    ok(machine.onFrame(hiChainFrame(step1Reply(psk, field(step1, "isoSalt")))));
    ok(machine.onFrame(hiChainFrame(hiChainJsonReply({
      returnCodeMac: hexOf(hmacSha256(psk, Uint8Array.of(0, 0, 0, 0))),
    }))));
    ok(machine.onFrame(hiChainFrame(hiChainStep4Reply())));
    const derived = machine.finalKey;
    assert.ok(derived);
    assert.equal(derived.length, 32);
    assert.notDeepEqual(derived, new Uint8Array(32));

    machine.destroy();
    assert.equal(machine.finalKey, null);
    // The very buffer the caller was handed, zeroed in place.
    assert.deepEqual(derived, new Uint8Array(32));
    // The caller's own key is untouched: the machine always worked on a copy.
    assert.deepEqual(AUTH_KEY, hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"));
    machine.destroy();
  });

  test("destroy() mid-flow wipes the handshake, so a later reply is refused, not computed", () => {
    const machine = machineWith();
    const step1Out = driveToHiChain(machine);
    const step1 = onlyFrame(step1Out.out);
    const psk = hmacSha256(AUTH_KEY, field(step1, "seed"));
    machine.destroy();
    const err = failure(machine.onFrame(hiChainFrame(step1Reply(psk, field(step1, "isoSalt")))));
    // The seed is gone, so the machine refuses to derive anything: a typed stop, never a TypeError.
    assert.equal(err.code, "auth-state");
    assert.match(err.message, /no handshake in progress/);
    assert.equal(machine.finalKey, null);
  });
describe("validatePhoneModel", () => {
  test("the helper's own default is valid, so nothing changes for a caller that says nothing", () => {
    assert.equal(DEFAULT_PHONE_MODEL, "Aether Health BCS");
    assert.deepEqual(validatePhoneModel(DEFAULT_PHONE_MODEL), { ok: true, value: DEFAULT_PHONE_MODEL });
  });

  test("1 to 32 printable ASCII characters are the bounds", () => {
    for (const value of ["x", "Pixel 7", "Pixel 7 Pro", "a".repeat(32), "Aether Health BCS!"]) {
      assert.equal(validatePhoneModel(value).ok, true, JSON.stringify(value));
    }
    for (const value of ["", "a".repeat(33), "tab\there", "line\nbreak", "caf\u00e9", "\u2026"]) {
      const checked = validatePhoneModel(value);
      assert.equal(checked.ok, false, JSON.stringify(value));
      if (!checked.ok) {
        assert.equal(checked.error.code, "bad-argument");
        assert.match(checked.error.message, /1-32 printable ASCII/);
      }
    }
  });

  test("a value that is not a string is refused rather than coerced", () => {
    for (const value of [undefined, null, 7, new Uint8Array(4), ["Pixel"]]) {
      assert.equal(validatePhoneModel(value).ok, false, String(value));
    }
  });
});
});