// BCS helper — Phase 3 (trust/auth) tests: the auth packets — link params, device status, security
// negotiation, pin code, and the HiChain JSON envelope and its four steps.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7 (GitHub mirror, frozen
// 2024-12-22), read-only. Every expected value below comes from one of:
//   devices/huawei/packets/DeviceConfig.java   LinkParams :50-123, DeviceStatus :858-902,
//                                              SecurityNegotiation :1575-1640, HiChain :970-1419,
//                                              PinCode :1419-1462, createJson :1114-1144
//   service/devices/huawei/requests/GetHiChainRequest.java   :60-262 (the step machine)
//   service/devices/huawei/HuaweiSupportProvider.java        :474-495, :497-529, :564-578
//   HuaweiConstants.java:30                                  GROUP_ID
// No radio, no watch, no real key, no health data, and nothing is ever sent anywhere.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { DEVICE_CONFIG } from "../src/huawei/constants.ts";
import { hexdumpUpper } from "../src/huawei/crypto.ts";
import { HuaweiTlv } from "../src/huawei/tlv.ts";
import { decodeFrames } from "../src/huawei/stream.ts";
import { encodeRequest } from "../src/huawei/requests.ts";
import {
  HI_CHAIN_CURRENT_VERSION,
  HI_CHAIN_GROUP_AND_MODULE_VERSION,
  HI_CHAIN_GROUP_ID,
  HI_CHAIN_MIN_VERSION,
  HI_CHAIN_PKG_NAME,
  authPathFor,
  deviceStatusRequest,
  hiChainRequest,
  isHiChain3,
  parseDeviceStatus,
  parseHiChainResponse,
  parseLinkParams,
  parsePincodeResponse,
  parseSecurityNegotiation,
  pincodeRequest,
  securityNegotiationRequest,
  type HiChainStepInput,
} from "../src/huawei/authPackets.ts";

type Result<T> = { ok: true; value: T } | { ok: false; error: { code: string; message: string; detail: string | null } };
const ok = <T>(result: Result<T>): T => {
  if (!result.ok) throw new Error(`expected success, got ${result.error.code}: ${result.error.message}`);
  return result.value;
};
const failure = <T>(result: Result<T>): { code: string; message: string; detail: string | null } => {
  if (result.ok) throw new Error("expected a typed failure");
  return result.error;
};
const bytes = (...values: number[]): Uint8Array => Uint8Array.from(values);

/** A LinkParams reply with the tags a real watch sends (DeviceConfig.java:50-123). */
function linkParamsTlv(input: {
  deviceSupportType?: number;
  authVersion?: number;
  authAlgo?: number;
  encryptMethod?: number;
  sliceSize?: number;
  serverNonce?: Uint8Array;
  nonceTag?: Uint8Array;
} = {}): HuaweiTlv {
  const tlv = new HuaweiTlv()
    .putByte(0x01, 0x02)
    .putShort(0x02, input.sliceSize ?? 0x00f4)
    .putShort(0x03, 0x0014)
    .putShort(0x04, 0x0000);
  const nonceTag = input.nonceTag ?? bytes(
    0x00, input.authVersion ?? 0x02,
    ...(input.serverNonce ?? Uint8Array.from({ length: 16 }, (_, i) => i + 1)),
  );
  tlv.putBytes(0x05, nonceTag);
  return tlv
    .putByte(0x07, input.deviceSupportType ?? 0x04)
    .putByte(0x08, input.authAlgo ?? 0x00)
    .putByte(0x09, 0x00)
    .putByte(0x0c, input.encryptMethod ?? 0x00);
}

describe("authPackets — link params (DeviceConfig.LinkParams.Response, :43-71)", () => {
  test("a HiChain watch's reply parses into the four crypto inputs and the defaults", () => {
    const info = ok(parseLinkParams(linkParamsTlv({ deviceSupportType: 0x04, authVersion: 0x02 })));
    assert.equal(info.protocolVersion, 0x02);
    assert.equal(info.sliceSize, 0x00f4);
    assert.equal(info.mtu, 0x0014);
    assert.equal(info.interval, 0x0000);
    assert.equal(info.authVersion, 0x02);
    assert.deepEqual(info.serverNonce, Uint8Array.from({ length: 16 }, (_, i) => i + 1));
    assert.equal(info.deviceSupportType, 0x04);
    assert.equal(info.authAlgo, 0x00);
    assert.equal(info.bondState, 0x00);
    assert.equal(info.encryptMethod, 0x00);
  });

  test("the optional tags fall back exactly as upstream's field defaults do", () => {
    const tlv = new HuaweiTlv().putBytes(0x05, bytes(0x00, 0x01, ...new Array(16).fill(0x00)));
    const info = ok(parseLinkParams(tlv));
    assert.equal(info.protocolVersion, 0x00);
    assert.equal(info.sliceSize, 0x00f4); // the field default, not zero
    assert.equal(info.mtu, 0x0014);
    assert.equal(info.deviceSupportType, 0x00);
    assert.equal(info.encryptMethod, 0x00);
  });

  test("no tag 0x05 is auth-negotiation; a tag 0x05 shorter than 18 bytes is auth-truncated", () => {
    assert.equal(failure(parseLinkParams(new HuaweiTlv().putByte(0x01, 0x02))).code, "auth-negotiation");
    const short = failure(parseLinkParams(linkParamsTlv({ nonceTag: bytes(0x00, 0x02, 0x01, 0x02, 0x03) })));
    assert.equal(short.code, "auth-truncated");
    assert.equal(short.detail, "got 5");
  });
});

describe("authPackets — which auth path a device gets (HuaweiSupportProvider.java:474-495)", () => {
  test("deviceSupportType 0x01/0x03/0x04 is hichain, 0x02 is hichain-lite, everything else is normal", () => {
    assert.equal(authPathFor(0x01), "hichain");
    assert.equal(authPathFor(0x03), "hichain");
    assert.equal(authPathFor(0x04), "hichain");
    assert.equal(authPathFor(0x02), "hichain-lite");
    assert.equal(authPathFor(0x00), "normal");
    assert.equal(authPathFor(0x05), "normal");
    assert.equal(authPathFor(0xff), "normal");
  });

  test("isHiChain3 is (authType ^ 1) == 4 or (authType ^ 2) == 4, so 5 and 6", () => {
    assert.equal(isHiChain3(0x05), true);
    assert.equal(isHiChain3(0x06), true);
    assert.equal(isHiChain3(0x0186a0), false);
    assert.equal(isHiChain3(0x02), false);
    assert.equal(isHiChain3(0x07), false);
  });
});

describe("authPackets — security negotiation (DeviceConfig.SecurityNegotiation, :1575-1640)", () => {
  const input = {
    authMode: 0x02,
    deviceUuid: bytes(0x41, 0x42),
    phoneModel: "Test Model",
    encryptMethod: 0x00,
  };

  test("authMode 2 sends tags 0x01, 0x02, 0x05, 0x03, 0x04", () => {
    const request = securityNegotiationRequest(input);
    assert.equal(request.serviceId, DEVICE_CONFIG.serviceId);
    assert.equal(request.commandId, DEVICE_CONFIG.securityNegotiation);
    assert.deepEqual(request.tlv.entries.map((entry) => entry.tag), [0x01, 0x02, 0x05, 0x03, 0x04]);
    assert.equal(request.tlv.getByte(0x01), 0x02);
    assert.equal(request.tlv.getByte(0x02), 0x01);
    assert.deepEqual(request.tlv.getBytes(0x05), bytes(0x41, 0x42));
    assert.equal(request.tlv.getByte(0x03), 0x01);
    assert.equal(request.tlv.getByte(0x04), 0x00);
    assert.equal(request.isEncrypted, false);
    assert.equal(request.isSliced, true);
  });

  test("authMode 4 adds the device-level tags 0x06 and 0x07", () => {
    const request = securityNegotiationRequest({ ...input, authMode: 0x04 });
    assert.deepEqual(request.tlv.entries.map((entry) => entry.tag), [0x01, 0x02, 0x05, 0x03, 0x04, 0x06, 0x07]);
    assert.equal(request.tlv.getString(0x07), "Test Model");
  });

  test("encryptMethod 1 adds tag 0x0D, and only then", () => {
    assert.equal(securityNegotiationRequest({ ...input, encryptMethod: 0x01 }).tlv.getByte(0x0d), 0x01);
    assert.equal(securityNegotiationRequest(input).tlv.entries.some((entry) => entry.tag === 0x0d), false);
  });

  test("the reply's authType: 0x01 means 0x186A0, tag 0x02 wins, tag 0x7F wins over both", () => {
    assert.equal(ok(parseSecurityNegotiation(new HuaweiTlv().putByte(0x01, 0x01))), 0x0186a0);
    assert.equal(ok(parseSecurityNegotiation(new HuaweiTlv().putByte(0x02, 0x05))), 0x05);
    // tag 0x01 == 0x04 leaves pw = 4 behind, and the tag 0x02 value is XOR-ed with it (:1598-1637).
    assert.equal(ok(parseSecurityNegotiation(new HuaweiTlv().putByte(0x01, 0x04).putByte(0x02, 0x06))), 0x06 ^ 0x04);
    assert.equal(ok(parseSecurityNegotiation(new HuaweiTlv().putByte(0x02, 0x05).putByte(0x7f, 0x00))), 0x00);
    // Nothing at all is -1: the device refused to say, which the machine treats as unsupported.
    assert.equal(ok(parseSecurityNegotiation(new HuaweiTlv().putByte(0x03, 0x00))), -1);
  });
});

describe("authPackets — device status and pin code requests", () => {
  test("device status is 0x01/0x16 with one empty tag, unencrypted and unsliced", () => {
    const request = deviceStatusRequest();
    assert.equal(request.serviceId, DEVICE_CONFIG.serviceId);
    assert.equal(request.commandId, DEVICE_CONFIG.deviceStatus);
    assert.deepEqual(request.tlv.entries.map((entry) => entry.tag), [0x01]);
    assert.equal(request.isEncrypted, false);
    assert.equal(request.isSliced, false);
    assert.equal(ok(decodeFrames(ok(encodeRequest(request))[0]))[0].commandId, 0x16);
  });

  test("the status is tag 0x01, and a reply without it is -1, as upstream defaults", () => {
    assert.equal(ok(parseDeviceStatus(new HuaweiTlv().putByte(0x01, 0x01))), 0x01);
    assert.equal(ok(parseDeviceStatus(new HuaweiTlv().putByte(0x01, 0xff))), 0xff);
    assert.equal(ok(parseDeviceStatus(new HuaweiTlv().putByte(0x02, 0x00))), -1);
  });

  test("the pin code request is 0x01/0x2C with one empty tag, unencrypted and unsliced", () => {
    const request = pincodeRequest();
    assert.equal(request.serviceId, DEVICE_CONFIG.serviceId);
    assert.equal(request.commandId, DEVICE_CONFIG.pinCode);
    assert.deepEqual(request.tlv.entries.map((entry) => entry.tag), [0x01]);
    assert.equal(request.isEncrypted, false);
    assert.equal(request.isSliced, false);
  });

  test("the pin code reply is decrypted with the static digest secret, not the user's key", () => {
    const calls: { encryptMethod: number; message: number[]; iv: number[] }[] = [];
    const stub = {
      decryptPinCode(encryptMethod: number, message: Uint8Array, iv: Uint8Array) {
        calls.push({ encryptMethod, message: [...message], iv: [...iv] });
        return { ok: true as const, value: bytes(0x31, 0x32, 0x33, 0x34, 0x35, 0x36) };
      },
    };
    const tlv = new HuaweiTlv().putBytes(0x01, bytes(0xaa, 0xbb)).putBytes(0x02, bytes(0xcc));
    assert.deepEqual(ok(parsePincodeResponse(tlv, stub, 0x01)), bytes(0x31, 0x32, 0x33, 0x34, 0x35, 0x36));
    assert.deepEqual(calls, [{ encryptMethod: 0x01, message: [0xaa, 0xbb], iv: [0xcc] }]);

    const noMessage = new HuaweiTlv().putBytes(0x02, bytes(0xcc));
    assert.equal(failure(parsePincodeResponse(noMessage, stub, 0x01)).code, "auth-truncated");
    const noIv = new HuaweiTlv().putBytes(0x01, bytes(0xaa));
    assert.equal(failure(parsePincodeResponse(noIv, stub, 0x01)).code, "auth-truncated");
  });
});

const ANDROID_ID = "0123456789abcdef0123456789abcdef";
const ANDROID_ID_BYTES = new Uint8Array(Buffer.from(ANDROID_ID, "utf8"));
const RAND_SELF = Uint8Array.from({ length: 16 }, (_, i) => 0x10 + i);
const SEED = Uint8Array.from({ length: 32 }, (_, i) => 0x20 + i);
const NONCE = Uint8Array.from({ length: 12 }, (_, i) => 0x30 + i);
const ENC_DATA = Uint8Array.from({ length: 32 }, (_, i) => 0x40 + i);
const SELF_TOKEN = Uint8Array.from({ length: 32 }, (_, i) => 0x50 + i);
const ENC_RESULT = Uint8Array.from({ length: 20 }, (_, i) => 0x60 + i);

/** The JSON envelope of a built HiChain step, as the watch parses it (tag 0x01). */
const envelope = (input: HiChainStepInput): Record<string, unknown> =>
  JSON.parse(ok(hiChainRequest(input)).tlv.getString(0x01)) as Record<string, unknown>;
const payloadOf = (input: HiChainStepInput): Record<string, unknown> =>
  envelope(input).payload as Record<string, unknown>;
const jsonKeys = (value: Record<string, unknown>): string[] => Object.keys(value);

const bindStep = (step: 1 | 2 | 3 | 4, extra: Partial<HiChainStepInput> = {}): HiChainStepInput => ({
  operationCode: 0x02,
  requestId: 1700000000000n,
  androidId: ANDROID_ID_BYTES,
  step,
  randSelf: RAND_SELF,
  seed: SEED,
  ...extra,
});
const authStep = (step: 1 | 2 | 3 | 4, extra: Partial<HiChainStepInput> = {}): HiChainStepInput => ({
  operationCode: 0x01,
  requestId: 1700000000000n,
  androidId: ANDROID_ID_BYTES,
  step,
  randSelf: RAND_SELF,
  seed: SEED,
  ...extra,
});

describe("authPackets — the HiChain JSON envelope (DeviceConfig.createJson, :1114-1144)", () => {
  test("bind step 1: the value's keys in upstream's order, message 0x11, isDeviceLevel false", () => {
    const value = envelope(bindStep(1));
    assert.deepEqual(jsonKeys(value),
      ["authForm", "payload", "groupAndModuleVersion", "message", "isDeviceLevel"]);
    assert.equal(value.authForm, 0x00);
    assert.equal(value.groupAndModuleVersion, HI_CHAIN_GROUP_AND_MODULE_VERSION);
    assert.equal(value.message, 0x11);
    assert.equal(value.isDeviceLevel, false);

    const payload = payloadOf(bindStep(1));
    assert.deepEqual(jsonKeys(payload),
      ["version", "isoSalt", "peerAuthId", "operationCode", "seed", "peerUserType", "pkgName", "serviceType", "keyLength"]);
    assert.deepEqual(jsonKeys(payload.version as Record<string, unknown>), ["minVersion", "currentVersion"]);
    assert.equal((payload.version as Record<string, unknown>).minVersion, HI_CHAIN_MIN_VERSION);
    assert.equal((payload.version as Record<string, unknown>).currentVersion, HI_CHAIN_CURRENT_VERSION);
    assert.equal(payload.isoSalt, hexdumpUpper(RAND_SELF));
    assert.equal(payload.peerAuthId, hexdumpUpper(ANDROID_ID_BYTES));
    assert.equal(payload.seed, hexdumpUpper(SEED));
    assert.equal(payload.operationCode, 0x02);
    assert.equal(payload.peerUserType, 0x00);
    assert.equal(payload.pkgName, HI_CHAIN_PKG_NAME);
    assert.equal(payload.serviceType, HI_CHAIN_GROUP_ID);
    assert.equal(payload.keyLength, 0x20);
  });

  test("bind step 1: three TLVs, and the request id big-endian in tag 0x03", () => {
    const request = ok(hiChainRequest(bindStep(1)));
    assert.equal(request.serviceId, DEVICE_CONFIG.serviceId);
    assert.equal(request.commandId, DEVICE_CONFIG.hiChain);
    assert.equal(request.commandId, 0x28);
    assert.deepEqual(request.tlv.entries.map((entry) => entry.tag), [0x01, 0x02, 0x03]);
    assert.equal(request.tlv.getByte(0x02), 0x02);
    const expected = Buffer.alloc(8);
    expected.writeBigUInt64BE(1700000000000n);
    assert.deepEqual(request.tlv.getBytes(0x03), new Uint8Array(expected));
    assert.equal(request.isEncrypted, false);
    assert.equal(request.isSliced, true);
  });

  test("bind step 2: message 0x12, peerAuthId and token, isDeviceLevel again, no requestId", () => {
    const input = bindStep(2, { selfToken: SELF_TOKEN });
    const value = envelope(input);
    assert.equal(value.message, 0x12);
    assert.equal(value.isDeviceLevel, false);
    assert.equal("requestId" in value, false);
    const payload = payloadOf(input);
    assert.deepEqual(jsonKeys(payload), ["version", "peerAuthId", "token"]);
    assert.equal(payload.peerAuthId, hexdumpUpper(ANDROID_ID_BYTES));
    assert.equal(payload.token, hexdumpUpper(SELF_TOKEN));
  });

  test("bind step 4 sends message 0x13: upstream captured the step before incrementing it", () => {
    const input = bindStep(4, { nonce: NONCE, encResult: ENC_RESULT, messageId: 3 });
    assert.equal(envelope(input).message, 0x13);
    assert.equal("isDeviceLevel" in envelope(input), false);
    const payload = payloadOf(input);
    assert.deepEqual(jsonKeys(payload), ["version", "nonce", "encResult", "operationCode"]);
    assert.equal(payload.nonce, hexdumpUpper(NONCE));
    assert.equal(payload.encResult, hexdumpUpper(ENC_RESULT));
    assert.equal(payload.operationCode, 0x02);
    // Without the override the same step would say 0x14 — GetHiChainRequest.java:105 vs :144 vs :154.
    assert.equal(envelope(bindStep(4, { nonce: NONCE, encResult: ENC_RESULT })).message, 0x14);
  });

  test("the auth operation: message 1..4, a string requestId, the group block, no isDeviceLevel", () => {
    const one = envelope(authStep(1));
    assert.equal(one.message, 0x01);
    assert.equal("isDeviceLevel" in one, false);
    assert.deepEqual(jsonKeys(one), [
      "authForm", "payload", "groupAndModuleVersion", "message", "requestId", "groupId", "groupName",
      "groupOp", "groupType", "peerDeviceId", "connDeviceId", "appId", "ownerName",
    ]);
    assert.equal(one.requestId, "1700000000000");
    assert.equal(one.groupId, HI_CHAIN_GROUP_ID);
    assert.equal(one.groupName, "health_group_name");
    assert.equal(one.groupOp, 2);
    assert.equal(one.groupType, 256);
    assert.equal(one.peerDeviceId, ANDROID_ID);
    assert.equal(one.connDeviceId, ANDROID_ID);
    assert.equal(one.appId, "com.huawei.health");
    assert.equal(one.ownerName, "");
    // The auth operation has no pkgName/serviceType/keyLength: those are the bind operation's (:1021-1025).
    const payload = payloadOf(authStep(1));
    assert.deepEqual(jsonKeys(payload), ["version", "isoSalt", "peerAuthId", "operationCode", "seed", "peerUserType"]);
    assert.equal(payload.operationCode, 0x01);
    assert.equal(envelope(authStep(3, { nonce: NONCE, encData: ENC_DATA })).message, 0x03);
    assert.equal(envelope(authStep(4, { nonce: NONCE, encResult: ENC_RESULT })).message, 0x04);
  });

  test("a step without its inputs is bad-argument, never a half-built request", () => {
    assert.equal(failure(hiChainRequest(authStep(1, { randSelf: undefined }))).code, "bad-argument");
    assert.equal(failure(hiChainRequest(authStep(1, { seed: undefined }))).code, "bad-argument");
    assert.equal(failure(hiChainRequest(authStep(2))).code, "bad-argument");
    assert.equal(failure(hiChainRequest(authStep(3, { nonce: NONCE }))).code, "bad-argument");
    assert.equal(failure(hiChainRequest(authStep(4, { encResult: ENC_RESULT }))).code, "bad-argument");
  });
});

/** The watch's side of a HiChain step: one JSON string in tag 0x01, the payload type in tag 0x04. */
const reply = (payload: Record<string, unknown>, type = 0x00): HuaweiTlv =>
  new HuaweiTlv()
    .putString(0x01, JSON.stringify({ authForm: 0, payload, groupAndModuleVersion: "2.0.1", message: 0x11 }))
    .putByte(0x04, type);
const rawEnvelope = (json: string, type = 0x00): HuaweiTlv =>
  new HuaweiTlv().putString(0x01, json).putByte(0x04, type);

describe("authPackets — reading the watch's HiChain replies (DeviceConfig.HiChain.Response, :1229-1279)", () => {
  test("step 1 is recognised by isoSalt, and its four fields are hex-decoded", () => {
    const response = ok(parseHiChainResponse(reply({
      errorCode: 0,
      isoSalt: "AABB",
      peerAuthId: "CCDD",
      token: hexdumpUpper(SELF_TOKEN),
      peerUserType: 1,
    })));
    assert.equal(response.type, 0x00);
    assert.equal(response.step, 1);
    assert.deepEqual(response.step1?.isoSalt, bytes(0xaa, 0xbb));
    assert.deepEqual(response.step1?.peerAuthId, bytes(0xcc, 0xdd));
    assert.deepEqual(response.step1?.token, SELF_TOKEN);
    assert.equal(response.step1?.peerUserType, 1);
  });

  test("step 2 is recognised by returnCodeMac, step 3 by encAuthToken with its nonce", () => {
    const two = ok(parseHiChainResponse(reply({ returnCodeMac: "0102" })));
    assert.equal(two.step, 2);
    assert.deepEqual(two.step2?.returnCodeMac, bytes(0x01, 0x02));
    const three = ok(parseHiChainResponse(reply({ nonce: "0304", encAuthToken: "0506" })));
    assert.equal(three.step, 3);
    assert.deepEqual(three.step3?.nonce, bytes(0x03, 0x04));
    assert.deepEqual(three.step3?.encAuthToken, bytes(0x05, 0x06));
    // Upstream's own comment calls this ugly (:1244): the step exists only as this key test.
    assert.equal(ok(parseHiChainResponse(reply({ peerUserType: 0 }))).step, 0);
  });

  test("a non-zero type is step 4 and the tag 0x01 value is raw data, not JSON", () => {
    const response = ok(parseHiChainResponse(rawEnvelope("SOME-DATA", 0x01)));
    assert.equal(response.type, 0x01);
    assert.equal(response.step, 4);
    assert.equal(response.step4?.data, "SOME-DATA");
    const withoutData = ok(parseHiChainResponse(new HuaweiTlv().putByte(0x04, 0x02)));
    assert.equal(withoutData.step, 4);
    assert.equal(withoutData.step4?.data, null);
  });

  test("errorCode is reported and does not stop the parse", () => {
    const response = ok(parseHiChainResponse(reply({ errorCode: 10001, returnCodeMac: "0102" })));
    assert.equal(response.errorCode, 10001);
    assert.equal(response.step, 2);
  });

  test("a reply that cannot be read is auth-truncated, and names the key at fault", () => {
    assert.equal(failure(parseHiChainResponse(new HuaweiTlv().putString(0x01, "{}"))).code, "auth-truncated");
    assert.equal(failure(parseHiChainResponse(new HuaweiTlv().putByte(0x04, 0x00))).code, "auth-truncated");
    assert.equal(failure(parseHiChainResponse(rawEnvelope("not json"))).code, "auth-truncated");
    assert.equal(failure(parseHiChainResponse(rawEnvelope(JSON.stringify({ authForm: 0 })))).code, "auth-truncated");
    assert.equal(failure(parseHiChainResponse(reply({ isoSalt: "AABB", peerAuthId: "CCDD" }))).detail, "token");
    assert.equal(failure(parseHiChainResponse(reply({ isoSalt: "ZZ", peerAuthId: "CCDD", token: "EEFF" }))).detail, "isoSalt");
  });

  test("trailing NUL bytes inside tag 0x01 are trimmed before JSON parsing", () => {
    const jsonBytes = new TextEncoder().encode(JSON.stringify({ payload: { returnCodeMac: "0102" } }));
    const padded = new Uint8Array(jsonBytes.length + 2);
    padded.set(jsonBytes, 0);
    const tlv = new HuaweiTlv().putBytes(0x01, padded).putByte(0x04, 0x00);
    const response = ok(parseHiChainResponse(tlv));
    assert.equal(response.step, 2);
    assert.deepEqual(response.step2?.returnCodeMac, bytes(0x01, 0x02));
  });

  test("non-JSON tag 0x01 reports structural metadata without echoing payload text", () => {
    const err = failure(parseHiChainResponse(rawEnvelope("not json")));
    assert.equal(err.code, "auth-truncated");
    assert.ok(err.detail?.includes("len=8"));
    assert.ok(err.detail?.includes("head=6e6f"));
    assert.equal(err.detail?.includes("not json"), false);
  });
});

