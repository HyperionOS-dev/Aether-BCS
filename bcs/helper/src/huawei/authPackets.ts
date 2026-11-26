// BCS helper — Phase 3 (trust/auth): the auth-related packets — link parameters, device status,
// security negotiation, pin code, and the four HiChain steps. Pure code: TLV/JSON in, TLV/JSON out.
// No socket, no process, no timer, no file, no key storage.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7 (GitHub mirror,
// frozen 2024-12-22), read-only:
//   devices/huawei/packets/DeviceConfig.java
//     LinkParams.Response        lines 50-123   (tags 0x01-0x05, 0x07-0x09, 0x0C)
//     DeviceStatus.Request/.Resp lines 858-902   (tags 0x01 / 0x02, status = tag 0x01)
//     SecurityNegotiation        lines 1575-1640 (request tags 0x01-0x07, 0x0D; authType rule)
//     HiChain                    lines 970-1419  (JSON envelope, steps 1-4, response type/step)
//     PinCode                    lines 1419-1462 (request tag 0x01; reply 0x01 message, 0x02 iv)
//   devices/huawei/HuaweiConstants.java:30  GROUP_ID
//   service/devices/huawei/HuaweiSupportProvider.java
//     isHiChain / isHiChainLite / isHiChain3     lines 474-495
//     initializeDeviceDealHiChain                lines 497-529
//     initializeDeviceHiChainMode                lines 564-578
//   service/devices/huawei/requests/GetHiChainRequest.java lines 60-256 (the step machine)
//   service/devices/huawei/requests/GetSecurityNegotiationRequest.java
//   service/devices/huawei/requests/GetPincodeRequest.java
//   service/devices/huawei/requests/GetDeviceStatusRequest.java
//
// Divergences: every parse returns a typed error instead of throwing ParseException; every optional
// tag is read with tryGet* and defaulted rather than read unconditionally; nothing is logged.
// The JSON key order and every literal mirror upstream, because the device parses this JSON — see
// HI_CHAIN_* below and the notes on `message`.

import { codecFail, codecOk, type CodecResult } from "./errors.ts";
import { authError, type HuaweiAuthError } from "./authErrors.ts";
import { DEVICE_CONFIG } from "./constants.ts";
import { hexdumpUpper, hexToBytes } from "./crypto.ts";
import { HuaweiTlv } from "./tlv.ts";
import type { HuaweiRequest } from "./requests.ts";

/** HuaweiConstants.java:30 — the HiChain group id, a published upstream constant. */
export const HI_CHAIN_GROUP_ID = "7B0BC0CBCE474F6C238D9661C63400B797B166EA7849B3A370FC73A9A236E989";
/** HiChain StepOne, operationCode 0x02 (DeviceConfig.java:1155). */
export const HI_CHAIN_PKG_NAME = "com.huawei.devicegroupmanage";
/** HiChain JSON versions (DeviceConfig.java:1132-1133, :1159). */
export const HI_CHAIN_MIN_VERSION = "1.0.0";
export const HI_CHAIN_CURRENT_VERSION = "2.0.16";
export const HI_CHAIN_GROUP_AND_MODULE_VERSION = "2.0.1";

const failure = (code: Parameters<typeof authError>[0], message: string, step: string, detail: string | null = null) =>
  codecFail(code as never, message, null, detail) as CodecResult<never>;

/** LinkParams.Response fields (DeviceConfig.java:24-34). */
export interface LinkParamsInfo {
  protocolVersion: number;
  sliceSize: number;
  mtu: number;
  interval: number;
  authVersion: number;
  /** 16 bytes: tag 0x05 from offset 2 (DeviceConfig.java:57-58). */
  serverNonce: Uint8Array;
  deviceSupportType: number;
  authAlgo: number;
  bondState: number;
  encryptMethod: number;
}

/**
 * LinkParams.Response.parseTlv (DeviceConfig.java:43-71). Tag 0x05 carries
 * `[?, authVersion, serverNonce(16)]`; tags 0x01-0x04 and 0x07-0x09, 0x0C are optional and default
 * exactly as upstream defaults them (mtu 0x14, sliceSize 0xF4).
 */
export function parseLinkParams(tlv: HuaweiTlv): CodecResult<LinkParamsInfo> {
  const nonceTag = tlv.tryGetBytes(0x05);
  if (!nonceTag.ok) return failure("auth-negotiation", "link params has no auth/nonce tag 0x05", "link-params");
  if (nonceTag.value.length < 18) {
    return failure("auth-truncated", "link params tag 0x05 is shorter than 18 bytes", "link-params",
      `got ${nonceTag.value.length}`);
  }
  const byteOrDefault = (tag: number, fallback: number): number => {
    const read = tlv.tryGetByte(tag);
    return read.ok ? read.value : fallback;
  };
  const shortOrDefault = (tag: number, fallback: number): number => {
    const read = tlv.tryGetShort(tag);
    return read.ok ? read.value : fallback;
  };
  return codecOk({
    protocolVersion: byteOrDefault(0x01, 0x00),
    sliceSize: shortOrDefault(0x02, 0x00f4),
    mtu: shortOrDefault(0x03, 0x0014),
    interval: shortOrDefault(0x04, 0x00),
    authVersion: nonceTag.value[1],
    serverNonce: nonceTag.value.slice(2, 18),
    deviceSupportType: byteOrDefault(0x07, 0x00),
    authAlgo: byteOrDefault(0x08, 0x00),
    bondState: byteOrDefault(0x09, 0x00),
    encryptMethod: byteOrDefault(0x0c, 0x00),
  });
}

/** Which auth path the device's deviceSupportType selects (HuaweiSupportProvider.java:474-495). */
export type AuthPath = "hichain" | "hichain-lite" | "normal";

export function authPathFor(deviceSupportType: number): AuthPath {
  if (deviceSupportType === 0x02) return "hichain-lite";
  if (deviceSupportType === 0x01 || deviceSupportType === 0x03 || deviceSupportType === 0x04) return "hichain";
  return "normal";
}

/**
 * DeviceStatus.Request (DeviceConfig.java:861-875) and its parseTlv (:886-892).
 * `askStatus` true sends tag 0x01 and the reply carries the status in tag 0x01.
 */
export function deviceStatusRequest(): HuaweiRequest {
  return {
    serviceId: DEVICE_CONFIG.serviceId,
    commandId: DEVICE_CONFIG.deviceStatus,
    tlv: new HuaweiTlv().putEmpty(0x01),
    isEncrypted: false,
    isSliced: false,
  };
}

export function parseDeviceStatus(tlv: HuaweiTlv): CodecResult<number> {
  const status = tlv.tryGetByte(0x01);
  // AW70 has no status tag at all and upstream leaves the default -1 in place (:888-891).
  return codecOk(status.ok ? status.value : -1);
}

/**
 * SecurityNegotiation.Request (DeviceConfig.java:1578-1608): tag 0x01 authMode, 0x02 = 0x01 when
 * authMode is 2 or 4 ("force to not reconnected"), 0x05 the device uuid (upstream sends the android
 * id), 0x03 = 0x01, 0x04 = 0x00, mode 4 adds 0x06 and 0x07 (phone model), and 0x0D = 0x01 when the
 * device asked for encryptMethod 1.
 */
export function securityNegotiationRequest(input: {
  authMode: number;
  deviceUuid: Uint8Array;
  phoneModel: string;
  encryptMethod: number;
}): HuaweiRequest {
  const tlv = new HuaweiTlv().putByte(0x01, input.authMode);
  if (input.authMode === 0x02 || input.authMode === 0x04) tlv.putByte(0x02, 0x01);
  tlv.putBytes(0x05, input.deviceUuid)
    .putByte(0x03, 0x01)
    .putByte(0x04, 0x00);
  if (input.authMode === 0x04) {
    tlv.putEmpty(0x06).putString(0x07, input.phoneModel);
  }
  if (input.encryptMethod === 1) tlv.putByte(0x0d, 0x01);
  return {
    serviceId: DEVICE_CONFIG.serviceId,
    commandId: DEVICE_CONFIG.securityNegotiation,
    tlv,
    isEncrypted: false,
    isSliced: true,
  };
}

/** SecurityNegotiation.Response.parseTlv (DeviceConfig.java:1598-1637). */
export function parseSecurityNegotiation(tlv: HuaweiTlv): CodecResult<number> {
  let authType = -1;
  let pw = -1;
  const first = tlv.tryGetByte(0x01);
  if (first.ok) {
    if (first.value === 0x01) authType = 0x0186a0;
    if (first.value === 0x04) pw = 4;
  }
  const second = tlv.tryGetByte(0x02);
  if (second.ok) {
    authType = second.value;
    if (pw !== -1) authType ^= pw;
  }
  const result = tlv.tryGetByte(0x7f);
  if (result.ok) authType = result.value;
  return codecOk(authType);
}

/** isHiChain3 (HuaweiSupportProvider.java:493-495): (authType ^ 1) == 4 || (authType ^ 2) == 4. */
export function isHiChain3(authType: number): boolean {
  return (authType ^ 0x01) === 0x04 || (authType ^ 0x02) === 0x04;
}

/** PinCode.Request (DeviceConfig.java:1422-1437): a single empty tag 0x01. */
export function pincodeRequest(): HuaweiRequest {
  return {
    serviceId: DEVICE_CONFIG.serviceId,
    commandId: DEVICE_CONFIG.pinCode,
    tlv: new HuaweiTlv().putEmpty(0x01),
    isEncrypted: false,
    isSliced: false,
  };
}

/**
 * PinCode.Response.parseTlv (DeviceConfig.java:1449-1460): tag 0x01 is the AES-encrypted code and tag
 * 0x02 its IV; the AES key is the *static* digest secret, never the user's key.
 */
export function parsePincodeResponse(
  tlv: HuaweiTlv,
  crypto: { decryptPinCode(encryptMethod: number, message: Uint8Array, iv: Uint8Array): CodecResult<Uint8Array> },
  encryptMethod: number,
): CodecResult<Uint8Array> {
  const message = tlv.tryGetBytes(0x01);
  if (!message.ok) return failure("auth-truncated", "pin code reply has no tag 0x01", "pincode");
  const iv = tlv.tryGetBytes(0x02);
  if (!iv.ok) return failure("auth-truncated", "pin code reply has no tag 0x02", "pincode");
  return crypto.decryptPinCode(encryptMethod, message.value, iv.value);
}

/** Operation code: 0x01 = the auth operation, 0x02 = the bind operation (GetHiChainRequest.java:42). */
export type HiChainOperation = 0x01 | 0x02;

export interface HiChainStepInput {
  operationCode: HiChainOperation;
  /**
   * Overrides the `message` value that would otherwise be the step. Needed in exactly one place:
   * the bind operation's step 4. Upstream captures `int messageId = step;` at
   * GetHiChainRequest.java:105 and then, on the bind path only, does `step += 0x01` at :144 before
   * building StepFour with the *captured* value at :154 — so the bind operation sends
   * `3 | 0x10 = 0x13` there, not `0x14`. The commented-out lines in StepFour (:1094-1098) show the
   * upstream author hitting the same question and leaving the captured value in place.
   */
  messageId?: number;
  /** System.currentTimeMillis() upstream; 8 bytes, big-endian (DeviceConfig.java:1006). */
  requestId: bigint;
  /** selfAuthId: the fake Android ID, as UTF-8 bytes (HuaweiSupportProvider.getAndroidId). */
  androidId: Uint8Array;
  step: 1 | 2 | 3 | 4;
  /** Step 1: isoSalt is randSelf, seed is 32 random bytes (GetHiChainRequest.java:106-113). */
  randSelf?: Uint8Array;
  seed?: Uint8Array;
  /** Step 2: HMAC(psk, randSelf‖randPeer‖authIdPeer‖authIdSelf) — see the note on ordering below. */
  selfToken?: Uint8Array;
  /** Steps 3 and 4. */
  nonce?: Uint8Array;
  encData?: Uint8Array;
  encResult?: Uint8Array;
}

function stepPayload(input: HiChainStepInput): CodecResult<Record<string, unknown>> {
  const payload: Record<string, unknown> = {
    version: { minVersion: HI_CHAIN_MIN_VERSION, currentVersion: HI_CHAIN_CURRENT_VERSION },
  };
  if (input.step === 1) {
    if (!input.randSelf || !input.seed) return failure("bad-argument", "step 1 needs randSelf and seed", "hichain");
    payload.isoSalt = hexdumpUpper(input.randSelf);
    payload.peerAuthId = hexdumpUpper(input.androidId);
    payload.operationCode = input.operationCode;
    payload.seed = hexdumpUpper(input.seed);
    payload.peerUserType = 0x00;
    if (input.operationCode === 0x02) {
      payload.pkgName = HI_CHAIN_PKG_NAME;
      payload.serviceType = HI_CHAIN_GROUP_ID;
      payload.keyLength = 0x20;
    }
  } else if (input.step === 2) {
    if (!input.selfToken) return failure("bad-argument", "step 2 needs selfToken", "hichain");
    payload.peerAuthId = hexdumpUpper(input.androidId);
    payload.token = hexdumpUpper(input.selfToken);
  } else if (input.step === 3) {
    if (!input.nonce || !input.encData) return failure("bad-argument", "step 3 needs nonce and encData", "hichain");
    payload.nonce = hexdumpUpper(input.nonce);
    payload.encData = hexdumpUpper(input.encData);
  } else {
    if (!input.nonce || !input.encResult) return failure("bad-argument", "step 4 needs nonce and encResult", "hichain");
    payload.nonce = hexdumpUpper(input.nonce);
    payload.encResult = hexdumpUpper(input.encResult);
    payload.operationCode = input.operationCode;
  }
  return codecOk(payload);
}

/**
 * DeviceConfig.HiChain.Request and its four steps (DeviceConfig.java:983-1180).
 *
 * The envelope is one JSON string in tag 0x01, plus tag 0x02 = operationCode and tag 0x03 =
 * requestId as a big-endian long. Two upstream details are reproduced exactly, because the watch
 * parses this JSON:
 *  - `createJson` masks the message with `messageId |= 0x10` when operationCode is 0x02 (:1113-1115),
 *    so the bind operation's messages are 0x11..0x14 while the auth operation's are 1..4.
 *  - `isDeviceLevel: false` is added only by StepOne and StepTwo, and only for operationCode 0x02.
 * Request ids are strings (`Long.toString`) in the auth operation and absent in the bind operation.
 */
export function hiChainRequest(input: HiChainStepInput): CodecResult<HuaweiRequest> {
  const payload = stepPayload(input);
  if (!payload.ok) return payload;
  const baseId = input.messageId ?? input.step;
  const messageId = input.operationCode === 0x02 ? (baseId | 0x10) : baseId;
  const value: Record<string, unknown> = {
    authForm: 0x00,
    payload: payload.value,
    groupAndModuleVersion: HI_CHAIN_GROUP_AND_MODULE_VERSION,
    message: messageId,
  };
  if (input.operationCode === 0x02 && (input.step === 1 || input.step === 2)) {
    value.isDeviceLevel = false;
  }
  if (input.operationCode === 0x01) {
    const selfAuthId = Buffer.from(input.androidId).toString("utf8");
    value.requestId = input.requestId.toString();
    value.groupId = HI_CHAIN_GROUP_ID;
    value.groupName = "health_group_name";
    value.groupOp = 2;
    value.groupType = 256;
    value.peerDeviceId = selfAuthId;
    value.connDeviceId = selfAuthId;
    value.appId = "com.huawei.health";
    value.ownerName = "";
  }
  const requestId = Buffer.alloc(8);
  requestId.writeBigUInt64BE(BigInt.asUintN(64, input.requestId));
  return codecOk({
    serviceId: DEVICE_CONFIG.serviceId,
    commandId: DEVICE_CONFIG.hiChain,
    tlv: new HuaweiTlv()
      .putString(0x01, JSON.stringify(value))
      .putByte(0x02, input.operationCode)
      .putBytes(0x03, new Uint8Array(requestId)),
    isEncrypted: false,
    // BaseStep sets isSliced = true (DeviceConfig.java:996): these frames are always sliced.
    isSliced: true,
  });
}

export interface HiChainStep1Data {
  isoSalt: Uint8Array;
  peerAuthId: Uint8Array;
  peerUserType: number;
  token: Uint8Array;
}
export interface HiChainStep2Data { returnCodeMac: Uint8Array }
export interface HiChainStep3Data { nonce: Uint8Array; encAuthToken: Uint8Array }
export interface HiChainStep4Data { data: string | null }
export interface HiChainResponse {
  type: number;
  /** 1..4. Upstream infers it from which payload keys are present; so does this. */
  step: number;
  errorCode: number;
  step1?: HiChainStep1Data;
  step2?: HiChainStep2Data;
  step3?: HiChainStep3Data;
  step4?: HiChainStep4Data;
}

function hexField(payload: Record<string, unknown>, key: string): CodecResult<Uint8Array> {
  const raw = payload[key];
  if (typeof raw !== "string") {
    return failure("auth-truncated", `HiChain payload has no "${key}" string`, "hichain", key);
  }
  const decoded = hexToBytes(raw);
  if (!decoded.ok) {
    return failure("auth-truncated", `HiChain payload "${key}" is not hex`, "hichain", key);
  }
  return decoded;
}

/**
 * DeviceConfig.HiChain.Response.parseTlv (DeviceConfig.java:1229-1279). Tag 0x04 is the payload type:
 * 0x00 means the tag 0x01 value is JSON, anything else means step 4 and the tag 0x01 value is the
 * raw data string. Inside the JSON, the step is inferred from the payload keys exactly as upstream
 * does: `isoSalt` → 1, `returnCodeMac` → 2, `encAuthToken` → 3.
 */
export function parseHiChainResponse(tlv: HuaweiTlv): CodecResult<HiChainResponse> {
  const type = tlv.tryGetByte(0x04);
  if (!type.ok) return failure("auth-truncated", "HiChain reply has no type tag 0x04", "hichain");
  if (type.value !== 0x00) {
    const data = tlv.tryGetString(0x01);
    return codecOk({
      type: type.value,
      step: 4,
      errorCode: 0,
      step4: { data: data.ok ? data.value : null },
    });
  }
  const raw = tlv.tryGetBytes(0x01);
  if (!raw.ok) return failure("auth-truncated", "HiChain reply has no JSON tag 0x01", "hichain");
  let end = raw.value.length;
  while (end > 0 && raw.value[end - 1] === 0x00) end -= 1;
  const trimmed = raw.value.subarray(0, end);
  const text = new TextDecoder().decode(trimmed);
  let value: Record<string, unknown>;
  try {
    value = JSON.parse(text) as Record<string, unknown>;
  } catch (err) {
    const bytes = raw.value;
    const hex2 = (slice: Uint8Array): string =>
      Array.from(slice, (b) => b.toString(16).padStart(2, "0")).join("");
    let ctrl = 0;
    let nonAscii = 0;
    for (const b of trimmed) {
      if (b >= 0x80) nonAscii += 1;
      else if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) ctrl += 1;
    }
    const msg = err instanceof Error ? err.message : "";
    const posMatch = /position ([0-9]+)/.exec(msg);
    const pos = posMatch ? Number(posMatch[1]) : null;
    const atHex = pos !== null && pos < text.length
      ? text.charCodeAt(pos).toString(16).padStart(2, "0")
      : null;
    const detail = [
      `len=${bytes.length}`,
      `nul=${bytes.length - end}`,
      `head=${hex2(bytes.subarray(0, 2))}`,
      `tail=${hex2(bytes.subarray(Math.max(0, bytes.length - 2)))}`,
      `open=${text.indexOf("{")}`,
      `close=${text.lastIndexOf("}")}`,
      `ctrl=${ctrl}`,
      `nonAscii=${nonAscii}`,
      ...(pos !== null ? [`pos=${pos}`] : []),
      ...(atHex !== null ? [`at=0x${atHex}`] : []),
    ].join(" ");
    return failure("auth-truncated", "HiChain reply tag 0x01 is not JSON", "hichain", detail);
  }
  const payload = value.payload;
  if (payload === null || typeof payload !== "object") {
    return failure("auth-truncated", "HiChain reply JSON has no payload object", "hichain");
  }
  const fields = payload as Record<string, unknown>;
  const errorCodeRaw = fields.errorCode;
  const response: HiChainResponse = {
    type: type.value,
    step: 0,
    errorCode: typeof errorCodeRaw === "number" ? errorCodeRaw : 0,
  };
  if ("isoSalt" in fields) {
    const isoSalt = hexField(fields, "isoSalt");
    const peerAuthId = hexField(fields, "peerAuthId");
    const token = hexField(fields, "token");
    if (!isoSalt.ok) return isoSalt;
    if (!peerAuthId.ok) return peerAuthId;
    if (!token.ok) return token;
    const userType = fields.peerUserType;
    response.step = 1;
    response.step1 = {
      isoSalt: isoSalt.value,
      peerAuthId: peerAuthId.value,
      peerUserType: typeof userType === "number" ? userType : 0,
      token: token.value,
    };
  } else if ("returnCodeMac" in fields) {
    const mac = hexField(fields, "returnCodeMac");
    if (!mac.ok) return mac;
    response.step = 2;
    response.step2 = { returnCodeMac: mac.value };
  } else if ("encAuthToken" in fields) {
    const nonce = hexField(fields, "nonce");
    const encAuthToken = hexField(fields, "encAuthToken");
    if (!nonce.ok) return nonce;
    if (!encAuthToken.ok) return encAuthToken;
    response.step = 3;
    response.step3 = { nonce: nonce.value, encAuthToken: encAuthToken.value };
  }
  return codecOk(response);
}