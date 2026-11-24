// BCS helper — Phase 3 (trust/auth): the auth state machine. Bytes in, bytes out, no I/O, no timers,
// no retries. The caller owns the transport, the timeouts and the decision to stop.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7 (GitHub mirror,
// frozen 2024-12-22), read-only:
//   service/devices/huawei/HuaweiSupportProvider.java
//     initializeDevice → link params, then device status        lines 405-473
//     initializeDeviceDealHiChain (mode, security negotiation)  lines 497-529
//     initializeDeviceHiChainMode (pin code first, or not)      lines 564-578
//     configureReq timeout/exception → disconnect               lines 535-560
//     createSecretKey / getSecretKey                            lines 677-699
//   service/devices/huawei/requests/GetHiChainRequest.java      lines 38-256 (the whole step machine)
//
// What this is: the sequence, the step arithmetic, the MAC checks and the key derivations — the part
// that can be proven offline. What this is NOT: a transport. It never opens, reads, writes or closes
// anything; every function returns the bytes a caller should send, and nothing else.
//
// Guarantees this file is written to keep:
//  * The key is copied on construction and zeroed by destroy()/on completion. Intermediate secrets
//    (psk, sessionKey, seed) are zeroed as soon as they are no longer needed, where a buffer is ours.
//  * No key material — key bytes, key hex, key base64, or anything derived from the key — can reach
//    an error message or a `detail`. Every message in this file is a literal or a number.
//  * No loop and no retry: each onFrame produces at most one next request, and only for the frame it
//    expects. Anything else is a typed failure and the machine stops in state "failed".
//
// Upstream quirk, ported verbatim (GetHiChainRequest.java:214-224 vs :31-38): the step-2 token that
// we *send* is HMAC(psk, randSelf‖randPeer‖authIdPeer‖authIdSelf) but the token we *verify* from the
// device is HMAC(psk, randPeer‖randSelf‖authIdSelf‖authIdPeer) — same four blocks, different order.
// Both paths are reproduced exactly; "fixing" either would break interop.

import { codecFail, codecOk, type CodecResult } from "./errors.ts";
import type { HuaweiAuthErrorCode } from "./authErrors.ts";
import {
  aesGcmDecryptNoPad,
  aesGcmEncryptNoPad,
  bytesEqualConstantTime,
  createHuaweiCrypto,
  hkdfSha256,
  hmacSha256,
  sha256,
  zeroBytes,
  hexdumpUpper,
  generateNonce,
  type HuaweiCrypto,
} from "./crypto.ts";
import {
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
  type HiChainOperation,
  type LinkParamsInfo,
} from "./authPackets.ts";
import { encodeRequest, linkParamsRequest } from "./requests.ts";
import type { HuaweiFrame } from "./frame.ts";
import { DEFAULT_SLICE_SIZE, DEVICE_CONFIG } from "./constants.ts";

export type AuthState =
  | "start"
  | "link-params"
  | "device-status"
  | "security-negotiation"
  | "pincode"
  | "hichain-auth-step1"
  | "hichain-auth-step2"
  | "hichain-auth-step3"
  | "hichain-auth-step4"
  | "hichain-bind-step1"
  | "hichain-bind-step2"
  | "hichain-bind-step3"
  | "hichain-bind-step4"
  | "done"
  | "failed";

export interface AuthMachineOptions {
  /** The user's auth key (the auth token). Copied; the machine never writes it anywhere. */
  key: Uint8Array;
  /** Identity bytes for HiChain (selfAuthId), i.e. the UTF-8 bytes of a 32-char id. Never the key. */
  androidId: Uint8Array;
  /** SecurityNegotiation tag 0x07, upstream sends Build.MODEL. Cosmetic for the watch. */
  phoneModel?: string;
  /**
   * "bind" (default): operation 0x02 with the stored key — what Gadgetbridge does on every later
   * connection, and what this tool does because the user has an auth code.
   * "auth-then-bind": operation 0x01 first (needs the pin code the watch displays), then the bind
   * operation with the token the watch returns. Only useful for a device that was never paired.
   */
  mode?: "bind" | "auth-then-bind";
  /** Required for mode "auth-then-bind" unless the caller lets the machine request the pin codes. */
  pinCode?: Uint8Array | null;
  /** Injectable RNG, so tests are deterministic. */
  random?: (n: number) => Uint8Array;
  /** Injectable clock for the HiChain request id, so tests are deterministic. */
  requestId?: () => bigint;
}

export interface AuthOutput {
  state: AuthState;
  /** The frames to write, in order. Empty when the flow finished or failed. */
  out: Uint8Array[];
  done: boolean;
}

export interface AuthMachine {
  readonly state: AuthState;
  /** How long the caller may wait for the reply in the current state (upstream: 5s, 30s for step 1). */
  readonly timeoutMs: number;
  /** The derived key after a successful bind operation. Null until `done`. */
  readonly finalKey: Uint8Array | null;
  /** True once no further request may be sent (done or failed). */
  readonly finished: boolean;
  start(): CodecResult<AuthOutput>;
  onFrame(frame: HuaweiFrame): CodecResult<AuthOutput>;
  /** Zeroes everything the machine holds. Safe to call more than once. */
  destroy(): void;
}

const STEP_TIMEOUT_MS = 5_000;
/** Upstream waits 30s for the first auth step because the user may have to confirm on the watch. */
const FIRST_HI_CHAIN_TIMEOUT_MS = 30_000;

/**
 * Phase 3G (D6): the model string SecurityNegotiation carries in tag 0x07. Upstream sends
 * `Build.MODEL` (`GetSecurityNegotiationRequest.java:67`, `DeviceConfig.java:1865-1876`), so the
 * default stays what it always was unless the caller configures another one.
 */
export const DEFAULT_PHONE_MODEL = "Aether Health BCS";

/**
 * Validate a phone model before it can become a frame.
 *
 * The value is sent as a UTF-8 string, so it has to be 1-32 printable ASCII characters: empty
 * would drop a tag, and anything outside ASCII would change the packet's length on the wire.
 */
export function validatePhoneModel(value: unknown): CodecResult<string> {
  if (typeof value !== "string" || value.length === 0) {
    return codecFail(
      "bad-argument",
      "the phone model must be 1-32 printable ASCII characters",
      null,
      "empty",
    );
  }
  if (value.length > 32) {
    return codecFail(
      "bad-argument",
      "the phone model must be 1-32 printable ASCII characters",
      null,
      `length ${value.length}`,
    );
  }
  if (!/^[\x20-\x7e]+$/.test(value)) {
    return codecFail(
      "bad-argument",
      "the phone model must be 1-32 printable ASCII characters",
      null,
      "not printable ASCII",
    );
  }
  return codecOk(value);
}

export function createAuthMachine(options: AuthMachineOptions): AuthMachine {
  const random = options.random ?? ((n: number) => new Uint8Array(generateNonce(n)));
  const nextRequestId = options.requestId ?? (() => BigInt(Date.now()));
  const phoneModel = options.phoneModel ?? DEFAULT_PHONE_MODEL;
  const mode = options.mode ?? "bind";
  const androidId = Uint8Array.from(options.androidId);

  let key: Uint8Array = Uint8Array.from(options.key);
  let pinCode: Uint8Array | null = options.pinCode ? Uint8Array.from(options.pinCode) : null;
  let state: AuthState = "start";
  let finalKey: Uint8Array | null = null;
  let params: LinkParamsInfo | null = null;
  let crypto: HuaweiCrypto | null = null;
  let authMode = 0x00;
  let sliceSize: number = DEFAULT_SLICE_SIZE;
  let operation: HiChainOperation = 0x02;
  let requestId = 0n;
  let randSelf: Uint8Array | null = null;
  let randPeer: Uint8Array | null = null;
  let authIdPeer: Uint8Array | null = null;
  let seed: Uint8Array | null = null;
  let psk: Uint8Array | null = null;
  let sessionKey: Uint8Array | null = null;
  let challenge: Uint8Array | null = null;
  /** Which HiChain step the machine is waiting for. Mirrors upstream's `byte step`. */
  let hiChainStep = 0;

  const wipeHandshake = (): void => {
    for (const buffer of [psk, sessionKey, challenge, seed]) if (buffer) zeroBytes(buffer);
    psk = null;
    sessionKey = null;
    challenge = null;
    seed = null;
  };

  const stop = (code: HuaweiAuthErrorCode, message: string, detail: string | null = null): CodecResult<never> => {
    state = "failed";
    wipeHandshake();
    zeroBytes(key);
    if (pinCode) {
      zeroBytes(pinCode);
      pinCode = null;
    }
    return codecFail(code as never, message, null, detail) as CodecResult<never>;
  };

  const advance = (next: AuthState, out: Uint8Array[]): CodecResult<AuthOutput> => {
    state = next;
    return codecOk({ state: next, out, done: next === "done" });
  };

  const encode = (request: Parameters<typeof encodeRequest>[0]): CodecResult<Uint8Array[]> =>
    encodeRequest(request, { sliceSize });

  const expectIds = (frame: HuaweiFrame, serviceId: number, commandId: number): boolean =>
    frame.serviceId === serviceId && frame.commandId === commandId;

  const concat = (...parts: Uint8Array[]): Uint8Array => {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  };

  const utf8 = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "utf8"));

  const unexpected = (frame: HuaweiFrame): CodecResult<never> =>
    stop("auth-state", "a frame arrived that this state does not expect",
      `service 0x${frame.serviceId.toString(16)} command 0x${frame.commandId.toString(16)} in ${state}`);

  /**
   * Build one HiChain step and hand the caller its bytes. `messageId` is only passed on the bind
   * operation's step 4, where upstream sends the step number it captured before incrementing it.
   */
  const emitStep = (
    step: 1 | 2 | 3 | 4,
    extra: Partial<{ randSelf: Uint8Array; seed: Uint8Array; selfToken: Uint8Array; nonce: Uint8Array; encData: Uint8Array; encResult: Uint8Array; messageId: number }>,
  ): CodecResult<AuthOutput> => {
    const built = hiChainRequest({ operationCode: operation, requestId, androidId, step, ...extra });
    if (!built.ok) return stop("bad-argument", "could not build a HiChain step", `step ${step}`);
    const encoded = encode(built.value);
    if (!encoded.ok) return stop("bad-argument", "could not encode a HiChain step", `step ${step}`);
    hiChainStep = step;
    return advance(operationState(step), encoded.value);
  };

  /**
   * Start the HiChain operation: bind directly, or auth first when the caller asked for the pin-code
   * path. Upstream picks the operation in the constructor (GetHiChainRequest.java:60-71) and, on the
   * auth path, the pin code is fetched *before* the HiChain request is created
   * (HuaweiSupportProvider.initializeDeviceHiChainMode).
   */
  function beginHiChain(): CodecResult<AuthOutput> {
    if (mode === "bind") {
      if (key.length === 0) return stop("bad-key", "the bind operation needs an auth key and none was supplied");
      operation = 0x02;
      requestId = nextRequestId();
      randSelf = random(16);
      seed = random(32);
      return emitStep(1, { randSelf, seed });
    }
    if (!pinCode) {
      const encoded = encode(pincodeRequest());
      if (!encoded.ok) return stop("bad-argument", "could not encode the pin code request");
      return advance("pincode", encoded.value);
    }
    operation = 0x01;
    requestId = nextRequestId();
    randSelf = random(16);
    seed = random(32);
    return emitStep(1, { randSelf, seed });
  }

  /**
   * Steps 3 and 4 share the session key derivation — HKDF(psk, randSelf‖randPeer, "hichain_iso_session_key")
   * (GetHiChainRequest.java:126-132). The bind operation never sends step 3: upstream increments the
   * step and falls through to StepFour with the pre-increment message id (:143-155).
   */
  function sendStepThreeOrFour(): CodecResult<AuthOutput> {
    const derived = hkdfSha256(psk!, concat(randSelf!, randPeer!), utf8("hichain_iso_session_key"), 32);
    if (!derived.ok) return stop("crypto-failed", "could not derive the HiChain session key");
    sessionKey = derived.value;
    if (operation === 0x01) {
      const nonce = random(12);
      challenge = random(16);
      const encData = aesGcmEncryptNoPad(challenge, sessionKey, nonce, utf8("hichain_iso_exchange"));
      if (!encData.ok) return stop("crypto-failed", "could not encrypt the HiChain challenge");
      return emitStep(3, { nonce, encData: encData.value });
    }
    const nonce = random(12);
    const encResult = aesGcmEncryptNoPad(Uint8Array.of(0, 0, 0, 0), sessionKey, nonce, utf8("hichain_iso_result"));
    if (!encResult.ok) return stop("crypto-failed", "could not encrypt the HiChain result");
    return emitStep(4, { nonce, encResult: encResult.value, messageId: 3 });
  }

  const operationState = (step: number): AuthState =>
    `hichain-${operation === 0x01 ? "auth" : "bind"}-step${step}` as AuthState;

  const timeoutFor = (): number => {
    if (state === "done" || state === "failed") return 0;
    if (state === "hichain-auth-step1" || state === "hichain-bind-step1") {
      return operation === 0x01 ? FIRST_HI_CHAIN_TIMEOUT_MS : STEP_TIMEOUT_MS;
    }
    if (state === "pincode") return FIRST_HI_CHAIN_TIMEOUT_MS;
    return STEP_TIMEOUT_MS;
  };

  function start(): CodecResult<AuthOutput> {
    if (state !== "start") return stop("auth-state", "the auth flow has already started", state);
    const encoded = encode(linkParamsRequest());
    if (!encoded.ok) return stop("bad-argument", "could not encode the link params request");
    return advance("link-params", encoded.value);
  }

  return {
    get state() {
      return state;
    },
    get timeoutMs() {
      return timeoutFor();
    },
    get finalKey() {
      return finalKey;
    },
    get finished() {
      return state === "done" || state === "failed";
    },
    start,
    onFrame,
    destroy() {
      zeroBytes(key);
      if (pinCode) zeroBytes(pinCode);
      if (finalKey) zeroBytes(finalKey);
      pinCode = null;
      finalKey = null;
      wipeHandshake();
    },
  };

  function onFrame(frame: HuaweiFrame): CodecResult<AuthOutput> {
    const tlv = frame.tlv;
    if (!tlv) return stop("auth-truncated", "the frame carries no TLV", state);
    if (state === "done" || state === "failed") {
      return stop("auth-state", "the auth flow has already finished", state);
    }
    if (state === "link-params") {
      if (!expectIds(frame, DEVICE_CONFIG.serviceId, DEVICE_CONFIG.linkParams)) return unexpected(frame);
      const parsed = parseLinkParams(tlv);
      if (!parsed.ok) return stop(parsed.error.code as HuaweiAuthErrorCode, parsed.error.message, parsed.error.detail);
      params = parsed.value;
      if (params.sliceSize > 0) sliceSize = params.sliceSize;
      authMode = params.deviceSupportType === 0x04 ? 0x04 : 0x02;
      crypto = createHuaweiCrypto({
        authVersion: params.authVersion,
        deviceSupportType: params.deviceSupportType,
        authAlgo: params.authAlgo,
        authMode,
      });
      if (authPathFor(params.deviceSupportType) !== "hichain") {
        return stop("auth-unsupported",
          "this watch does not use HiChain (deviceSupportType 0x02 is HiChainLite, others have no HiChain at all), and Phase 3 implements HiChain only",
          `deviceSupportType ${params.deviceSupportType}`);
      }
      const encoded = encode(deviceStatusRequest());
      if (!encoded.ok) return stop("bad-argument", "could not encode the device status request");
      return advance("device-status", encoded.value);
    }
    if (state === "device-status") {
      if (!expectIds(frame, DEVICE_CONFIG.serviceId, DEVICE_CONFIG.deviceStatus)) return unexpected(frame);
      const status = parseDeviceStatus(tlv);
      if (!status.ok) return stop(status.error.code as HuaweiAuthErrorCode, status.error.message, status.error.detail);
      // 0xFF is -1 as a java byte; -1, 0 and 1 all mean "authenticate now" (HuaweiSupportProvider:451-465).
      if (![0xff, 0x00, 0x01].includes(status.value)) {
        return stop("auth-refused", "the watch reports a device status that skips authentication", `status ${status.value}`);
      }
      const model = validatePhoneModel(phoneModel);
      if (!model.ok) return stop("bad-argument", model.error.message, model.error.detail ?? undefined);
      const encoded = encode(securityNegotiationRequest({
        authMode,
        deviceUuid: androidId,
        phoneModel,
        encryptMethod: params!.encryptMethod,
      }));
      if (!encoded.ok) return stop("bad-argument", "could not encode the security negotiation request");
      return advance("security-negotiation", encoded.value);
    }
    if (state === "security-negotiation") {
      if (!expectIds(frame, DEVICE_CONFIG.serviceId, DEVICE_CONFIG.securityNegotiation)) return unexpected(frame);
      const authType = parseSecurityNegotiation(tlv);
      if (!authType.ok) return stop(authType.error.code as HuaweiAuthErrorCode, authType.error.message, authType.error.detail);
      // isHiChain / isHiChain3 / isHiChainLite decide this (HuaweiSupportProvider.java:474-495).
      if (authType.value !== 0x0186a0 && !isHiChain3(authType.value)) {
        return stop("auth-unsupported",
          "this watch negotiated HiChainLite (the legacy digest auth in service 0x01 command 0x13), which Phase 3 does not implement",
          `authType 0x${(authType.value >>> 0).toString(16)}`);
      }
      return beginHiChain();
    }
    if (state === "pincode") {
      if (!expectIds(frame, DEVICE_CONFIG.serviceId, DEVICE_CONFIG.pinCode)) return unexpected(frame);
      if (!crypto) return stop("auth-state", "the pin code arrived before the link parameters were read", state);
      const pin = parsePincodeResponse(tlv, crypto, params!.encryptMethod);
      if (!pin.ok) return stop(pin.error.code as HuaweiAuthErrorCode, pin.error.message, pin.error.detail);
      pinCode = pin.value;
      operation = 0x01;
      requestId = nextRequestId();
      randSelf = random(16);
      seed = random(32);
      return emitStep(1, { randSelf, seed });
    }
    if (!expectIds(frame, DEVICE_CONFIG.serviceId, DEVICE_CONFIG.hiChain)) return unexpected(frame);
    return handleHiChainStep(tlv);
  }

  /**
   * The step machine, mirroring GetHiChainRequest.processResponse (:168-262). Every check upstream
   * makes is made here, in the same order, and every check that upstream turns into an exception
   * becomes a typed stop with the machine left in "failed" — there is no path back into the flow and
   * no second attempt at anything. Nothing in this function is retried, and nothing is logged.
   */
  function handleHiChainStep(tlv: NonNullable<HuaweiFrame["tlv"]>): CodecResult<AuthOutput> {
    const parsed = parseHiChainResponse(tlv);
    if (!parsed.ok) return stop(parsed.error.code as HuaweiAuthErrorCode, parsed.error.message, parsed.error.detail);
    const response = parsed.value;
    if (response.errorCode !== 0) {
      return stop("auth-refused", "the watch refused this auth step", `errorCode ${response.errorCode} in ${state}`);
    }
    if (response.step !== hiChainStep) {
      return stop("auth-state", "the watch's step does not match the request: a replayed, out-of-order or stale reply",
        `waiting for ${hiChainStep}, got ${response.step}`);
    }
    if (hiChainStep === 1) {
      if (!response.step1) return stop("auth-truncated", "the step 1 reply carries no step-1 payload");
      // A machine that was destroyed (or a replayed reply) has no seed left: that is a typed stop,
      // never a TypeError from handing null to a primitive.
      if (!seed) return stop("auth-state", "a step 1 reply arrived with no handshake in progress", state);
      randPeer = response.step1.isoSalt;
      authIdPeer = response.step1.peerAuthId;
      if (operation === 0x01) {
        if (!pinCode) return stop("auth-pincode-missing", "the auth operation needs the pin code the watch displays");
        // Upstream digests the *hex string* of the pin code, not the pin code itself (:207-209).
        const pinKey = sha256(utf8(hexdumpUpper(pinCode)));
        psk = hmacSha256(pinKey, seed!);
        zeroBytes(pinKey);
      } else {
        psk = hmacSha256(key, seed!);
      }
      zeroBytes(seed!);
      seed = null;
      // Verified order (upstream :214-220): randPeer ‖ randSelf ‖ authIdSelf ‖ authIdPeer …
      const checked = hmacSha256(psk, concat(randPeer, randSelf!, androidId, authIdPeer));
      if (!bytesEqualConstantTime(checked, response.step1.token)) {
        return stop("auth-token-mismatch",
          "the watch's token does not match: the auth key is wrong, or this watch was paired with a different one");
      }
      // … while the token sent back is the mirror image of it (:115-123). Both orders are upstream's.
      const selfToken = hmacSha256(psk, concat(randSelf!, randPeer, authIdPeer, androidId));
      return emitStep(2, { selfToken });
    }
    if (hiChainStep === 2) {
      if (!response.step2) return stop("auth-truncated", "the step 2 reply carries no step-2 payload");
      if (!psk) return stop("auth-state", "a step 2 reply arrived with no handshake in progress", state);
      const expectedMac = hmacSha256(psk!, Uint8Array.of(0, 0, 0, 0));
      if (!bytesEqualConstantTime(expectedMac, response.step2.returnCodeMac)) {
        return stop("auth-mac-mismatch", "the watch's return-code MAC does not match");
      }
      return sendStepThreeOrFour();
    }
    if (hiChainStep === 3) {
      if (!response.step3) return stop("auth-truncated", "the step 3 reply carries no step-3 payload");
      if (!sessionKey || !challenge) {
        return stop("auth-state", "a step 3 reply arrived without the session key", state);
      }
      const decrypted = aesGcmDecryptNoPad(response.step3.encAuthToken, sessionKey, response.step3.nonce, challenge);
      if (!decrypted.ok) return stop("crypto-failed", "could not decrypt the auth token (the session key does not match)");
      // setSecretKey(authToken) (:238-244): the token becomes the key of the bind operation.
      zeroBytes(key);
      key = decrypted.value;
      const nonce = random(12);
      const encResult = aesGcmEncryptNoPad(Uint8Array.of(0, 0, 0, 0), sessionKey, nonce, utf8("hichain_iso_result"));
      if (!encResult.ok) return stop("crypto-failed", "could not encrypt the HiChain result");
      return emitStep(4, { nonce, encResult: encResult.value });
    }
    if (operation === 0x01) {
      // "Finished auth operation, go to bind" (:181-185): a *new* request, operation 0x02, key = auth token.
      wipeHandshake();
      randSelf = null;
      randPeer = null;
      authIdPeer = null;
      operation = 0x02;
      requestId = nextRequestId();
      randSelf = random(16);
      seed = random(32);
      return emitStep(1, { randSelf, seed });
    }
    // "Finished bind operation" (:186-197): the key this tool came for.
    if (!sessionKey || !randSelf || !randPeer) {
      return stop("auth-state", "the bind reply arrived with no handshake in progress", state);
    }
    const derived = hkdfSha256(sessionKey!, concat(randSelf!, randPeer!), utf8("hichain_return_key"), 32);
    if (!derived.ok) return stop("crypto-failed", "could not derive the final key");
    finalKey = derived.value;
    wipeHandshake();
    zeroBytes(key);
    return advance("done", []);
  }
}