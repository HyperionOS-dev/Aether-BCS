// BCS helper — Phase 2 (Huawei packet codec): the requests this phase is allowed to build. Pure
// code: no socket, no I/O, no key material, nothing sent to the watch.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7
// (GitHub mirror, frozen 2024-12-22):
//   devices/huawei/packets/DeviceConfig.java
//     LinkParams.Request             lines 53-70   (isEncrypted=false, isSliced=false)
//     SupportedServices.Request      lines 137-146
//     SupportedCommands.Request      lines 240-282 (0x81 wrapper, size guard)
//     ProductInfo.Request            lines 424-446
//     Auth.Request                   lines 609-627 (isEncrypted=false)
//     BatteryLevel.Request           lines 668-678
//   devices/huawei/packets/AccountRelated.java
//     SendAccountToDevice.Request          lines 28-43
//     SendExtendedAccountToDevice.Request  lines 55-74
//
// SCOPE — why this list is short, and why nothing else is here:
//   * Only handshake, auth-challenge and read requests are built. Alarms, notifications, contacts,
//     music, find-phone, file upload and OTA are write-type commands and are deliberately absent.
//   * DeviceConfig.Bond.Request (:486-506) and BondParams.Request (:530-551) are auth-related but
//     carry key material (tags 0x06/0x07 are a bonding key and its IV). A codec phase that holds no
//     key does not build them; that belongs with the Phase 3 crypto and its key handling.
//   * The auth challenge encodes challenge and nonce bytes supplied by the caller. Nothing here
//     derives, reads, stores or logs a key, and an account string is only ever encoded.
// isAllowedRequest() is the machine-checkable form of this paragraph, and
// test/huaweiRequests.test.ts asserts that every builder below is on the list.

import {
  ACCOUNT_RELATED,
  DEFAULT_SLICE_SIZE,
  DEVICE_CONFIG,
  KNOWN_SUPPORTED_SERVICES,
} from "./constants.ts";
import { codecFail, codecOk, type CodecResult } from "./errors.ts";
import { HuaweiTlv } from "./tlv.ts";
import { encodeFrame } from "./frame.ts";

/** A packet this phase can build: the ids, its TLVs, and upstream's two per-packet flags. */
export interface HuaweiRequest {
  serviceId: number;
  commandId: number;
  tlv: HuaweiTlv;
  /** Upstream's flag: "encrypt this once a key exists". True unless the source says otherwise. */
  isEncrypted: boolean;
  /** Upstream's flag: "this may be sliced". True unless the source says otherwise. */
  isSliced: boolean;
}

/** The only (service, command) pairs this phase builds. Mirrors the builders below one to one. */
export const ALLOWED_REQUEST_IDS: readonly (readonly [number, number])[] = [
  [DEVICE_CONFIG.serviceId, DEVICE_CONFIG.linkParams],
  [DEVICE_CONFIG.serviceId, DEVICE_CONFIG.supportedServices],
  [DEVICE_CONFIG.serviceId, DEVICE_CONFIG.supportedCommands],
  [DEVICE_CONFIG.serviceId, DEVICE_CONFIG.productInfo],
  [DEVICE_CONFIG.serviceId, DEVICE_CONFIG.auth],
  [DEVICE_CONFIG.serviceId, DEVICE_CONFIG.batteryLevel],
  [ACCOUNT_RELATED.serviceId, ACCOUNT_RELATED.sendAccountToDevice],
  [ACCOUNT_RELATED.serviceId, ACCOUNT_RELATED.sendExtendedAccountToDevice],
];

export function isAllowedRequest(serviceId: number, commandId: number): boolean {
  return ALLOWED_REQUEST_IDS.some(([s, c]) => s === serviceId && c === commandId);
}

/** Serialise one of the requests above. `sliceSize` comes from the watch's link params. */
export function encodeRequest(
  request: HuaweiRequest,
  options: { sliceSize?: number; transactionsCrypted?: boolean } = {},
): CodecResult<Uint8Array[]> {
  return encodeFrame({
    serviceId: request.serviceId,
    commandId: request.commandId,
    tlv: request.tlv,
    sliced: request.isSliced,
    sliceSize: options.sliceSize ?? DEFAULT_SLICE_SIZE,
    isEncrypted: request.isEncrypted,
    transactionsCrypted: options.transactionsCrypted,
  });
}

/**
 * LinkParams.Request (DeviceConfig.java:53-70): the first request of a session, sent before any
 * key exists, so upstream marks it unencrypted *and* unsliced.
 */
export function linkParamsRequest(options: { deviceTypeAw?: boolean } = {}): HuaweiRequest {
  const tlv = new HuaweiTlv().putEmpty(0x01).putEmpty(0x02).putEmpty(0x03).putEmpty(0x04);
  if (options.deviceTypeAw === true) tlv.putEmpty(0x06);
  return {
    serviceId: DEVICE_CONFIG.serviceId,
    commandId: DEVICE_CONFIG.linkParams,
    tlv,
    isEncrypted: false,
    isSliced: false,
  };
}

/** SupportedServices.Request (DeviceConfig.java:137-146): the caller's list, default the known one. */
export function supportedServicesRequest(
  allSupportedServices: Uint8Array = KNOWN_SUPPORTED_SERVICES,
): HuaweiRequest {
  return {
    serviceId: DEVICE_CONFIG.serviceId,
    commandId: DEVICE_CONFIG.supportedServices,
    tlv: new HuaweiTlv().putBytes(0x01, allSupportedServices),
    isEncrypted: true,
    isSliced: true,
  };
}

export interface CommandsForService {
  service: number;
  commands: Uint8Array;
}

/**
 * SupportedCommands.Request (DeviceConfig.java:240-282): repeated (0x02 service, 0x03 commands)
 * pairs, wrapped in the 0x81 tag by the upstream serialize() override (:38-44), and refused when a
 * pair would not fit the alignment budget upstream computes at :258-262.
 */
export function supportedCommandsRequest(
  entries: readonly CommandsForService[],
  options: { sliceSize?: number } = {},
): CodecResult<HuaweiRequest> {
  const sliceSize = options.sliceSize ?? DEFAULT_SLICE_SIZE;
  const maxSize = sliceSize - 32;
  const aligned = maxSize - (maxSize % 16) - 4;
  const inner = new HuaweiTlv();
  for (const entry of entries) {
    if (inner.length() + entry.commands.length + 5 > aligned) {
      return codecFail(
        "bad-argument",
        `commands for service 0x${(entry.service & 0xff).toString(16)} do not fit the ${aligned}-byte budget`,
      );
    }
    inner.putByte(0x02, entry.service).putBytes(0x03, entry.commands);
  }
  return codecOk({
    serviceId: DEVICE_CONFIG.serviceId,
    commandId: DEVICE_CONFIG.supportedCommands,
    tlv: new HuaweiTlv().putTlv(0x81, inner),
    isEncrypted: true,
    isSliced: true,
  });
}

/** ProductInfo.Request (DeviceConfig.java:424-446): empty tags, listed per device type. */
export function productInfoRequest(options: { deviceTypeAw?: boolean } = {}): HuaweiRequest {
  const tags =
    options.deviceTypeAw === true
      ? [0x01, 0x02, 0x03, 0x07, 0x09, 0x0a, 0x0c, 0x11]
      : [
          0x01, 0x02, 0x07, 0x09, 0x0a, 0x11, 0x12, 0x16, 0x1a, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
          0x22, 0x23,
        ];
  const tlv = new HuaweiTlv();
  for (const tag of tags) tlv.putEmpty(tag);
  return {
    serviceId: DEVICE_CONFIG.serviceId,
    commandId: DEVICE_CONFIG.productInfo,
    tlv,
    isEncrypted: true,
    isSliced: true,
  };
}

/**
 * Auth.Request (DeviceConfig.java:609-627): the challenge and nonce the caller supplies, plus the
 * algorithm byte only in auth mode 2. Unencrypted, as upstream marks it. Phase 3 owns the crypto
 * that produces those two inputs; this builder only frames them.
 */
export function authChallengeRequest(input: {
  challenge: Uint8Array;
  nonce: Uint8Array;
  authMode?: number;
  authAlgo?: number;
}): HuaweiRequest {
  const tlv = new HuaweiTlv().putBytes(0x01, input.challenge).putBytes(0x02, input.nonce);
  if ((input.authMode ?? 0) === 0x02) tlv.putByte(0x03, input.authAlgo ?? 0);
  return {
    serviceId: DEVICE_CONFIG.serviceId,
    commandId: DEVICE_CONFIG.auth,
    tlv,
    isEncrypted: false,
    isSliced: true,
  };
}

/** BatteryLevel.Request (DeviceConfig.java:668-678): one empty tag. */
export function batteryLevelRequest(): HuaweiRequest {
  return {
    serviceId: DEVICE_CONFIG.serviceId,
    commandId: DEVICE_CONFIG.batteryLevel,
    tlv: new HuaweiTlv().putEmpty(0x01),
    isEncrypted: true,
    isSliced: true,
  };
}

/**
 * AccountRelated.SendAccountToDevice.Request (AccountRelated.java:28-43). The account string is
 * supplied by the caller and only ever encoded here: this module never reads a saved account, never
 * prints one, and stores nothing.
 */
export function sendAccountRequest(account: string): HuaweiRequest {
  const tlv = new HuaweiTlv();
  if (account.length > 0) tlv.putString(0x01, account);
  else tlv.putEmpty(0x01);
  return {
    serviceId: ACCOUNT_RELATED.serviceId,
    commandId: ACCOUNT_RELATED.sendAccountToDevice,
    tlv,
    isEncrypted: true,
    isSliced: true,
  };
}

/** AccountRelated.SendExtendedAccountToDevice.Request (AccountRelated.java:55-74). */
export function sendExtendedAccountRequest(input: {
  account: string;
  accountPairingOptimization?: boolean;
}): HuaweiRequest {
  const tlv = new HuaweiTlv();
  if (input.account.length > 0) tlv.putString(0x01, input.account);
  else tlv.putByte(0x01, 0x00);
  if (input.accountPairingOptimization === true) tlv.putByte(0x03, 0x01);
  return {
    serviceId: ACCOUNT_RELATED.serviceId,
    commandId: ACCOUNT_RELATED.sendExtendedAccountToDevice,
    tlv,
    isEncrypted: true,
    isSliced: true,
  };
}
