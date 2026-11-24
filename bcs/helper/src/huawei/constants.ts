// BCS helper — Phase 2 (Huawei packet codec): the protocol constants this phase actually uses.
// Pure data: no socket, no I/O, no key material, nothing sent to the watch.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7 (GitHub mirror,
// frozen 2024-12-22): HuaweiConstants.java lines 28-45, packets/DeviceConfig.java lines 48-135,
// 182, 422, 607 and 668, and packets/AccountRelated.java lines 23, 26 and 53. Every value below
// names its own upstream file and line; nothing here is inferred or remembered, and a value that
// was not in the source that was read is not in this file.

/**
 * The SDP service UUID the watch advertises for its classic-Bluetooth serial service
 * (HuaweiConstants.java:28, `UUID_SERVICE_HUAWEI_SDP`).
 *
 * This is how the RFCOMM channel is found: upstream never connects to a channel number.
 * `HuaweiBRSupport.java:51` registers this UUID and `BtClassicIoThread.java:150-159` asks the stack
 * for a socket to that service record. The helper resolves the channel through SDP for this same
 * UUID and refuses to connect to anything else, so a channel found by probing is never used.
 */
export const HUAWEI_SDP_UUID = "82ff3820-8411-400c-b85a-55bdb32cf060";

/** Frame magic: 0x5A (HuaweiConstants.java:33, `HUAWEI_MAGIC`). */
export const HUAWEI_MAGIC = 0x5a;
/** Protocol version modern devices report: 0x02 (HuaweiConstants.java:35). */
export const PROTOCOL_VERSION = 0x02;
/** Tag carrying a result code: 127 (HuaweiConstants.java:37, `TAG_RESULT`). */
export const TAG_RESULT = 0x7f;
/** Success result value (HuaweiConstants.java:38, `RESULT_SUCCESS`). */
export const RESULT_SUCCESS = Uint8Array.of(0x00, 0x01, 0x86, 0xa0);
/** The same success value as an int: 0x186A0 = 100000 (HuaweiConstants.java:39). */
export const RESULT_SUCCESS_INT = 0x186a0;

/**
 * The three tags of the encrypted-transaction envelope (HuaweiConstants.java:41-45):
 * 0x7C flags encryption, 0x7D is the init vector, 0x7E is the ciphertext. Phase 2 recognises the
 * envelope but never decrypts it: the key is Phase 3, and this phase holds no key.
 */
export const CRYPTO_TAGS = {
  encryption: 0x7c,
  initVector: 0x7d,
  cipherText: 0x7e,
} as const;

/**
 * Service 0x01: the handshake, the capability reads and the auth challenge
 * (DeviceConfig.java:48, then the `id` of each inner class: LinkParams :51, SupportedServices
 * :124, SupportedCommands :182, DateFormat :345, TimeRequest :386, ProductInfo :422,
 * BatteryLevel :668, BatteryLevel change :669, Auth :607, Bond :484, BondParams :528).
 */
export const DEVICE_CONFIG = {
  serviceId: 0x01,
  linkParams: 0x01,
  supportedServices: 0x02,
  supportedCommands: 0x03,
  dateFormat: 0x04,
  timeRequest: 0x05,
  productInfo: 0x07,
  batteryLevel: 0x08,
  batteryLevelChange: 0x27,
  auth: 0x13,
  deviceStatus: 0x16,
  bond: 0x0e,
  bondParams: 0x0f,
  hiChain: 0x28,
  pinCode: 0x2c,
  securityNegotiation: 0x33,
} as const;

/** Service 0x1A: the account handshake (AccountRelated.java:23, :26, :53). */
export const ACCOUNT_RELATED = {
  serviceId: 0x1a,
  sendAccountToDevice: 0x01,
  sendExtendedAccountToDevice: 0x05,
} as const;

/** Service 0x0B. Its command 0x01 is the "known encrypted packet" in Gadgetbridge's own test. */
export const FIND_PHONE = {
  serviceId: 0x0b,
  response: 0x01,
  stopRequest: 0x02,
} as const;

/** Services a modern Huawei device is asked about: DeviceConfig.java:129-135 (44 values). */
export const KNOWN_SUPPORTED_SERVICES = Uint8Array.from([
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
  0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
  0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1d, 0x20,
  0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2a, 0x2b, 0x2d, 0x2e,
  0x30, 0x32, 0x33, 0x34, 0x35,
]);

/**
 * Packets whose payload is not a TLV, listed in HuaweiPacket.java:408-417:
 * (0x0a, 0x05), (0x28, 0x06), (0x2c, 0x05), (0x1c, 0x05). Upstream's comment is "TODO: this
 * doesn't seem to be TLV" and it keeps the raw payload; this port does the same and sets
 * `tlv` to null so a caller cannot mistake garbage for tags.
 */
export const NON_TLV_PACKETS: readonly (readonly [number, number])[] = [
  [0x0a, 0x05],
  [0x28, 0x06],
  [0x2c, 0x05],
  [0x1c, 0x05],
];

/** Default slice size a device reports unless it says otherwise (HuaweiPacket.java:64). */
export const DEFAULT_SLICE_SIZE = 0xf4;
/** Default MTU (HuaweiPacket.java:66). */
export const DEFAULT_MTU = 0xffff;
/** Minimum frame: magic + a two-byte length (HuaweiPacket.java:246, `PACKET_MINIMAL_SIZE`). */
export const PACKET_MINIMAL_SIZE = 3;

export function isNonTlvPacket(serviceId: number, commandId: number): boolean {
  return NON_TLV_PACKETS.some(([s, c]) => s === serviceId && c === commandId);
}

