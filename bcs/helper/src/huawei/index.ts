// BCS helper — the barrel for `src/huawei`: Phase 2 (the packet codec) and Phase 3 (trust/auth).
// Pure code: no socket, no process, no timer, no I/O, no logging, nothing sent to the watch.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Read a frame, write a frame, read a TLV, write a TLV, reassemble a stream, the eight request
// builders of Phase 2, and from Phase 3 the crypto, the auth packets and the auth state machine.
// Everything here is ported from Gadgetbridge and each file says where from; `errors.ts`,
// `authErrors.ts` and this file are this project's own.

export {
  codecError,
  codecFail,
  codecOk,
  isHuaweiCodecError,
  type CodecResult,
  type HuaweiCodecError,
  type HuaweiCodecErrorCode,
} from "./errors.ts";

export { crc16, crc16Bytes, frameCrc16 } from "./crc16.ts";

export { MAX_VARINT_BYTES, encodeVarInt, readVarInt, varIntSize, type VarIntValue } from "./varint.ts";

export {
  HuaweiTlv,
  bytesToHex,
  readUnsignedBE,
  tlvEntriesEqual,
  tlvEntryEquals,
  type TlvEntry,
} from "./tlv.ts";

export {
  CRYPTO_TAGS,
  DEFAULT_MTU,
  DEFAULT_SLICE_SIZE,
  DEVICE_CONFIG,
  ACCOUNT_RELATED,
  FIND_PHONE,
  HUAWEI_MAGIC,
  KNOWN_SUPPORTED_SERVICES,
  NON_TLV_PACKETS,
  PACKET_MINIMAL_SIZE,
  PROTOCOL_VERSION,
  RESULT_SUCCESS,
  RESULT_SUCCESS_INT,
  TAG_RESULT,
  isNonTlvPacket,
} from "./constants.ts";

export {
  decodeOneFrame,
  encodeFrame,
  frameFromPayload,
  serializeSliced,
  serializeUnsliced,
  type EncodeFrameOptions,
  type FrameSlice,
  type FrameStep,
  type HuaweiFrame,
} from "./frame.ts";

export {
  createHuaweiStream,
  decodeFrames,
  type HuaweiStream,
  type HuaweiStreamOptions,
  type StreamStep,
} from "./stream.ts";

export {
  ALLOWED_REQUEST_IDS,
  authChallengeRequest,
  batteryLevelRequest,
  encodeRequest,
  isAllowedRequest,
  linkParamsRequest,
  productInfoRequest,
  sendAccountRequest,
  sendExtendedAccountRequest,
  supportedCommandsRequest,
  supportedServicesRequest,
  type CommandsForService,
  type HuaweiRequest,
} from "./requests.ts";

// --- Phase 3 (trust/auth): the crypto, the auth packets and the state machine -------------------
// Still pure code: no socket, no timer, no retry, no file, no logging. `createAuthMachine` returns
// the bytes a caller should send and nothing else; it never opens, reads, writes or closes anything.

export {
  DIGEST_SECRET_V1,
  DIGEST_SECRET_V2,
  DIGEST_SECRET_V3,
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
  hexToBytes,
  hexdumpUpper,
  hkdfSha256,
  hmacSha256,
  pbkdf2Sha256,
  sha256,
  zeroBytes,
  type HuaweiCrypto,
  type HuaweiCryptoContext,
} from "./crypto.ts";

export {
  authError,
  isHuaweiAuthError,
  type HuaweiAuthError,
  type HuaweiAuthErrorCode,
} from "./authErrors.ts";

export {
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
  type AuthPath,
  type HiChainOperation,
  type HiChainResponse,
  type HiChainStep1Data,
  type HiChainStep2Data,
  type HiChainStep3Data,
  type HiChainStep4Data,
  type HiChainStepInput,
  type LinkParamsInfo,
} from "./authPackets.ts";

// --- Phase 3E (account support): the Huawei account ID and its frame ---------------------------
// Still pure code, and deliberately incomplete in one place: an account frame must be encrypted with
// the transaction key upstream, so `encodeAccountFrame` refuses `transactionsCrypted: true` instead of
// producing a frame the watch would reject. See `account.ts`.

export {
  ACCOUNT_FRAME_PAIRS,
  ACCOUNT_ID_MAX_DIGITS,
  ACCOUNT_ID_MIN_DIGITS,
  accountFramePlan,
  encodeAccountFrame,
  isAccountId,
  tryParseAccountId,
  type AccountCommand,
  type AccountFramePlan,
} from "./account.ts";

export {
  createAuthMachine,
  type AuthMachine,
  type AuthMachineOptions,
  type AuthOutput,
  type AuthState,
} from "./authMachine.ts";
