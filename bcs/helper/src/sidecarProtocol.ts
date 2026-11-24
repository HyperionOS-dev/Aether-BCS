// BCS helper — the pure half of the TypeScript <-> Python pipe. The sidecar limits writes to
// allowlisted authentication frames.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// One JSON object per line in both directions. Keeping encode/parse/hex here — with no streams,
// no timers and no child process — is what makes the pipe testable in microseconds: the tests
// feed it lines the Python side really produces, including the malformed ones.
//
// `hex` is how bytes travel over the pipe. It is transport, not logging: nothing in this file
// prints anything, and the transport logs only the byte count and the time.

import { bcsError, type BcsError, type BcsErrorCode } from "./types.ts";

export interface SidecarResponse {
  id: number;
  ok: boolean;
  error?: string;
  code?: string;
  detail?: string;
  /** Already masked by the sidecar; masked again before it is logged. */
  address?: string;
  errno?: number | null;
  version?: string;
  capabilities?: string[];
  /** The SDP answer to `resolve_channel`: which tool answered, and what the channel it named proves. */
  method?: string;
  channel?: number;
  matched_uuid?: boolean;
  matched_serial?: boolean;
}

export interface SidecarDataEvent {
  event: "data";
  bytes: number;
  at: string;
  channel?: number;
  /** Present only when the sidecar was started with --emit-hex. */
  hex?: string;
}

export interface SidecarClosedEvent {
  event: "closed";
  at: string;
  reason?: string;
}

export interface SidecarErrorEvent {
  event: "error";
  error: string;
  code?: string;
  errno?: number | null;
}

export type SidecarMessage = SidecarResponse | SidecarDataEvent | SidecarClosedEvent | SidecarErrorEvent;

/** A response line longer than this is treated as a broken pipe, not as data. */
export const MAX_LINE_BYTES = 1_048_576;

const ERROR_CODES: BcsErrorCode[] = [
  "no-config",
  "bad-config",
  "not-open",
  "already-open",
  "timeout",
  "busy",
  "refused",
  "unreachable",
  "permission",
  "reset",
  "unsupported",
  "write-not-allowed",
  "write-refused",
  "missing-channel",
  "sidecar-exited",
  "sdp-unavailable",
  "sdp-no-channel",
  "sdp-unconfirmed",
  "sdp-disagreement",
  "channel-unverified",
  "bad-uuid",
  "not-bonded",
  "security-refused",
  "protocol",
  "unknown",
];

export function isKnownErrorCode(code: unknown): code is BcsErrorCode {
  return typeof code === "string" && (ERROR_CODES as string[]).includes(code);
}

const SAFE_ERROR_MESSAGES: Record<BcsErrorCode, string> = {
  "no-config": "no saved watch address",
  "bad-config": "saved watch configuration is invalid",
  "not-open": "the link is not open",
  "already-open": "the link is already open",
  timeout: "the sidecar request timed out",
  busy: "the link is busy",
  refused: "the link was refused",
  unreachable: "the link is unreachable",
  permission: "permission was denied",
  reset: "the link was reset",
  unsupported: "the operation is unsupported",
  "write-not-allowed": "the write is not allowed",
  "write-refused": "the sidecar refused this frame",
  "missing-channel": "the RFCOMM channel is missing",
  "sidecar-exited": "the sidecar exited",
  // The SDP channel gate. These sentences are written here, not copied from the sidecar line, and
  // each one says the same thing the design does: the channel comes from SDP or there is no link.
  "sdp-unavailable": "SDP could not be read, so the watch's RFCOMM channel cannot be resolved",
  "sdp-no-channel": "SDP did not name the serial channel, and a channel found by probing is never used instead",
  "sdp-unconfirmed": "SDP named a channel, but no Huawei or serial-port record proves it belongs to the watch",
  "sdp-disagreement": "SDP disagrees with the saved channel, so nothing was connected",
  "channel-unverified": "that channel was not resolved through SDP in this session",
  "bad-uuid": "only the Huawei SDP service UUID can be resolved",
  // Phase 3G link options. Both sentences say what to do next, and neither copies a sidecar line.
  "not-bonded": "the watch is not paired with this computer, and this run asked for a paired watch",
  "security-refused":
    "the Bluetooth stack refused the secure link; the watch is probably not bonded to this computer",
  protocol: "the sidecar reported a protocol error",
  unknown: "the sidecar reported an unknown error",
};

/** Never copy text from a sidecar line into a thrown error or log. */
export function safeSidecarErrorMessage(code: unknown): string {
  return SAFE_ERROR_MESSAGES[isKnownErrorCode(code) ? code : "unknown"];
}

/** One command line, newline terminated. The caller never passes an address: the sidecar owns it. */
export function encodeCommand(command: Record<string, unknown>): string {
  return `${JSON.stringify(command)}\n`;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * Parse one line from the sidecar. Returns null for anything that is not a message this
 * helper understands — a blank line, a Python traceback that escaped to stdout, a truncated
 * write. Callers decide whether that is fatal; the probe never is.
 */
export function parseLine(line: string): SidecarMessage | null {
  const text = line.trim();
  if (!text) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  const record = asRecord(parsed);
  if (!record) return null;
  if (typeof record.id === "number") {
    return {
      id: record.id,
      ok: record.ok === true,
      error: typeof record.error === "string" ? record.error : undefined,
      code: typeof record.code === "string" ? record.code : undefined,
      detail: typeof record.detail === "string" ? record.detail : undefined,
      address: typeof record.address === "string" ? record.address : undefined,
      errno: typeof record.errno === "number" ? record.errno : null,
      version: typeof record.version === "string" ? record.version : undefined,
      capabilities: Array.isArray(record.capabilities)
        ? record.capabilities.filter((capability): capability is string => typeof capability === "string")
        : undefined,
      method: typeof record.method === "string" ? record.method : undefined,
      channel: typeof record.channel === "number" ? record.channel : undefined,
      matched_uuid: record.matched_uuid === true,
      matched_serial: record.matched_serial === true,
    };
  }
  if (record.event === "data" && typeof record.bytes === "number" && typeof record.at === "string") {
    return {
      event: "data",
      bytes: record.bytes,
      at: record.at,
      channel: typeof record.channel === "number" ? record.channel : undefined,
      hex: typeof record.hex === "string" ? record.hex : undefined,
    };
  }
  if (record.event === "closed") {
    return {
      event: "closed",
      at: typeof record.at === "string" ? record.at : "",
      reason: typeof record.reason === "string" ? record.reason : undefined,
    };
  }
  if (record.event === "error" && typeof record.error === "string") {
    return {
      event: "error",
      error: record.error,
      code: typeof record.code === "string" ? record.code : undefined,
      errno: typeof record.errno === "number" ? record.errno : null,
    };
  }
  return null;
}

/** Hex from the sidecar to bytes. A malformed hex field is a broken pipe, not silent loss. */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9A-Fa-f]*$/.test(hex)) {
    throw bcsError("protocol", "sidecar sent a data event with unusable hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Turn a failed response into the error the transport throws. */
export function errorFromResponse(response: SidecarResponse): BcsError {
  const code = isKnownErrorCode(response.code) ? response.code : "unknown";
  return bcsError(code, safeSidecarErrorMessage(code), typeof response.errno === "number" ? response.errno : null);
}

/** Keep a data event inside the rule that only counts and time are ever reported. */
export function dataCountOf(event: SidecarDataEvent): { bytes: number; at: string; channel: number } {
  const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(event.at)
    ? event.at
    : "unknown time";
  return { bytes: event.bytes, at: timestamp, channel: event.channel ?? 0 };
}