// BCS helper — the transport contract shared by the fake, sidecar client and later consumers.
// Real sidecar writes are limited to allowlisted authentication frames.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// This is the BcsTransport interface of docs/BCS_PHASE0.md §4, with one deliberate
// widening: `address` is optional. The Phase 0 interface required it, but a Phase 1 rule
// says the address comes from ~/.config/aether-bcs/watch.json and must not be passed around
// in arguments, so the sidecar ignores this field and reads the saved address itself. An
// optional field accepts every call the documented interface allows, so no caller written
// against the doc breaks. Reported to the user rather than changed silently.

/**
 * Where to connect. `address` is accepted for interface compatibility and ignored in Phase 1.
 *
 * Phase 3G adds two opt-in fields. Both default to today's behaviour, so a caller that does not
 * mention them builds exactly the command it built before.
 */
export interface BcsOpenTarget {
  address?: string;
  /** RFCOMM channel, 1-30. Required in Phase 1: channel discovery is a separate step. */
  channel?: number;
  /** Milliseconds allowed for one connect attempt. Defaults to the transport's own limit. */
  timeoutMs?: number;
  /**
   * Ask the stack for this BT_SECURITY level before connect(). `none` (the default) asks for
   * nothing at all, which is what every earlier phase did; `medium` means authenticated and
   * encrypted. This records what we asked for, never what the stack granted.
   */
  btSecurity?: BcsBtSecurity;
  /**
   * Refuse to connect unless the sidecar can see `Bonded: yes` for the watch. A precondition check
   * only: it never pairs a watch, and a state that cannot be verified is a refusal, not a pass.
   */
  requireBond?: boolean;
}

/** The four BT_SECURITY names the sidecar accepts. `none` means "ask the stack for nothing". */
export type BcsBtSecurity = "none" | "low" | "medium" | "high";

/**
 * The transport contract from docs/BCS_PHASE0.md §4. Everything above a transport (codec,
 * crypto, request layer) is written against this and never against a socket.
 */
export interface BcsTransport {
  open(target: BcsOpenTarget): Promise<void>;
  /** Phase 4 (dual channel, service 0x01 command 0x3C). Refused in Phase 1. */
  openAux(channel: number): Promise<void>;
  /** Sends a frame through the sidecar, which enforces the auth-only allowlist. */
  write(data: Uint8Array, channel?: number): Promise<void>;
  onData(cb: (data: Uint8Array, channel: number) => void): void;
  close(): Promise<void>;
}

/** Extra observability a real link needs and the fake offers too. */
export interface BcsObservableTransport {
  onClosed(cb: (info: BcsClosedEvent) => void): void;
  onError(cb: (err: BcsError) => void): void;
}

export interface BcsClosedEvent {
  at: string;
  reason: string;
}

/** What a transport tells its logger about arriving bytes: never the bytes themselves. */
export interface BcsDataCountEvent {
  bytes: number;
  at: string;
  channel: number;
}

export interface BcsLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
  /** Counts and a timestamp only. No payload ever reaches a log line. */
  bytesReceived(event: BcsDataCountEvent): void;
}

export type BcsErrorCode =
  | "no-config"
  | "bad-config"
  | "not-open"
  | "already-open"
  | "timeout"
  | "busy"
  | "refused"
  | "unreachable"
  | "permission"
  | "reset"
  | "missing-channel"
  | "unsupported"
  | "write-not-allowed"
  | "write-refused"
  | "sdp-unavailable"
  | "sdp-no-channel"
  | "sdp-unconfirmed"
  | "sdp-disagreement"
  | "channel-unverified"
  | "bad-uuid"
  | "sidecar-exited"
  | "not-bonded"
  | "security-refused"
  | "protocol"
  | "unknown";

/** An Error carrying a stable code, so callers switch on `code` rather than on English. */
export interface BcsError extends Error {
  code: BcsErrorCode;
  errno: number | null;
}

/** Errors are plain objects built here: no class fields, so any runtime can strip types. */
export function bcsError(code: BcsErrorCode, message: string, errno: number | null = null): BcsError {
  const err = new Error(message) as BcsError;
  err.code = code;
  err.errno = errno;
  return err;
}

export function isBcsError(value: unknown): value is BcsError {
  return value instanceof Error && typeof (value as BcsError).code === "string";
}