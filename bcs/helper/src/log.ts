// BCS helper — Phase 1 (link only): the only logger the link layer may use. Phase 1 writes
// no bytes to the watch.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Two privacy rules are enforced here rather than trusted to callers:
//   1. every message is masked, so a Bluetooth address cannot reach a log line;
//   2. bytes received from the watch are reported as "N bytes at T" only — a long hex blob in
//      any message is redacted before it is printed, so accidentally logging a payload is not
//      possible from this logger.
// mask.ts stays a pure formatting module; this file is where the rules are applied.

import { maskMacText } from "./mask.ts";
import type { BcsDataCountEvent, BcsLogger } from "./types.ts";

/** Hex runs this long are treated as payload, never as an identifier, and are redacted. */
const LONG_HEX = /\b[0-9A-Fa-f]{32,}\b/g;

export function scrubPayloads(text: unknown): string {
  return maskMacText(text).replace(LONG_HEX, "[bytes redacted]");
}

export interface CreateLoggerOptions {
  /** Label in front of each line, e.g. "bcs-sidecar". */
  prefix?: string;
  /** Where lines go. Tests pass a collector; the sidecar transport defaults to stdout. */
  sink?: (line: string) => void;
}

export function createLogger(options: CreateLoggerOptions = {}): BcsLogger {
  const prefix = options.prefix ?? "bcs";
  const sink = options.sink ?? ((line: string) => console.log(line));
  const emit = (level: "info" | "warn" | "error", message: unknown) => {
    sink(`${level} ${prefix}: ${scrubPayloads(message)}`);
  };
  return {
    info: (message: string) => emit("info", message),
    warn: (message: string) => emit("warn", message),
    error: (message: string) => emit("error", message),
    // The one way payload time may be reported: count, channel and timestamp, never content.
    bytesReceived: ({ bytes, at, channel }: BcsDataCountEvent) => {
      emit("info", `received ${bytes} bytes on channel ${channel} at ${at}`);
    },
  };
}