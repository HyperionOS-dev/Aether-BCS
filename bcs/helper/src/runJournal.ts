// BCS helper — the run journal: which stage the flow reached, how many bytes and frames crossed the
// link, and the difference between "nothing came back" and "something came back that was not the
// frame this step needed".
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Why this is its own module: a live bind that fails has to answer one question before any other —
// did the watch stay silent, or did it answer and get ignored? Those are opposite diagnoses (a link
// or radio problem, versus a protocol or channel problem), and the first live bind could not tell
// them apart because only step names were reported. Tools/bcs_auth.mjs keeps one of these and puts
// its lines in the report of every run.
//
// It holds numbers and stage names only: no frame, no key, no address and no payload. Every line it
// renders goes through maskMacText(), so even a stage name that somehow carried an address could not
// print one.

import { maskMacText } from "./mask.ts";

/** The four counters a run keeps. Bytes and frames are separate on purpose (see `silence`). */
export interface RunCounts {
  /** Payload bytes the link delivered, as reported by the sidecar's data events. */
  readonly bytesReceived: number;
  /** Complete frames reassembled from those bytes. */
  readonly framesReceived: number;
  /** Payload bytes this helper wrote, as counted in the frames it asked the transport to send. */
  readonly bytesWritten: number;
  readonly framesWritten: number;
}

export interface RunJournal {
  /** The stage the flow is in now: `start`, `sdp`, `link-open`, then the auth state names. */
  readonly stage: string;
  /** Every stage reached, in order, without repeats. */
  readonly stages: readonly string[];
  readonly counts: RunCounts;
  /** Record that the flow has reached a stage. Repeating the same name does not add it twice. */
  reached(name: string): void;
  /** One data event arrived: `bytes` payload bytes the sidecar counted. */
  data(bytes: number): void;
  /** One complete frame was reassembled from the bytes that arrived. */
  frame(): void;
  /** One frame was handed to the transport for writing. */
  written(bytes: number): void;
  /**
   * One sentence saying why a wait ended without the expected frame, chosen by what actually
   * arrived: silence, unframeable bytes, or frames that were not the reply.
   */
  silence(state: string, timeoutMs: number): string;
  /** The report lines: stage reached, the stage trail, and the counters. Masked, counts only. */
  lines(): string[];
}

/**
 * A journal for one run. Nothing here reads a clock, a file or a socket: the caller decides when a
 * stage is reached, and a test can therefore assert the exact lines a run would report.
 */
export function createRunJournal(): RunJournal {
  const stages: string[] = [];
  let bytesReceived = 0;
  let framesReceived = 0;
  let bytesWritten = 0;
  let framesWritten = 0;

  return {
    get stage() {
      return stages.at(-1) ?? "start";
    },
    get stages() {
      return [...stages];
    },
    get counts(): RunCounts {
      return { bytesReceived, framesReceived, bytesWritten, framesWritten };
    },
    reached(name: string) {
      const cleaned = String(name ?? "").trim();
      if (!cleaned || stages.at(-1) === cleaned) return;
      stages.push(cleaned);
    },
    data(bytes: number) {
      if (Number.isFinite(bytes) && bytes > 0) bytesReceived += bytes;
    },
    frame() {
      framesReceived += 1;
    },
    written(bytes: number) {
      framesWritten += 1;
      if (Number.isFinite(bytes) && bytes > 0) bytesWritten += bytes;
    },
    silence(state: string, timeoutMs: number) {
      const where = `${timeoutMs}ms while waiting for ${state}`;
      if (framesReceived === 0 && bytesReceived === 0) {
        return `timeout: no bytes received in ${where}: the link was open and the watch said nothing at all`;
      }
      if (framesReceived === 0) {
        return `timeout: ${bytesReceived} byte(s) arrived in ${where}, but they never formed a frame: the watch answered with something this stream could not frame`;
      }
      return `timeout: ${framesReceived} frame(s) (${bytesReceived} bytes) arrived in ${where}, and none of them was the reply this step needs: the watch answered something else`;
    },
    lines() {
      const trail = stages.length > 1 ? ` (after: ${stages.join(" -> ")})` : "";
      return [
        `stage: ${stages.at(-1) ?? "start"}${trail}`,
        `bytes received: ${bytesReceived}`,
        `frames received: ${framesReceived}`,
        `frames written: ${framesWritten} (${bytesWritten} bytes)`,
      ].map((line) => maskMacText(line));
    },
  };
}