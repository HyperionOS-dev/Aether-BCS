// BCS helper — Phase 2 (Huawei packet codec): reassembly. Pure code: it takes chunks of bytes and
// returns frames. No socket, no timer, no I/O, no key material, nothing sent to the watch.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge, HuaweiPacket.java at commit
// a0948ee1cbc2a870f91d313f8e37df5f524465f7 (GitHub mirror, frozen 2024-12-22):
//   the partial-packet rule  lines 321-361 (merge what is left with what just arrived)
//   the slice assembly rule  lines 388-402 (append content until the 0x03 slice completes it)
//   the surplus-bytes rule   line 375      (`left`: bytes after the frame, kept by its caller)
// Upstream keeps that state inside the packet object and hands the surplus back to its caller; a
// live RFCOMM read can split a frame in the middle or deliver several at once, so this module owns
// the buffer instead and reports every frame it can build.
//
// Two divergences, both about desynchronisation, both deliberate:
//  1. A 0x01 slice starts a fresh accumulation even if an unfinished one is pending. Upstream
//     appends to whatever it already held (:389-395), which merges two different packets into one
//     bogus payload when a middle slice was lost. Starting fresh loses one packet instead of
//     inventing one.
//  2. A middle (0x02) or last (0x03) slice with no first slice is a typed error, not a frame built
//     from the fragment (upstream would read its first two bytes as ids).
// A hard error (bad magic, bad length, bad CRC) also clears the buffer: the stream is out of step,
// and guessing where the next frame begins is how garbage gets parsed as a packet.

import { codecFail, codecOk, type CodecResult, type HuaweiCodecError } from "./errors.ts";
import { decodeOneFrame, frameFromPayload, type HuaweiFrame } from "./frame.ts";

/** What one push produced: the frames it completed, and a typed error if one was hit. */
export interface StreamStep {
  frames: HuaweiFrame[];
  error?: HuaweiCodecError;
  /** Bytes still waiting for the rest of their frame. */
  pendingBytes: number;
}

export interface HuaweiStreamOptions {
  /**
   * Refuse to buffer more than this without framing anything. Default 65536, which is twice the
   * largest legal frame (a length field of 0x7FFF is 32772 bytes on the wire).
   */
  maxPendingBytes?: number;
}

export interface HuaweiStream {
  push(chunk: Uint8Array): StreamStep;
  /** Signal end of stream: anything still buffered becomes a "truncated" error. */
  end(): StreamStep;
  pendingBytes(): number;
  reset(): void;
}

export function createHuaweiStream(options: HuaweiStreamOptions = {}): HuaweiStream {
  const maxPending = options.maxPendingBytes ?? 64 * 1024;
  let buffer = new Uint8Array(0);
  let partialContent: Uint8Array | null = null;
  let sliceFlags: number[] = [];
  let sliceCount = 0;

  function clear(): void {
    buffer = new Uint8Array(0);
    partialContent = null;
    sliceFlags = [];
    sliceCount = 0;
  }

  function fail(frames: HuaweiFrame[], error: HuaweiCodecError): StreamStep {
    clear();
    return { frames, error, pendingBytes: 0 };
  }

  function push(chunk: Uint8Array): StreamStep {
    if (chunk.length === 0) {
      // Not an error: a read that returned nothing yet is what upstream treats as "no packet".
      // An empty *frame* is different, and decodeOneFrame reports that as bad-length.
      return { frames: [], pendingBytes: buffer.length };
    }
    const merged = new Uint8Array(buffer.length + chunk.length);
    merged.set(buffer, 0);
    merged.set(chunk, buffer.length);
    buffer = merged;

    if (buffer.length > maxPending) {
      const error = codecFail(
        "bad-length",
        `nothing could be framed in ${buffer.length} bytes, past the ${maxPending}-byte limit`,
      ).error;
      return fail([], error);
    }

    const frames: HuaweiFrame[] = [];
    let consumed = 0;
    for (;;) {
      const rest = buffer.subarray(consumed);
      if (rest.length === 0) break;
      const step = decodeOneFrame(rest);
      if (!step.ok) return fail(frames, step.error);
      if (step.value.kind === "incomplete") break;
      consumed += step.value.consumed;

      if (step.value.kind === "slice") {
        const { sliceType, flag, content } = step.value.slice;
        if (sliceType === 1) {
          partialContent = content;
          sliceFlags = [flag];
          sliceCount = 1;
          continue;
        }
        if (partialContent === null) {
          const error = codecFail(
            "bad-length",
            `slice ${sliceType} arrived with no first slice before it`,
            consumed,
            `slice ${sliceType}`,
          ).error;
          return fail(frames, error);
        }
        const assembled = new Uint8Array(partialContent.length + content.length);
        assembled.set(partialContent, 0);
        assembled.set(content, partialContent.length);
        partialContent = assembled;
        sliceFlags.push(flag);
        sliceCount += 1;
        if (sliceType === 2) continue;
        const frame = frameFromPayload(assembled, sliceType, sliceFlags, sliceCount);
        partialContent = null;
        sliceFlags = [];
        sliceCount = 0;
        if (!frame.ok) return fail(frames, frame.error);
        frames.push(frame.value);
        continue;
      }

      frames.push(step.value.frame);
    }
    if (consumed > 0) buffer = buffer.subarray(consumed);
    return { frames, pendingBytes: buffer.length };
  }

  function end(): StreamStep {
    if (partialContent !== null) {
      const pending = buffer.length + partialContent.length;
      const error = codecFail("truncated", `stream ended inside a sliced frame with about ${pending} bytes`).error;
      return fail([], error);
    }
    if (buffer.length > 0) {
      const error = codecFail("truncated", `stream ended with ${buffer.length} unconsumed bytes`).error;
      return fail([], error);
    }
    return { frames: [], pendingBytes: 0 };
  }

  return {
    push,
    end,
    pendingBytes: () => buffer.length + (partialContent === null ? 0 : partialContent.length),
    reset: clear,
  };
}

/**
 * Decode a buffer that should hold a whole number of frames, and report an error if anything is
 * left over. The stream ceiling is lifted for the caller's buffer so this differs from push() only
 * in reporting leftovers as "truncated".
 */
export function decodeFrames(bytes: Uint8Array): CodecResult<HuaweiFrame[]> {
  const stream = createHuaweiStream({ maxPendingBytes: Math.max(64 * 1024, bytes.length + 1) });
  const step = stream.push(bytes);
  if (step.error) return { ok: false, error: step.error };
  const ended = stream.end();
  if (ended.error) return { ok: false, error: ended.error };
  return codecOk(step.frames);
}
