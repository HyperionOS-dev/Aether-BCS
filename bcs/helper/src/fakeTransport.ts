// BCS helper — an in-memory transport, so the contract and everything built on it can be tested
// with no Bluetooth hardware. This fake sends nothing unless a test opts in to recording writes.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// The fake mirrors the real transport's opt-in discipline: write() is refused unless a test asks
// for recording. Tests that assert "nothing was sent to the watch" can therefore use the fake.

import {
  bcsError,
  type BcsClosedEvent,
  type BcsError,
  type BcsObservableTransport,
  type BcsOpenTarget,
  type BcsTransport,
} from "./types.ts";

const nowIso = () => new Date().toISOString();

export interface FakeTransportOptions {
  /** Off by default: Phase 1 must never send bytes, so neither must the fake. */
  allowWrites?: boolean;
  /** When set, open() fails with exactly this error. */
  failOpenWith?: BcsError | null;
}

export class FakeTransport implements BcsTransport, BcsObservableTransport {
  #options: FakeTransportOptions;
  #state: "closed" | "open" = "closed";
  #dataHandlers: ((data: Uint8Array, channel: number) => void)[] = [];
  #closedHandlers: ((info: BcsClosedEvent) => void)[] = [];
  #errorHandlers: ((err: BcsError) => void)[] = [];
  #opens: BcsOpenTarget[] = [];
  #auxChannels: number[] = [];
  #writes: { data: Uint8Array; channel: number }[] = [];
  #closeCount = 0;

  constructor(options: FakeTransportOptions = {}) {
    this.#options = options;
  }

  get state(): string {
    return this.#state;
  }
  get opens(): BcsOpenTarget[] {
    return this.#opens;
  }
  get auxChannels(): number[] {
    return this.#auxChannels;
  }
  get writes(): { data: Uint8Array; channel: number }[] {
    return this.#writes;
  }
  get closeCount(): number {
    return this.#closeCount;
  }

  async open(target: BcsOpenTarget = {}): Promise<void> {
    if (this.#state === "open") throw bcsError("already-open", "transport is already open");
    if (this.#options.failOpenWith) throw this.#options.failOpenWith;
    this.#opens.push({ ...target });
    this.#state = "open";
  }

  async openAux(channel: number): Promise<void> {
    if (this.#state !== "open") {
      throw bcsError("not-open", "open the primary link before opening an aux channel");
    }
    this.#auxChannels.push(channel);
  }

  async write(data: Uint8Array, channel = 0): Promise<void> {
    if (this.#state !== "open") throw bcsError("not-open", "transport is not open");
    if (!this.#options.allowWrites) {
      throw bcsError("write-not-allowed", "Phase 1 is link only: no bytes are sent to the watch");
    }
    this.#writes.push({ data, channel });
  }

  onData(cb: (data: Uint8Array, channel: number) => void): void {
    this.#dataHandlers.push(cb);
  }

  onClosed(cb: (info: BcsClosedEvent) => void): void {
    this.#closedHandlers.push(cb);
  }

  onError(cb: (err: BcsError) => void): void {
    this.#errorHandlers.push(cb);
  }

  async close(): Promise<void> {
    if (this.#state === "closed") return;
    this.#state = "closed";
    this.#closeCount += 1;
    this.#emitClosed("closed by caller");
  }

  // --- test drivers: the watch side of the conversation ---

  /** Bytes arriving from the watch. Tests may assert on them; nothing logs them. */
  emitData(bytes: Uint8Array, channel = 0): void {
    for (const cb of this.#dataHandlers) cb(bytes, channel);
  }

  /** The watch dropped the link on its own. */
  emitRemoteClose(reason = "remote closed the link"): void {
    if (this.#state === "closed") return;
    this.#state = "closed";
    this.#emitClosed(reason);
  }

  emitError(err: BcsError): void {
    for (const cb of this.#errorHandlers) cb(err);
  }

  #emitClosed(reason: string): void {
    const info: BcsClosedEvent = { at: nowIso(), reason };
    for (const cb of this.#closedHandlers) cb(info);
  }
}