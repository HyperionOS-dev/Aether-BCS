// BCS helper — the TypeScript client of the Python sidecar's pipe. It connects and carries only
// allowlisted auth-frame writes.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// The transport takes a `pipe` object rather than a child process, so tests drive it with an
// in-memory pair and no Python, no Bluetooth and no timing luck. sidecarProcess.ts is the thin
// adapter that gives a real child process this shape.
//
// The Python side validates every write before sendall. open() still requires a channel found by
// probe-channel, and received frame bytes reach handlers only from an explicit pipe event.

import { MASKED_ADDRESS, isAddress, maskAddress, maskMacText } from "./mask.ts";
import { createLogger } from "./log.ts";
import { HUAWEI_SDP_UUID } from "./huawei/constants.ts";
import {
  dataCountOf,
  encodeCommand,
  errorFromResponse,
  hexToBytes,
  MAX_LINE_BYTES,
  parseLine,
  isKnownErrorCode,
  safeSidecarErrorMessage,
  type SidecarResponse,
} from "./sidecarProtocol.ts";
import {
  bcsError,
  type BcsClosedEvent,
  type BcsBtSecurity,
  type BcsDataCountEvent,
  type BcsError,
  type BcsErrorCode,
  type BcsLogger,
  type BcsObservableTransport,
  type BcsOpenTarget,
  type BcsTransport,
} from "./types.ts";

/** The four things the transport needs from a pipe. A child process and a test double both fit. */
export interface SidecarPipe {
  write(line: string): void;
  onLine(handler: (line: string) => void): void;
  onEnd(handler: (reason: string) => void): void;
}

export interface SidecarTransportOptions {
  pipe: SidecarPipe;
  logger?: BcsLogger;
  requestTimeoutMs?: number;
  connectTimeoutMs?: number;
  /** SDP is a query to the watch, so it gets its own, longer bound than an ordinary command. */
  sdpTimeoutMs?: number;
  /**
   * Phase 3G (D1): the BT_SECURITY level every open() asks for unless it names its own. `none`, the
   * default, keeps the link exactly as it was before this phase.
   */
  btSecurity?: BcsBtSecurity;
  /** Phase 3G (D2): require a bonded watch before connecting. Off by default. */
  requireBond?: boolean;
  onDataCount?: (event: BcsDataCountEvent) => void;
}

/** The four names the sidecar accepts. Kept here so a bad value is refused before the pipe. */
const BT_SECURITY_NAMES: readonly BcsBtSecurity[] = ["none", "low", "medium", "high"];

function checkedBtSecurity(value: BcsBtSecurity | undefined): BcsBtSecurity {
  const name = value ?? "none";
  if (!BT_SECURITY_NAMES.includes(name)) {
    throw bcsError("bad-config", `bt-security must be one of ${BT_SECURITY_NAMES.join(", ")}`);
  }
  return name;
}

/**
 * What SDP said about the watch's RFCOMM channel. `channel` is the only channel this helper may
 * connect to: the sidecar refuses any other one, so a probed channel cannot reach the radio.
 */
export interface SdpChannel {
  /**
   * The watch the query was about, masked by the sidecar (`XX:XX:XX:XX:AA:BB`). A lookup run prints
   * this so the evidence names a device; the full address never leaves the sidecar.
   */
  readonly address: string;
  /** Which tool answered: `sdptool`, `bluetoothctl` or `unavailable`. */
  readonly method: string;
  readonly channel: number;
  /** True when the record carried the Huawei service UUID (the strongest evidence). */
  readonly matchedUuid: boolean;
  /** True when it carried the serial-port profile name or UUID instead. */
  readonly matchedSerial: boolean;
  /** The sidecar's own masked note about where the channel came from. Never contains an address. */
  readonly detail: string;
}

export interface SidecarTransport extends BcsTransport, BcsObservableTransport {
  /** Ask the running sidecar which operations it supports; this is the live capability check. */
  ping(): Promise<string[]>;
  /**
   * Ask SDP which channel serves the Huawei service. A refusal (no SDP, no channel, no evidence,
   * or a disagreement with `expectChannel`) rejects with a typed code, and nothing is connected.
   */
  resolveChannel(options?: { uuid?: string; expectChannel?: number }): Promise<SdpChannel>;
  isOpen(): boolean;
  /** Resolves when the link ends, whoever ended it. */
  waitForClosed(): Promise<BcsClosedEvent>;
}

const nowIso = () => new Date().toISOString();
const SAFE_CLOSED_REASONS = new Set([
  "the watch closed the link",
  "closed by the caller",
  "the parent stopped talking to the sidecar",
  "interrupted",
  "write timed out",
  "write failed",
]);

function safeAddress(address: string | undefined): string {
  if (!address) return MASKED_ADDRESS;
  if (/^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$/i.test(address)) return address;
  if (/^XX:XX:XX:XX:[0-9A-F]{2}:[0-9A-F]{2}$/i.test(address)) return address;
  return MASKED_ADDRESS;
}

/**
 * The watch an SDP answer names, always masked. The sidecar masks it before sending, but a transport
 * that trusted the far side would put a full address into a printed line or a report the moment that
 * side changed, so an unmasked value is masked here and anything that is not an address at all
 * becomes the fully masked placeholder.
 */
function maskedWatchAddress(address: string | undefined): string {
  if (!address) return MASKED_ADDRESS;
  if (/^XX:XX:XX:XX:[0-9A-F]{2}:[0-9A-F]{2}$/i.test(address)) return address.toUpperCase();
  if (isAddress(address)) return maskAddress(address);
  return MASKED_ADDRESS;
}

export function createSidecarTransport(options: SidecarTransportOptions): SidecarTransport {
  const logger = options.logger ?? createLogger({ prefix: "bcs-sidecar" });
  const requestTimeoutMs = options.requestTimeoutMs ?? 5_000;
  const connectTimeoutMs = options.connectTimeoutMs ?? 10_000;
  // Three bounded SDP attempts may take 3 * 20s plus two short backoffs.
  const sdpTimeoutMs = options.sdpTimeoutMs ?? 65_000;
  // Phase 3G defaults. `none` and off: an options object without these builds the old command.
  const btSecurity = checkedBtSecurity(options.btSecurity);
  const requireBond = options.requireBond ?? false;
  const dataHandlers: ((data: Uint8Array, channel: number) => void)[] = [];
  const closedHandlers: ((info: BcsClosedEvent) => void)[] = [];
  const errorHandlers: ((err: BcsError) => void)[] = [];
  const pending = new Map<
    number,
    { resolve: (r: SidecarResponse) => void; reject: (e: BcsError) => void; timer: NodeJS.Timeout }
  >();
  let nextId = 1;
  let isOpen = false;
  let resolveClosed: (info: BcsClosedEvent) => void = () => {};
  const closedPromise = new Promise<BcsClosedEvent>((resolve) => {
    resolveClosed = resolve;
  });

  function finish(info: BcsClosedEvent): void {
    if (!isOpen) return;
    isOpen = false;
    logger.info(`link ended: ${info.reason}`);
    for (const handler of closedHandlers) handler(info);
    resolveClosed(info);
  }

  function failWith(err: BcsError): void {
    const safeError = bcsError(err.code, safeSidecarErrorMessage(err.code), err.errno);
    logger.error(safeError.message);
    for (const handler of errorHandlers) handler(safeError);
  }

  function send(command: Record<string, unknown>, timeoutMs: number): Promise<SidecarResponse> {
    return new Promise<SidecarResponse>((resolve, reject) => {
      const id = nextId;
      nextId += 1;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(bcsError("timeout", `the sidecar did not answer "${String(command.cmd)}" within ${timeoutMs} ms`));
      }, timeoutMs);
      pending.set(id, { resolve, reject, timer });
      try {
        options.pipe.write(encodeCommand({ id, ...command }));
      } catch (cause) {
        clearTimeout(timer);
        pending.delete(id);
        reject(bcsError("sidecar-exited", "could not write to the sidecar"));
      }
    });
  }

  function settle(response: SidecarResponse): void {
    const entry = pending.get(response.id);
    if (!entry) {
      logger.warn(`ignoring a response for unknown request id ${response.id}`);
      return;
    }
    clearTimeout(entry.timer);
    pending.delete(response.id);
    entry.resolve(response);
  }

  options.pipe.onLine((line) => {
    if (line.length > MAX_LINE_BYTES) {
      failWith(bcsError("protocol", "the sidecar sent an over-long line; the pipe is treated as broken"));
      return;
    }
    const message = parseLine(line);
    if (!message) {
      logger.warn("ignoring an unparsable line from the sidecar");
      return;
    }
    if ("id" in message) {
      settle(message);
      return;
    }
    if (message.event === "data") {
      const count = dataCountOf(message);
      // The only report of arriving bytes: count, channel and time. Never the payload.
      logger.bytesReceived(count);
      options.onDataCount?.(count);
      if (message.hex) {
        try {
          const bytes = hexToBytes(message.hex);
          for (const handler of dataHandlers) handler(bytes, count.channel);
        } catch (err) {
          failWith(err as BcsError);
        }
      }
      return;
    }
    if (message.event === "closed") {
      finish({
        at: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(message.at)
          ? message.at
          : nowIso(),
        reason: SAFE_CLOSED_REASONS.has(message.reason ?? "") ? message.reason! : "the sidecar closed the link",
      });
      return;
    }
    // Never trust a code string from the child. Known failures get their stable sentence; an
    // invented or missing code becomes the one structured `unknown` error instead of a cast.
    const code = isKnownErrorCode(message.code) ? message.code : "unknown";
    failWith(bcsError(code, safeSidecarErrorMessage(code), message.errno ?? null));
  });

  options.pipe.onEnd((reason) => {
    for (const [id, entry] of pending) {
      clearTimeout(entry.timer);
      pending.delete(id);
      entry.reject(bcsError("sidecar-exited", `the sidecar stopped before answering: ${reason}`));
    }
    finish({ at: nowIso(), reason });
  });

  return {
    async ping() {
      const response = await send({ cmd: "ping" }, requestTimeoutMs);
      if (!response.ok) throw errorFromResponse(response);
      return response.capabilities ?? [];
    },
    async resolveChannel(request: { uuid?: string; expectChannel?: number } = {}) {
      const command: Record<string, unknown> = { cmd: "resolve_channel", uuid: request.uuid ?? HUAWEI_SDP_UUID };
      if (request.expectChannel !== undefined) command.expect_channel = request.expectChannel;
      const response = await send(command, sdpTimeoutMs);
      // A refusal is final: the message names the code, and the call never falls back to a channel
      // that came from anywhere else.
      if (!response.ok) throw errorFromResponse(response);
      const channel = response.channel;
      if (!Number.isInteger(channel) || (channel as number) < 1 || (channel as number) > 30) {
        throw bcsError("protocol", "the sidecar's SDP answer carried no usable channel number");
      }
      const sdp: SdpChannel = {
        address: maskedWatchAddress(response.address),
        method: typeof response.method === "string" ? response.method : "unknown",
        channel: channel as number,
        matchedUuid: response.matched_uuid === true,
        matchedSerial: response.matched_serial === true,
        detail: maskMacText(response.detail ?? ""),
      };
      logger.info(
        `SDP resolved channel ${String(sdp.channel)} through ${sdp.method} ` +
          `(huawei uuid: ${sdp.matchedUuid ? "yes" : "no"}, serial record: ${sdp.matchedSerial ? "yes" : "no"})`,
      );
      return sdp;
    },
    async open(target: BcsOpenTarget = {}) {
      if (isOpen) throw bcsError("already-open", "the link is already open");
      const channel = target.channel;
      if (!Number.isInteger(channel) || (channel as number) < 1 || (channel as number) > 30) {
        throw bcsError(
          "missing-channel",
          "open() needs the channel SDP resolved, between 1 and 30; ask resolveChannel() first",
        );
      }
      const timeoutMs = target.timeoutMs ?? connectTimeoutMs;
      // Both link options are checked here, so a typo stops at the driver rather than becoming a
      // different link. They are only put on the wire when they are not the defaults, which keeps a
      // plain open() byte-for-byte what it was before Phase 3G.
      const security = checkedBtSecurity(target.btSecurity ?? btSecurity);
      const needsBond = target.requireBond ?? requireBond;
      if (typeof needsBond !== "boolean") {
        throw bcsError("bad-config", "requireBond must be true or false");
      }
      const command: Record<string, unknown> = { cmd: "connect", channel, timeout_ms: timeoutMs };
      if (security !== "none") command.bt_security = security;
      if (needsBond) command.require_bond = true;
      if (security !== "none" || needsBond) {
        // Names only, so the run log says which link was attempted without carrying watch data.
        logger.info(`link options: bt-security ${security}, require-bond ${needsBond ? "on" : "off"}`);
      }
      const response = await send(command, timeoutMs + 1_000);
      if (!response.ok) throw errorFromResponse(response);
      isOpen = true;
      // The sidecar masks the address before sending it and the logger masks anything that
      // arrives unmasked, so the value is passed through rather than masked twice: masking a
      // masked address would hide the last two octets as well, and those are the part that
      // tells two watches apart in a log.
      logger.info(`connected to ${safeAddress(response.address)} on channel ${String(channel)}`);
    },
    async openAux(channel: number) {
      if (!isOpen) throw bcsError("not-open", "open the primary link before opening an aux channel");
      const response = await send({ cmd: "open_aux", channel }, requestTimeoutMs);
      if (!response.ok) throw errorFromResponse(response);
    },
    async write(data: Uint8Array) {
      if (!isOpen) throw bcsError("not-open", "write requires an open link");
      const hex = [...data].map((byte) => byte.toString(16).padStart(2, "0")).join("");
      const response = await send({ cmd: "write", hex }, requestTimeoutMs);
      if (!response.ok) throw errorFromResponse(response);
    },
    onData(cb: (data: Uint8Array, channel: number) => void) {
      dataHandlers.push(cb);
    },
    onClosed(cb: (info: BcsClosedEvent) => void) {
      closedHandlers.push(cb);
    },
    onError(cb: (err: BcsError) => void) {
      errorHandlers.push(cb);
    },
    async close() {
      if (!isOpen) return;
      try {
        const response = await send({ cmd: "close" }, requestTimeoutMs);
        // A refused close still ends the link, but it must not be reported as acknowledged.
        if (!response.ok) logger.warn(`close was not acknowledged: ${errorFromResponse(response).message}`);
      } catch (err) {
        logger.warn(`close was not acknowledged: ${(err as BcsError).message}`);
      }
      finish({ at: nowIso(), reason: "closed by the caller" });
    },
    isOpen: () => isOpen,
    waitForClosed: () => closedPromise,
  };
}