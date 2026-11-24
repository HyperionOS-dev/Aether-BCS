// BCS helper — the thin adapter that turns a real Python child process into the pipe shape the
// transport expects. Sidecar writes are limited to allowlisted authentication frames.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Line buffering lives here, including the case that matters: a JSON message split across two
// chunks of a pipe is one message, and two messages in one chunk are two. The sidecar's stderr
// is human diagnostics only, and goes through the masked logger.

import { spawn, type ChildProcess } from "node:child_process";
import type { Readable } from "node:stream";
import { createLogger } from "./log.ts";
import {
  createSidecarTransport,
  type SidecarPipe,
  type SidecarTransport,
} from "./sidecarTransport.ts";
import type { BcsDataCountEvent, BcsLogger } from "./types.ts";

const MAX_BUFFERED_LINE = 4_194_304;

/** Newline-delimited reading only. Used by the child pipe and by tests with a plain Readable. */
export function readLinesFromStream(stream: Readable): Pick<SidecarPipe, "onLine" | "onEnd"> {
  const lineHandlers: ((line: string) => void)[] = [];
  const endHandlers: ((reason: string) => void)[] = [];
  let buffer = "";
  stream.on("data", (chunk: string | Buffer) => {
    buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    if (buffer.length > MAX_BUFFERED_LINE) {
      buffer = "";
      for (const handler of endHandlers) handler("the sidecar sent more than a line without a newline");
      return;
    }
    let index = buffer.indexOf("\n");
    while (index >= 0) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      for (const handler of lineHandlers) handler(line);
      index = buffer.indexOf("\n");
    }
  });
  stream.on("end", () => {
    for (const handler of endHandlers) handler("the sidecar closed its output");
  });
  stream.on("error", (_err: Error) => {
    for (const handler of endHandlers) handler("the sidecar output pipe failed");
  });
  return {
    onLine: (handler) => lineHandlers.push(handler),
    onEnd: (handler) => endHandlers.push(handler),
  };
}

/** A child's stdout as lines, its stdin as the write side, its stderr as masked diagnostics. */
export function createChildPipe(child: ChildProcess, logger: BcsLogger): SidecarPipe {
  const reader = child.stdout ? readLinesFromStream(child.stdout) : null;
  const endHandlers: ((reason: string) => void)[] = [];
  let stderrBuffer = "";

  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk: string) => {
    stderrBuffer += chunk;
    let index = stderrBuffer.indexOf("\n");
    while (index >= 0) {
      const line = stderrBuffer.slice(0, index).trim();
      stderrBuffer = stderrBuffer.slice(index + 1);
      if (line) logger.warn("sidecar emitted a diagnostic line");
      index = stderrBuffer.indexOf("\n");
    }
  });

  child.on("exit", (code, signal) => {
    const reason = signal
      ? `the sidecar was killed (${signal})`
      : `the sidecar exited with code ${String(code)}`;
    for (const handler of endHandlers) handler(reason);
  });
  child.on("error", (_err: Error) => {
    for (const handler of endHandlers) handler("the sidecar could not be started");
  });
  // A child that exits while a request is being written can close stdin before write() returns.
  // Always consume that stream error and turn it into the ordinary sidecar-ended path.
  child.stdin?.on("error", () => {
    for (const handler of endHandlers) handler("the sidecar input pipe failed");
  });

  return {
    write: (line: string) => {
      if (!child.stdin || child.stdin.destroyed) throw new Error("the sidecar is not running");
      child.stdin.write(line);
    },
    onLine: (handler) => reader?.onLine(handler),
    onEnd: (handler) => {
      endHandlers.push(handler);
      reader?.onEnd(handler);
    },
  };
}

export interface SpawnSidecarOptions {
  /** Absolute path to sidecar/rfcomm_sidecar.py. */
  scriptPath: string;
  python?: string;
  /** The sidecar's place to read the address from. Never the address itself. */
  configPath?: string;
  /** Ask the sidecar to send arriving bytes as hex over Node's AF_UNIX socketpair. */
  emitHex?: boolean;
  logger?: BcsLogger;
  requestTimeoutMs?: number;
  connectTimeoutMs?: number;
  sdpTimeoutMs?: number;
  /**
   * Extra environment for the child, merged over this process's own. Tests use it to hand the
   * sidecar a temporary HOME, so no test can read or write the user's real config or state.
   */
  env?: NodeJS.ProcessEnv;
  onDataCount?: (event: BcsDataCountEvent) => void;
}

export interface SpawnedSidecar {
  transport: SidecarTransport;
  child: ChildProcess;
  stop(): void;
}

export function spawnSidecar(options: SpawnSidecarOptions): SpawnedSidecar {
  const logger = options.logger ?? createLogger({ prefix: "bcs" });
  const args = [options.scriptPath];
  if (options.configPath) args.push("--config", options.configPath);
  if (options.emitHex) args.push("--emit-hex");
  const child = spawn(options.python ?? "python3", args, {
    stdio: ["pipe", "pipe", "pipe"],
    ...(options.env ? { env: { ...process.env, ...options.env } } : {}),
  });
  const transport = createSidecarTransport({
    pipe: createChildPipe(child, logger),
    logger,
    requestTimeoutMs: options.requestTimeoutMs,
    connectTimeoutMs: options.connectTimeoutMs,
    sdpTimeoutMs: options.sdpTimeoutMs,
    onDataCount: options.onDataCount,
  });
  return {
    transport,
    child,
    stop: () => {
      if (!child.killed) child.kill();
    },
  };
}