// BCS helper — the real sidecar as a child process: start it, ping it, stop it.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// These tests start Python for real, and they only ever ping. Nothing here opens a socket to a
// watch, reads a config file or needs a watch address: a ping needs none of them.
//
// The first test is a regression, and it is the reason this file exists. Node's
// `spawn(..., { stdio: "pipe" })` does not hand the child a FIFO: libuv gives it one end of an
// AF_UNIX socketpair, so the child's stdout is S_IFSOCK. The sidecar used to accept only a FIFO for
// `--emit-hex`, so it exited 2 before reading a command and the driver reported "the sidecar did not
// answer its live capability ping" — while `--self-test` passed, because a shell pipe really is a
// FIFO. A test built on a FIFO, or on the in-memory pipe the transport tests use, cannot catch that
// class of bug. This one spawns the sidecar exactly the way `tools/bcs_auth.mjs` does.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { spawnSidecar, type SpawnedSidecar } from "../src/sidecarProcess.ts";
import type { BcsLogger } from "../src/types.ts";
import { createSandbox, type Sandbox } from "../testutil/sandbox.ts";

const SIDECAR = fileURLToPath(new URL("../sidecar/rfcomm_sidecar.py", import.meta.url));
/** Long enough for a cold Python start on a loaded machine; the answer itself arrives in milliseconds. */
const REQUEST_TIMEOUT_MS = 30_000;

function pythonIsAvailable(): boolean {
  try {
    return spawnSync("python3", ["-V"], { stdio: "ignore" }).status === 0;
  } catch {
    return false;
  }
}

const SKIP_NO_PYTHON = pythonIsAvailable()
  ? false
  : "these tests start the real Python sidecar, and python3 is not on PATH";

/** A logger that keeps the sidecar's diagnostics so a failure can say what the child reported. */
function recordingLogger(): { logger: BcsLogger; warnings: string[] } {
  const warnings: string[] = [];
  return {
    warnings,
    logger: {
      info: () => {},
      warn: (message: string) => warnings.push(String(message)),
      error: () => {},
      bytesReceived: () => {},
    },
  };
}

/** The driver's own call: the script path, --emit-hex, and no config path. */
function startSidecar(
  options: {
    emitHex?: boolean;
    scriptPath?: string;
    logger?: BcsLogger;
    env?: NodeJS.ProcessEnv;
    configPath?: string;
  } = {},
): SpawnedSidecar {
  return spawnSidecar({
    scriptPath: options.scriptPath ?? SIDECAR,
    emitHex: options.emitHex,
    logger: options.logger,
    configPath: options.configPath,
    requestTimeoutMs: REQUEST_TIMEOUT_MS,
    env: options.env,
  });
}

/**
 * A temporary HOME for one test, cleaned up when it finishes. Every test in this file passes one, so
 * the real sidecar's default `--config` path (~/.config/aether-bcs/watch.json) lands in the sandbox.
 */
function sandboxFor(context: { after: (fn: () => void) => void }): Sandbox {
  const box = createSandbox("bcs-sidecar-process");
  context.after(() => box.cleanup());
  return box;
}

test("with --emit-hex, exactly as the driver starts it, the live ping is answered", { skip: SKIP_NO_PYTHON }, async (context) => {
  const box = sandboxFor(context);
  const { logger, warnings } = recordingLogger();
  const spawned = startSidecar({ emitHex: true, logger, env: box.env() });
  try {
    const capabilities = await spawned.transport.ping();
    // "resolve" is the SDP capability: the driver requires it as well as "write".
    assert.deepEqual(capabilities, ["connect", "write", "resolve"]);
    // A normal startup is silent: only an actual sidecar problem may produce a diagnostic warning.
    assert.deepEqual(warnings, []);
    assert.equal(spawned.child.exitCode, null, "the sidecar should still be running after the ping");
  } finally {
    spawned.stop();
  }
});

test("without --emit-hex the ping is answered too, so the flag is the only difference", { skip: SKIP_NO_PYTHON }, async (context) => {
  const box = sandboxFor(context);
  const spawned = startSidecar({ emitHex: false, logger: recordingLogger().logger, env: box.env() });
  try {
    assert.deepEqual(await spawned.transport.ping(), ["connect", "write", "resolve"]);
  } finally {
    spawned.stop();
  }
});

test("stop() really ends the child, so a driver that gives up leaves nothing behind", { skip: SKIP_NO_PYTHON }, async (context) => {
  const box = sandboxFor(context);
  const spawned = startSidecar({ emitHex: true, logger: recordingLogger().logger, env: box.env() });
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    spawned.child.on("exit", (code, signal) => resolve({ code, signal }));
  });
  try {
    await spawned.transport.ping();
  } finally {
    spawned.stop();
  }
  const result = await exited;
  assert.ok(result.signal === "SIGTERM" || result.code === 0, `unexpected exit: ${JSON.stringify(result)}`);
});

test("a child that dies before answering rejects the ping with a typed sidecar-exited", { skip: SKIP_NO_PYTHON }, async (context) => {
  const box = sandboxFor(context);
  const directory = mkdtempSync(join(tmpdir(), "bcs-sidecar-exit-"));
  try {
    // A real Python process, not a stub of the pipe: it stays alive while the ping is written and
    // then exits without answering, which is the shape the driver has to survive.
    const script = join(directory, "exits_before_answering.py");
    writeFileSync(script, "import time\ntime.sleep(0.5)\nraise SystemExit(2)\n");
    const spawned = startSidecar({
      emitHex: true,
      scriptPath: script,
      logger: recordingLogger().logger,
      env: box.env(),
    });
    try {
      await assert.rejects(
        () => spawned.transport.ping(),
        (error: { code?: string }) => {
          assert.equal(error.code, "sidecar-exited");
          return true;
        },
      );
    } finally {
      spawned.stop();
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("resolve_channel with no saved address is a coded refusal and never queries SDP", { skip: SKIP_NO_PYTHON }, async (context) => {
  // No watch.json in the sandbox at all, so the sidecar stops at the address: sdptool is never run,
  // which is what makes this test safe to run on a machine with a real watch nearby.
  const box = sandboxFor(context);
  const spawned = startSidecar({ emitHex: true, logger: recordingLogger().logger, env: box.env() });
  try {
    await spawned.transport.ping();
    await assert.rejects(
      () => spawned.transport.resolveChannel({ expectChannel: 18 }),
      (error: { code?: string }) => {
        assert.equal(error.code, "no-config");
        return true;
      },
    );
    assert.equal(spawned.transport.isOpen(), false);
    // A refusal writes nothing: the sandbox state directory stays empty.
    assert.deepEqual(box.stateFiles(), []);
  } finally {
    spawned.stop();
  }
});

test("connect before resolve_channel is refused as channel-unverified, so no socket is opened", { skip: SKIP_NO_PYTHON }, async (context) => {
  // A synthetic address: if the sidecar ever tried to connect, it would dial this and fail loudly.
  // It must refuse before that, because nothing resolved the channel through SDP in this session.
  const box = sandboxFor(context);
  writeFileSync(box.watchConfig, '{"address":"AA:BB:CC:DD:EE:FF"}\n', { mode: 0o600 });
  const spawned = startSidecar({
    emitHex: true,
    logger: recordingLogger().logger,
    env: box.env(),
    configPath: box.watchConfig,
  });
  try {
    await spawned.transport.ping();
    await assert.rejects(
      () => spawned.transport.open({ channel: 18 }),
      (error: { code?: string; message?: string }) => {
        assert.equal(error.code, "channel-unverified");
        assert.match(error.message ?? "", /resolved through SDP/);
        return true;
      },
    );
    assert.equal(spawned.transport.isOpen(), false);
  } finally {
    spawned.stop();
  }
});
