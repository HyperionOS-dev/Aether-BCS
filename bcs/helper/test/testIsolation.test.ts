// BCS helper — test isolation: no test may touch the user's real ~/.config/aether-bcs or
// ~/.local/state/aether-bcs, and this file is what fails the suite if one tries.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in the directory above for attribution and privacy rules.
//
// Two checks, because either one alone is easy to slip past:
//
//   1. a structural one — every test file that starts the sidecar, the driver or the shell wrapper
//      must import testutil/sandbox.ts, which is the only thing that sets HOME for a child. A new
//      test that runs a child without it fails here, by name, before it can write anything.
//   2. a runtime one — the real directories are fingerprinted before and after a sandboxed sidecar
//      and a sandboxed `bcs_auth.sh --plan`, and must be identical. The fingerprint is taken from
//      the password database's home directory rather than `$HOME`, so a test that reassigns `$HOME`
//      cannot make this check look at the wrong directory.
//
// Nothing here starts a radio: the sidecar is only pinged, and the wrapper runs --plan.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { spawnSidecar } from "../src/sidecarProcess.ts";
import { createSandbox, isInside, realHelperPaths } from "../testutil/sandbox.ts";

const TEST_DIR = fileURLToPath(new URL(".", import.meta.url));
const HELPER_DIR = fileURLToPath(new URL("../", import.meta.url));

/** Markers that mean "this test file starts something that has its own HOME". */
const CHILD_MARKERS = [
  /spawnSidecar\(/,
  /spawnSync\(/,
  /spawn\(/,
  /from "node:child_process"/,
  /bcs_auth\.(?:mjs|sh)/,
  /rfcomm_sidecar\.py/,
];

/** Code only: a comment that mentions spawn() is prose, not a child process. */
function codeOnly(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

function testFileNames(): string[] {
  return readdirSync(TEST_DIR)
    .filter((name) => name.endsWith(".test.ts"))
    .sort();
}

/** `path -> signature` for a directory: names, mtimes and sizes. Missing directories are recorded. */
function fingerprint(paths: string[]): Map<string, string> {
  const print = new Map<string, string>();
  for (const path of paths) {
    let signature = "missing";
    try {
      signature = readdirSync(path)
        .sort()
        .map((name) => {
          try {
            const stats = statSync(join(path, name));
            return `${name}:${String(stats.size)}:${String(stats.mtimeMs)}`;
          } catch {
            return `${name}:unreadable`;
          }
        })
        .join("|");
      if (signature === "") signature = "empty";
    } catch {
      signature = "missing";
    }
    print.set(path, signature);
  }
  return print;
}

test("every test that starts a child process takes its HOME from the sandbox", () => {
  const offenders: string[] = [];
  for (const name of testFileNames()) {
    // The guard's own file is exempt: it sets its environment by hand, on purpose.
    if (name === "testIsolation.test.ts") continue;
    const source = codeOnly(readFileSync(join(TEST_DIR, name), "utf8"));
    if (!CHILD_MARKERS.some((marker) => marker.test(source))) continue;
    if (!/from "\.\.\/testutil\/sandbox\.ts"/.test(source)) offenders.push(name);
  }
  assert.deepEqual(
    offenders,
    [],
    "these test files start a child process without testutil/sandbox.ts, so they can read or write " +
      `the real config and state directories: ${offenders.join(", ")}`,
  );
});

test("the sandbox is a temporary directory with the helper's own layout inside it", () => {
  const box = createSandbox("bcs-isolation-shape");
  try {
    assert.equal(isInside(box.root, tmpdir()), true, "a sandbox must live under the temp directory");
    assert.equal(isInside(box.home, box.root), true);
    assert.equal(isInside(box.configDir, box.root), true);
    assert.equal(isInside(box.stateDir, box.root), true);
    assert.equal(isInside(box.keyFile, box.configDir), true);
    const env = box.env();
    assert.equal(env.HOME, box.home);
    assert.equal(env.BCS_STATE_DIR, box.stateDir);
    assert.equal(env.BCS_AUTH_KEY_FILE, box.keyFile);
    // `extra` wins, so a test can point one value elsewhere without losing the rest.
    const moved = join(box.root, "elsewhere");
    assert.equal(box.env({ BCS_STATE_DIR: moved }).BCS_STATE_DIR, moved);
  } finally {
    box.cleanup();
  }
});

test("the fingerprint really notices a change, so the checks below are not vacuous", () => {
  const box = createSandbox("bcs-isolation-control");
  try {
    const paths = [box.stateDir];
    const before = fingerprint(paths);
    writeFileSync(join(box.stateDir, "auth-report-20260101T000000Z-1.txt"), "x");
    assert.notDeepEqual(fingerprint(paths), before, "the fingerprint missed a new file");
  } finally {
    box.cleanup();
  }
});

test("the real config and state directories are unchanged by a sandboxed sidecar", async (context) => {
  const realPaths = realHelperPaths(userInfo().homedir);
  const before = fingerprint(realPaths);
  const box = createSandbox("bcs-isolation-sidecar");
  context.after(() => box.cleanup());

  const spawned = spawnSidecar({
    scriptPath: fileURLToPath(new URL("../sidecar/rfcomm_sidecar.py", import.meta.url)),
    emitHex: true,
    requestTimeoutMs: 30_000,
    logger: { info: () => {}, warn: () => {}, error: () => {}, bytesReceived: () => {} },
    env: box.env(),
  });
  try {
    assert.deepEqual(await spawned.transport.ping(), ["connect", "write", "resolve"]);
    // The child really ran and it read the sandbox: its default config path is under the sandbox
    // home, so a resolve stops at no-config instead of finding a real watch address.
    await assert.rejects(
      () => spawned.transport.resolveChannel({ expectChannel: 18 }),
      (error: { code?: string }) => {
        assert.equal(error.code, "no-config");
        return true;
      },
    );
  } finally {
    spawned.stop();
  }

  assert.deepEqual(
    fingerprint(realPaths),
    before,
    `a sandboxed sidecar changed the real directories ${realPaths.join(" and ")}`,
  );
});

test("the real config and state directories are unchanged by a sandboxed bcs_auth.sh --plan", () => {
  const realPaths = realHelperPaths(userInfo().homedir);
  const before = fingerprint(realPaths);
  const box = createSandbox("bcs-isolation-plan");
  try {
    const result = spawnSync("bash", [join(HELPER_DIR, "tools", "bcs_auth.sh"), "--plan"], {
      cwd: HELPER_DIR,
      encoding: "utf8",
      env: { ...process.env, ...box.env() },
      timeout: 120_000,
    });
    const output = `${result.stdout}${result.stderr}`;
    assert.equal(result.status, 0, output);
    // --plan has to describe the SDP gate and the per-run files, or the offline reading of a live run
    // no longer matches what that run does.
    assert.match(output, /resolve the RFCOMM channel through SDP/);
    assert.match(output, /never used instead/);
    assert.match(output, /auth-report-/);
    // Nothing was written anywhere: --plan touches nothing by design.
    assert.deepEqual(box.stateFiles(), []);
    assert.deepEqual(
      fingerprint(realPaths),
      before,
      `a sandboxed --plan changed the real directories ${realPaths.join(" and ")}`,
    );
  } finally {
    box.cleanup();
  }
});