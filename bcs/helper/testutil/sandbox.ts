// BCS helper — test isolation: every test that starts the sidecar, the driver or the shell wrapper
// gets a temporary HOME, so no test can read or write the user's real ~/.config/aether-bcs or
// ~/.local/state/aether-bcs.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in the directory above for attribution and privacy rules.
//
// Why this is not optional: the helper's real paths hold a watch address, an auth key and an account
// ID. A test that inherits the developer's HOME can therefore write a report next to real credentials
// — or, worse, read them. Handing each child an isolated HOME makes that impossible rather than
// unlikely, and `test/testIsolation.test.ts` fails the suite if a test spawns anything without it.
//
// Nothing here touches the network, a radio or the real configuration directory.

import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";

export interface Sandbox {
  /** The temporary root everything else lives under. Always inside `os.tmpdir()`. */
  readonly root: string;
  /** `$HOME` for the child: nothing outside this directory is reachable through it. */
  readonly home: string;
  readonly configHome: string;
  readonly stateHome: string;
  /** `~/.config/aether-bcs` inside the sandbox: where the watch address and key files go. */
  readonly configDir: string;
  /** `~/.local/state/aether-bcs` inside the sandbox: where reports and identity live. */
  readonly stateDir: string;
  readonly keyFile: string;
  readonly accountFile: string;
  readonly watchConfig: string;
  /** Environment for a child process. `extra` wins, so a test can override one value. */
  env(extra?: NodeJS.ProcessEnv): NodeJS.ProcessEnv;
  /** File names in the sandbox state directory, sorted. Empty until a child writes there. */
  stateFiles(): string[];
  /** Contents of every file in the sandbox state directory, keyed by name. */
  stateContents(): Record<string, string>;
  cleanup(): void;
}

/**
 * A throwaway HOME with the helper's config and state directories already in place, mode 0700, the
 * way a real one would be. `prefix` makes a failure easy to attribute in `os.tmpdir()`.
 */
export function createSandbox(prefix = "bcs-test"): Sandbox {
  const root = mkdtempSync(join(tmpdir(), `${prefix}-`));
  const home = join(root, "home");
  const configHome = join(home, ".config");
  const stateHome = join(home, ".local", "state");
  const configDir = join(configHome, "aether-bcs");
  const stateDir = join(stateHome, "aether-bcs");
  for (const directory of [configDir, stateDir]) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
  }

  const listIn = (directory: string): string[] => {
    if (!existsSync(directory)) return [];
    return readdirSync(directory).sort();
  };

  return {
    root,
    home,
    configHome,
    stateHome,
    configDir,
    stateDir,
    keyFile: join(configDir, "auth-key.txt"),
    accountFile: join(configDir, "account.txt"),
    watchConfig: join(configDir, "watch.json"),
    env(extra: NodeJS.ProcessEnv = {}) {
      return {
        // HOME is what Python's expanduser() and Node's homedir() both read, so the sidecar's default
        // --config path and the driver's default state directory both land inside the sandbox.
        HOME: home,
        XDG_CONFIG_HOME: configHome,
        XDG_STATE_HOME: stateHome,
        BCS_CONFIG_DIR: configDir,
        BCS_STATE_DIR: stateDir,
        BCS_AUTH_KEY_FILE: join(configDir, "auth-key.txt"),
        BCS_AUTH_ACCOUNT_FILE: join(configDir, "account.txt"),
        ...extra,
      };
    },
    stateFiles: () => listIn(stateDir),
    stateContents() {
      const contents: Record<string, string> = {};
      for (const name of listIn(stateDir)) {
        try {
          contents[name] = readFileSync(join(stateDir, name), "utf8");
        } catch {
          contents[name] = "";
        }
      }
      return contents;
    },
    cleanup() {
      rmSync(root, { recursive: true, force: true });
    },
  };
}

/**
 * The real home of the user running the suite, taken from the password database rather than `$HOME`,
 * so a test that reassigns `$HOME` still has its eye on the directory that matters.
 */
export function realHomeDirectory(userInfo: { homedir: string }): string {
  return userInfo.homedir;
}

/** The two directories a test must never touch, wherever the real home is. */
export function realHelperPaths(home: string, ambient: NodeJS.ProcessEnv = process.env): string[] {
  const configHome = ambient.XDG_CONFIG_HOME || join(home, ".config");
  const stateHome = ambient.XDG_STATE_HOME || join(home, ".local", "state");
  return [join(configHome, "aether-bcs"), join(stateHome, "aether-bcs")];
}

/** True when `path` is inside `root` (and not equal to it), used to prove a temp directory was used. */
export function isInside(path: string, root: string): boolean {
  const rest = relative(resolve(root), resolve(path));
  return rest !== "" && !rest.startsWith(`..${sep}`) && rest !== "..";
}