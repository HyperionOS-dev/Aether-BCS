// BCS helper — Phase 1 (link only): tests for masking and the logger's privacy rules. Phase 1
// writes no bytes to the watch. Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// These two modules are the reason no address or payload can reach a log line, so they are
// tested as rules rather than as helpers.

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { createLogger, scrubPayloads } from "../src/log.ts";
import { isAddress, maskAddress, maskMacText, MASKED_ADDRESS } from "../src/mask.ts";

const ADDRESS = "AA:BB:CC:DD:EE:FF";

describe("maskAddress", () => {
  test("a valid address keeps only its last two octets", () => {
    assert.equal(maskAddress(ADDRESS), "XX:XX:XX:XX:EE:FF");
    assert.equal(maskAddress("aa:bb:cc:dd:ee:ff"), "XX:XX:XX:XX:EE:FF");
  });

  test("anything unusable becomes the placeholder instead of being echoed", () => {
    for (const bad of ["", null, undefined, "AA:BB", "AA:BB:CC:DD:EE:FFF", "AA-BB-CC-DD-EE-FF", 17]) {
      assert.equal(maskAddress(bad), MASKED_ADDRESS, String(bad));
    }
  });
});

describe("isAddress", () => {
  test("six hex octets are an address", () => {
    assert.equal(isAddress(ADDRESS), true);
    assert.equal(isAddress("00:11:22:33:44:55"), true);
  });

  test("everything else is not", () => {
    for (const bad of ["", "AA:BB:CC:DD:EE", "AA:BB:CC:DD:EE:FF:00", "gg:bb:cc:dd:ee:ff", null]) {
      assert.equal(isAddress(bad), false, String(bad));
    }
  });
});

describe("maskMacText", () => {
  test("an address inside a sentence is masked in place", () => {
    assert.equal(maskMacText(`connected to ${ADDRESS} on channel 15`), "connected to XX:XX:XX:XX:EE:FF on channel 15");
  });

  test("masking twice changes nothing, so the rule can be applied at every layer", () => {
    const once = maskMacText(ADDRESS);
    assert.equal(maskMacText(once), once);
  });

  test("hex that is not an address is left alone", () => {
    const payload = "1a2b3c4d".repeat(4);
    assert.equal(maskMacText(payload), payload);
  });
});

describe("scrubPayloads", () => {
  test("a long hex run is treated as payload and removed", () => {
    const scrubbed = scrubPayloads(`frame ${"ab".repeat(20)} end`);
    assert.equal(scrubbed, "frame [bytes redacted] end");
  });

  test("a short hex run is still allowed through, so channel and version numbers survive", () => {
    assert.equal(scrubPayloads("channel 15, version 1.0"), "channel 15, version 1.0");
  });

  test("masking happens before the payload rule, so an address is never redacted whole", () => {
    assert.equal(scrubPayloads(`device ${ADDRESS}`), "device XX:XX:XX:XX:EE:FF");
  });

  test("undefined and null become text rather than throwing inside a logger", () => {
    assert.equal(scrubPayloads(undefined), "");
    assert.equal(scrubPayloads(null), "");
  });
});

describe("createLogger", () => {
  function collect(prefix = "bcs-test") {
    const lines: string[] = [];
    const logger = createLogger({ prefix, sink: (line) => lines.push(line) });
    return { logger, lines };
  }

  test("every line is prefixed and masked", () => {
    const { logger, lines } = collect();
    logger.info(`looking for ${ADDRESS}`);
    assert.equal(lines.length, 1);
    assert.match(lines[0], /^info bcs-test: looking for XX:XX:XX:XX:EE:FF$/);
    assert.equal(lines[0].includes(ADDRESS), false);
  });

  test("levels are distinguishable so a scan of the log shows what happened", () => {
    const { logger, lines } = collect();
    logger.warn("careful");
    logger.error("failed");
    assert.match(lines[0], /^warn /);
    assert.match(lines[1], /^error /);
  });

  test("bytes received are reported as a count, a channel and a time, never as content", () => {
    const { logger, lines } = collect();
    logger.bytesReceived({ bytes: 37, at: "2026-10-22T10:00:00Z", channel: 15 });
    assert.equal(lines[0], "info bcs-test: received 37 bytes on channel 15 at 2026-10-22T10:00:00Z");
  });

  test("a payload smuggled into a message is redacted before it is printed", () => {
    const { logger, lines } = collect();
    logger.info(`payload ${"deadbeef".repeat(8)}`);
    assert.equal(lines[0].includes("deadbeef"), false);
    assert.match(lines[0], /\[bytes redacted\]/);
  });

  test("without a sink the logger defaults to stdout and still masks", () => {
    const logger = createLogger();
    const printed: string[] = [];
    const original = console.log;
    console.log = (line: string) => printed.push(line);
    try {
      logger.info(`watch ${ADDRESS}`);
    } finally {
      console.log = original;
    }
    assert.equal(printed.length, 1);
    assert.equal(printed[0].includes(ADDRESS), false);
  });
});