// BCS helper — the run journal: stage tracking and the byte/frame counts a failed run needs.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in the directory above for attribution and privacy rules.
//
// Pure counting: no socket, no clock, no file. These tests are what make the report's wording a
// checked contract rather than a comment — the first live bind could say "timeout" and nothing else,
// which is exactly the ambiguity this module exists to remove.

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { createRunJournal } from "../src/runJournal.ts";

describe("run journal stages", () => {
  test("a fresh journal is at the start and has counted nothing", () => {
    const journal = createRunJournal();
    assert.equal(journal.stage, "start");
    assert.deepEqual(journal.stages, []);
    assert.deepEqual(journal.counts, { bytesReceived: 0, framesReceived: 0, bytesWritten: 0, framesWritten: 0 });
  });

  test("stages are recorded in order, and repeating one does not duplicate it", () => {
    const journal = createRunJournal();
    journal.reached("sdp");
    journal.reached("sdp");
    journal.reached("link-open");
    journal.reached("link-params");
    assert.equal(journal.stage, "link-params");
    assert.deepEqual(journal.stages, ["sdp", "link-open", "link-params"]);
  });

  test("an empty or blank stage name is ignored rather than recorded", () => {
    const journal = createRunJournal();
    journal.reached("ping");
    journal.reached("");
    journal.reached("   ");
    assert.deepEqual(journal.stages, ["ping"]);
  });
});

describe("run journal counts", () => {
  test("bytes and frames are counted separately, so a partial read is visible", () => {
    const journal = createRunJournal();
    journal.data(5);
    journal.data(7);
    assert.equal(journal.counts.bytesReceived, 12);
    assert.equal(journal.counts.framesReceived, 0);
    journal.frame();
    assert.deepEqual(journal.counts, { bytesReceived: 12, framesReceived: 1, bytesWritten: 0, framesWritten: 0 });
  });

  test("writes count frames and bytes, and a nonsense size does not corrupt the byte total", () => {
    const journal = createRunJournal();
    journal.written(16);
    journal.written(Number.NaN);
    journal.written(-4);
    assert.deepEqual(journal.counts, { bytesReceived: 0, framesReceived: 0, bytesWritten: 16, framesWritten: 3 });
  });

  test("a data event of zero or negative bytes is not a byte received", () => {
    const journal = createRunJournal();
    journal.data(0);
    journal.data(-1);
    journal.data(Number.NaN);
    assert.equal(journal.counts.bytesReceived, 0);
  });
});

describe("run journal silence: the three different failures", () => {
  test("nothing received at all is reported as silence after an open link", () => {
    const journal = createRunJournal();
    journal.reached("link-params");
    const line = journal.silence("link-params", 5_000);
    assert.match(line, /^timeout: no bytes received in 5000ms while waiting for link-params/);
    assert.match(line, /the watch said nothing at all/);
  });

  test("bytes that never formed a frame are reported as bytes, not as silence", () => {
    const journal = createRunJournal();
    journal.data(3);
    const line = journal.silence("device-status", 5_000);
    assert.match(line, /3 byte\(s\) arrived/);
    assert.match(line, /never formed a frame/);
    assert.equal(line.includes("no bytes received"), false);
  });

  test("frames that were not the reply are reported with both counts", () => {
    const journal = createRunJournal();
    journal.data(40);
    journal.frame();
    journal.frame();
    const line = journal.silence("hichain-step-2", 30_000);
    assert.match(line, /2 frame\(s\) \(40 bytes\) arrived in 30000ms while waiting for hichain-step-2/);
    assert.match(line, /none of them was the reply this step needs/);
    assert.equal(line.includes("no bytes received"), false);
    assert.equal(line.includes("never formed a frame"), false);
  });

  test("the silence sentence names the state, so the journal agrees with the report", () => {
    const journal = createRunJournal();
    journal.reached("security-negotiation");
    assert.match(journal.silence(journal.stage, 5_000), /while waiting for security-negotiation/);
  });
});

describe("run journal report lines", () => {
  test("the lines carry the stage reached, the trail and the counts", () => {
    const journal = createRunJournal();
    journal.reached("sdp");
    journal.reached("link-open");
    journal.reached("link-params");
    journal.data(16);
    journal.frame();
    journal.written(16);
    assert.deepEqual(journal.lines(), [
      "stage: link-params (after: sdp -> link-open -> link-params)",
      "bytes received: 16",
      "frames received: 1",
      "frames written: 1 (16 bytes)",
    ]);
  });

  test("a run that stopped before any stage reports start, without an empty trail", () => {
    const journal = createRunJournal();
    assert.deepEqual(journal.lines(), [
      "stage: start",
      "bytes received: 0",
      "frames received: 0",
      "frames written: 0 (0 bytes)",
    ]);
  });

  test("a stage name that somehow carried an address is masked before it is reported", () => {
    const journal = createRunJournal();
    journal.reached("lost AA:BB:CC:DD:EE:FF");
    const text = journal.lines().join("\n");
    assert.equal(text.includes("AA:BB:CC:DD:EE:FF"), false);
    assert.match(text, /XX:XX:XX:XX:EE:FF/);
  });
});