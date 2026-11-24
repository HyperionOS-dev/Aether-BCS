// BCS helper — Phase 2 (codec) tests: the request builders, and the scope rule that keeps them to
// handshake/auth/read only. Ids come from the Gadgetbridge sources named in src/huawei/requests.ts.
// No radio, no watch, no key material, no health data.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
// Ported from Gadgetbridge, app/src/main/java/nodomain/freeyourgadget/gadgetbridge/devices/huawei/
// packets/{DeviceConfig,AccountRelated}.java at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7:
// the service and command ids and the request shapes these tests assert.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { ACCOUNT_RELATED, DEVICE_CONFIG, KNOWN_SUPPORTED_SERVICES } from "../src/huawei/constants.ts";
import { decodeFrames } from "../src/huawei/stream.ts";
import {
  ALLOWED_REQUEST_IDS,
  authChallengeRequest,
  batteryLevelRequest,
  encodeRequest,
  isAllowedRequest,
  linkParamsRequest,
  productInfoRequest,
  sendAccountRequest,
  sendExtendedAccountRequest,
  supportedCommandsRequest,
  supportedServicesRequest,
  type HuaweiRequest,
} from "../src/huawei/requests.ts";

const ok = <T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!result.ok) throw new Error("expected success");
  return result.value;
};
const tagsOf = (request: HuaweiRequest): number[] => request.tlv.entries.map((entry) => entry.tag);

describe("requests — the handshake and read requests, decoded back", () => {
  test("linkParamsRequest: 0x01/0x01, four empty tags, unencrypted and unsliced", () => {
    const request = linkParamsRequest();
    assert.equal(request.serviceId, DEVICE_CONFIG.serviceId);
    assert.equal(request.commandId, DEVICE_CONFIG.linkParams);
    assert.deepEqual(tagsOf(request), [0x01, 0x02, 0x03, 0x04]);
    assert.equal(request.isEncrypted, false);
    assert.equal(request.isSliced, false);
    assert.equal(request.tlv.serialize().length, 8); // four tags, each with an empty value

    const frames = ok(encodeRequest(request));
    assert.equal(frames.length, 1);
    const frame = ok(decodeFrames(frames[0]))[0];
    assert.equal(frame.serviceId, 0x01);
    assert.equal(frame.commandId, 0x01);
    assert.deepEqual(frame.tlv?.serialize(), request.tlv.serialize());
  });

  test("the BR LinkParams frame is byte-for-byte upstream's four empty tags and CRC", () => {
    const [frame] = ok(encodeRequest(linkParamsRequest()));
    assert.ok(frame);
    assert.equal(frame.length, 16);
    assert.equal(Buffer.from(frame).toString("hex"), "5a000b0001010100020003000400f13b");
  });

  test("linkParamsRequest for an AW adds the sixth tag the source adds", () => {
    assert.deepEqual(tagsOf(linkParamsRequest({ deviceTypeAw: true })), [0x01, 0x02, 0x03, 0x04, 0x06]);
    assert.deepEqual(tagsOf(linkParamsRequest({ deviceTypeAw: false })), [0x01, 0x02, 0x03, 0x04]);
  });

  test("supportedServicesRequest: one 0x01 tag holding the list", () => {
    const request = supportedServicesRequest();
    assert.equal(request.commandId, DEVICE_CONFIG.supportedServices);
    assert.deepEqual(tagsOf(request), [0x01]);
    // DeviceConfig.java:129-135 lists 44 services, from 0x01 to 0x35.
    assert.equal(KNOWN_SUPPORTED_SERVICES.length, 44);
    assert.equal(KNOWN_SUPPORTED_SERVICES[0], 0x01);
    assert.equal(KNOWN_SUPPORTED_SERVICES[KNOWN_SUPPORTED_SERVICES.length - 1], 0x35);
    assert.deepEqual(request.tlv.getBytes(0x01), KNOWN_SUPPORTED_SERVICES);

    const custom = supportedServicesRequest(Uint8Array.of(0x01, 0x1a));
    assert.deepEqual(custom.tlv.getBytes(0x01), Uint8Array.of(0x01, 0x1a));
  });

  test("supportedCommandsRequest: (0x02 service, 0x03 commands) pairs inside a 0x81 wrapper", () => {
    const request = ok(
      supportedCommandsRequest([
        { service: 0x01, commands: Uint8Array.of(0x04, 0x07, 0x08) },
        { service: 0x0b, commands: Uint8Array.of(0x01) },
      ]),
    );
    assert.equal(request.commandId, DEVICE_CONFIG.supportedCommands);
    assert.deepEqual(tagsOf(request), [0x81]);

    const inner = ok(request.tlv.tryGetObject(0x81));
    assert.deepEqual(
      inner.entries.map((entry) => [entry.tag, [...entry.value]]),
      [
        [0x02, [0x01]],
        [0x03, [0x04, 0x07, 0x08]],
        [0x02, [0x0b]],
        [0x03, [0x01]],
      ],
    );

    // The wrapper survives a trip through the wire.
    const frame = ok(decodeFrames(ok(encodeRequest(request))[0]))[0];
    assert.deepEqual(frame.tlv?.serialize(), request.tlv.serialize());
  });

  test("supportedCommandsRequest refuses a list that would not fit the alignment budget", () => {
    // sliceSize 48 -> maxSize 16 -> aligned 12, so a 20-byte command list cannot go in.
    const result = supportedCommandsRequest([{ service: 0x01, commands: new Uint8Array(20) }], {
      sliceSize: 48,
    });
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.error.code, "bad-argument");
  });
});

describe("requests — the auth challenge and the remaining read requests", () => {
  test("productInfoRequest: empty tags, and the AW list is the shorter one", () => {
    const normal = productInfoRequest();
    assert.equal(normal.commandId, DEVICE_CONFIG.productInfo);
    assert.equal(tagsOf(normal).length, 16);
    assert.deepEqual(tagsOf(normal).slice(0, 3), [0x01, 0x02, 0x07]);
    assert.equal(tagsOf(normal).includes(0x23), true);
    assert.equal(normal.tlv.entries.every((entry) => entry.value.length === 0), true);

    const aw = productInfoRequest({ deviceTypeAw: true });
    assert.deepEqual(tagsOf(aw), [0x01, 0x02, 0x03, 0x07, 0x09, 0x0a, 0x0c, 0x11]);
  });

  test("authChallengeRequest: the caller's challenge and nonce, unencrypted", () => {
    const challenge = Uint8Array.of(0xca, 0xfe);
    const nonce = new Uint8Array(16).fill(0x11);
    const request = authChallengeRequest({ challenge, nonce });
    assert.equal(request.commandId, DEVICE_CONFIG.auth);
    assert.equal(request.isEncrypted, false);
    assert.deepEqual(tagsOf(request), [0x01, 0x02]);
    assert.deepEqual(request.tlv.getBytes(0x01), challenge);
    assert.deepEqual(request.tlv.getBytes(0x02), nonce);

    // The algorithm tag appears only in auth mode 2, exactly as the source has it.
    const mode2 = authChallengeRequest({ challenge, nonce, authMode: 0x02, authAlgo: 0x01 });
    assert.deepEqual(tagsOf(mode2), [0x01, 0x02, 0x03]);
    assert.deepEqual(mode2.tlv.getBytes(0x03), Uint8Array.of(0x01));
    assert.deepEqual(tagsOf(authChallengeRequest({ challenge, nonce, authMode: 0x01 })), [0x01, 0x02]);
  });

  test("batteryLevelRequest: 0x01/0x08 with one empty tag", () => {
    const request = batteryLevelRequest();
    assert.equal(request.serviceId, DEVICE_CONFIG.serviceId);
    assert.equal(request.commandId, DEVICE_CONFIG.batteryLevel);
    assert.deepEqual(tagsOf(request), [0x01]);
    assert.deepEqual(request.tlv.serialize(), Uint8Array.of(0x01, 0x00));
  });
});

describe("requests — the account handshake", () => {
  test("sendAccountRequest: the account string becomes UTF-8 bytes under tag 0x01", () => {
    const empty = sendAccountRequest("");
    assert.equal(empty.commandId, ACCOUNT_RELATED.sendAccountToDevice);
    assert.deepEqual(tagsOf(empty), [0x01]);
    assert.deepEqual(empty.tlv.serialize(), Uint8Array.of(0x01, 0x00));

    // A deliberately synthetic string: no real account value is used anywhere in these tests.
    const named = sendAccountRequest("BCS-PHASE2-TEST");
    assert.deepEqual(named.tlv.getBytes(0x01), new TextEncoder().encode("BCS-PHASE2-TEST"));
  });

  test("sendExtendedAccountRequest: 0x00 when there is no account, plus the optimisation tag", () => {
    const plain = sendExtendedAccountRequest({ account: "" });
    assert.equal(plain.commandId, ACCOUNT_RELATED.sendExtendedAccountToDevice);
    assert.deepEqual(tagsOf(plain), [0x01]);
    assert.deepEqual(plain.tlv.getBytes(0x01), Uint8Array.of(0x00));

    const optimised = sendExtendedAccountRequest({
      account: "BCS-PHASE2-TEST",
      accountPairingOptimization: true,
    });
    assert.deepEqual(tagsOf(optimised), [0x01, 0x03]);
    assert.deepEqual(optimised.tlv.getBytes(0x03), Uint8Array.of(0x01));
  });
});

describe("requests — the scope rule, asserted rather than assumed", () => {
  const builders: [string, HuaweiRequest][] = [
    ["linkParamsRequest", linkParamsRequest()],
    ["supportedServicesRequest", supportedServicesRequest()],
    [
      "supportedCommandsRequest",
      ok(supportedCommandsRequest([{ service: 0x01, commands: Uint8Array.of(0x04) }])),
    ],
    ["productInfoRequest", productInfoRequest()],
    ["authChallengeRequest", authChallengeRequest({ challenge: Uint8Array.of(1), nonce: Uint8Array.of(2) })],
    ["batteryLevelRequest", batteryLevelRequest()],
    ["sendAccountRequest", sendAccountRequest("")],
    ["sendExtendedAccountRequest", sendExtendedAccountRequest({ account: "" })],
  ];

  test("every builder in this module is on the allowed list, and they are all of them", () => {
    assert.equal(builders.length, ALLOWED_REQUEST_IDS.length);
    for (const [name, request] of builders) {
      assert.equal(isAllowedRequest(request.serviceId, request.commandId), true, name);
    }
  });

  test("write-type and key-carrying ids are refused", () => {
    // FindPhone.StopRequest is 0x0B/0x02 (FindPhone.java:47-48): a write-type command.
    assert.equal(isAllowedRequest(0x0b, 0x02), false);
    // DeviceConfig.Bond is 0x01/0x0E (DeviceConfig.java:483-484): it carries a bonding key.
    assert.equal(isAllowedRequest(0x01, 0x0e), false);
    assert.equal(isAllowedRequest(0x01, 0x0f), false); // BondParams
    assert.equal(isAllowedRequest(0x7f, 0x7f), false); // not in the list at all
  });

  test("every builder encodes and decodes back to the same ids and TLV bytes", () => {
    for (const [name, request] of builders) {
      const frames = ok(encodeRequest(request));
      const joined = Uint8Array.from(frames.flatMap((frame) => [...frame]));
      const decoded = ok(decodeFrames(joined));
      assert.equal(decoded.length, 1, name);
      assert.equal(decoded[0].serviceId, request.serviceId, name);
      assert.equal(decoded[0].commandId, request.commandId, name);
      assert.deepEqual(decoded[0].tlv?.serialize(), request.tlv.serialize(), name);
    }
  });

  test("encrypted transactions are refused until Phase 3, except where upstream sends plaintext", () => {
    // Battery level wants encryption, so with crypted transactions it cannot be built here.
    const refused = encodeRequest(batteryLevelRequest(), { transactionsCrypted: true });
    assert.equal(refused.ok, false);
    if (refused.ok) return;
    assert.equal(refused.error.code, "unsupported");

    // LinkParams is marked unencrypted upstream, so it is still sent in the clear when crypted.
    const allowed = ok(encodeRequest(linkParamsRequest(), { transactionsCrypted: true }));
    assert.equal(allowed.length, 1);
    assert.equal(allowed[0][3], 0x00); // still one unsliced frame
  });
});