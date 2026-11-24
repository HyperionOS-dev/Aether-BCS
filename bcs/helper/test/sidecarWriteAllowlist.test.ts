// BCS helper — Phase 3C: keep the Python write gate aligned with the TypeScript auth flow.
// No socket, process, Bluetooth, credential or device data is used.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in the helper directory for attribution and privacy rules.

import assert from "node:assert/strict";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { DEVICE_CONFIG, HUAWEI_SDP_UUID } from "../src/huawei/constants.ts";
import { isKnownErrorCode, safeSidecarErrorMessage } from "../src/sidecarProtocol.ts";
import { createSandbox } from "../testutil/sandbox.ts";
import { quietLogger } from "../tools/bcs_auth.mjs";
import { createAuthMachine } from "../src/huawei/authMachine.ts";
import { decodeFrames, type HuaweiFrame } from "../src/huawei/stream.ts";
import { HuaweiTlv } from "../src/huawei/tlv.ts";
import {
  aesGcmDecryptNoPad,
  aesGcmEncryptNoPad,
  DIGEST_SECRET_V2,
  hexToBytes,
  hexdumpUpper,
  hkdfSha256,
  hmacSha256,
  sha256,
} from "../src/huawei/crypto.ts";
import { encodeFrame } from "../src/huawei/frame.ts";
import {
  hiChainRequest,
  pincodeRequest,
  securityNegotiationRequest,
  deviceStatusRequest,
} from "../src/huawei/authPackets.ts";
import { sendAccountRequest, sendExtendedAccountRequest } from "../src/huawei/requests.ts";

const pythonSidecar = readFileSync(new URL("../sidecar/rfcomm_sidecar.py", import.meta.url), "utf8");
const pythonBluetooth = readFileSync(new URL("../sidecar/bcs_bt.py", import.meta.url), "utf8");
const pythonValidator = String.raw`
import io, json, sys
from sidecar import bcs_bt
from sidecar.rfcomm_sidecar import Emitter, Sidecar

class Socket:
    def settimeout(self, value): pass
    def sendall(self, data): pass
    def shutdown(self, how): pass
    def close(self): pass

def lookup(address, timeout=20.0):
    return bcs_bt.SdpResult("sdptool", 5, "sdptool named the record's channel", matched_uuid=True)

def socket_factory(address, channel, timeout, security="none"):
    # Phase 3G: the sidecar hands the BT_SECURITY name to the socket factory. Nothing was asked for
    # here, so the default path must still arrive as "none".
    assert security == "none", security
    return Socket()

def make_sidecar():
    return Sidecar(
        Emitter(io.StringIO()),
        address_loader=lambda path: "00:00:00:00:00:00",
        connect=socket_factory,
        reader=lambda *args, **kwargs: None,
        sdp_lookup=lookup,
    )

def connect(sidecar):
    # The sidecar connects only to a channel SDP named in this session, so resolve first.
    assert sidecar.handle_command({"id": 0, "cmd": "resolve_channel", "expect_channel": 5})["ok"]
    return sidecar.handle_command({"id": 1, "cmd": "connect", "channel": 5})

def write(sidecar, hex_frame, ident):
    return sidecar.handle_command({"id": ident, "cmd": "write", "hex": hex_frame})

source = json.load(sys.stdin)
accepted = {}
for mode, frames in source["sessions"].items():
    sidecar = make_sidecar()
    assert connect(sidecar)["ok"]
    accepted[mode] = [write(sidecar, frame, index + 2) for index, frame in enumerate(frames)]

base = bytes.fromhex(source["base"])
bad_crc = bytearray(base)
bad_crc[-1] ^= 1
bad_length = bytearray(base)
bad_length[2] ^= 1
bad_magic = bytearray(base)
bad_magic[0] ^= 1
negative_frames = {
    "bad_crc": bad_crc.hex(),
    "wrong_length": bad_length.hex(),
    "bad_magic": bad_magic.hex(),
    "non_allowlisted": source["nonAllowlisted"],
    "middle_without_first": source["middleWithoutFirst"],
}
refused = {}
for name, frame in negative_frames.items():
    sidecar = make_sidecar()
    assert connect(sidecar)["ok"]
    refused[name] = write(sidecar, frame, 2)

sidecar = make_sidecar()
assert connect(sidecar)["ok"]
over_budget = [write(sidecar, source["base"], index + 2) for index in range(65)]
print(json.dumps({"accepted": accepted, "refused": refused, "overBudget": over_budget}))
`;

type Result<T> = { ok: true; value: T } | { ok: false; error: unknown };
function value<T>(result: Result<T>): T {
  assert.equal(result.ok, true);
  if (!result.ok) throw new Error("synthetic auth flow failed");
  return result.value;
}

const concat = (...parts: Uint8Array[]) => {
  const output = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
};

const authKey = Uint8Array.from({ length: 32 }, (_, index) => index);
const androidId = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
const watchSalt = Uint8Array.from({ length: 16 }, (_, index) => 0xa0 + index);
const watchAuthId = new TextEncoder().encode("fedcba9876543210fedcba9876543210");
const requestId = 1730000000000n;
const asHex = (value: Uint8Array) => hexdumpUpper(value);
const fromHex = (value: string) => {
  const decoded = hexToBytes(value);
  assert.equal(decoded.ok, true);
  if (!decoded.ok) throw new Error("synthetic auth payload was not hex");
  return decoded.value;
};

function frameOf(output: Uint8Array[]): HuaweiFrame {
  const decoded = value(decodeFrames(concat(...output)));
  assert.equal(decoded.length, 1);
  return decoded[0];
}

function payloadOf(frame: HuaweiFrame): Record<string, unknown> {
  const json = frame.tlv?.tryGetString(0x01);
  assert.ok(json?.ok);
  return (JSON.parse(json.value) as { payload: Record<string, unknown> }).payload;
}

function response(serviceId: number, commandId: number, tlv: HuaweiTlv): HuaweiFrame {
  return {
    serviceId,
    commandId,
    tlv,
    payload: new Uint8Array(0),
    encryptedEnvelope: false,
    sliceType: 0,
    sliceFlags: [],
    sliceCount: 1,
  };
}

function hiReply(payload: Record<string, unknown>, raw = false): HuaweiFrame {
  const tlv = raw
    ? new HuaweiTlv().putByte(0x04, 0x01).putString(0x01, "ok")
    : new HuaweiTlv().putByte(0x04, 0x00).putString(0x01, JSON.stringify({ payload }));
  return response(DEVICE_CONFIG.serviceId, DEVICE_CONFIG.hiChain, tlv);
}

function authFrames(mode: "bind" | "auth-then-bind"): Uint8Array[] {
  let randomCall = 0;
  const machine = createAuthMachine({
    key: authKey,
    androidId,
    mode,
    random: (size) => {
      randomCall += 1;
      return Uint8Array.from({ length: size }, (_, index) => (randomCall * 0x11 + index * 7) & 0xff);
    },
    requestId: () => requestId,
  });
  const frames: Uint8Array[] = [];
  const capture = (result: Result<{ out: Uint8Array[] }>) => {
    const output = value(result);
    frames.push(...output.out);
    return output.out;
  };
  const linkTlv = new HuaweiTlv()
    .putByte(0x01, 0x02)
    .putShort(0x02, 0x00f4)
    .putShort(0x03, 0x0014)
    .putShort(0x04, 0)
    .putBytes(0x05, Uint8Array.of(0, 2, ...watchSalt))
    .putByte(0x07, 0x04)
    .putByte(0x08, 0)
    .putByte(0x09, 0)
    .putByte(0x0c, 1);

  capture(machine.start());
  capture(machine.onFrame(response(DEVICE_CONFIG.serviceId, DEVICE_CONFIG.linkParams, linkTlv)));
  capture(machine.onFrame(response(DEVICE_CONFIG.serviceId, DEVICE_CONFIG.deviceStatus, new HuaweiTlv().putByte(1, 1))));
  const afterNegotiation = capture(machine.onFrame(
    response(DEVICE_CONFIG.serviceId, DEVICE_CONFIG.securityNegotiation, new HuaweiTlv().putByte(1, 1)),
  ));

  let pin = new TextEncoder().encode("123456");
  if (mode === "auth-then-bind") {
    assert.equal(frameOf(afterNegotiation).commandId, DEVICE_CONFIG.pinCode);
    const iv = watchSalt;
    const encryptedPin = value(aesGcmEncryptNoPad(pin, DIGEST_SECRET_V2, iv, null));
    const authStep1 = capture(machine.onFrame(response(
      DEVICE_CONFIG.serviceId,
      DEVICE_CONFIG.pinCode,
      new HuaweiTlv().putBytes(1, encryptedPin).putBytes(2, iv),
    )));
    const authStep1Frame = frameOf(authStep1);
    const authStep1Payload = payloadOf(authStep1Frame);
    const authSeed = fromHex(authStep1Payload.seed as string);
    const authRandSelf = fromHex(authStep1Payload.isoSalt as string);
    const authPsk = hmacSha256(sha256(new TextEncoder().encode(asHex(pin))), authSeed);
    const authStep2 = capture(machine.onFrame(hiReply({
      isoSalt: asHex(watchSalt),
      peerAuthId: asHex(watchAuthId),
      peerUserType: 0,
      token: asHex(hmacSha256(authPsk, concat(watchSalt, authRandSelf, androidId, watchAuthId))),
    })));
    const authSessionKey = value(hkdfSha256(
      authPsk,
      concat(authRandSelf, watchSalt),
      new TextEncoder().encode("hichain_iso_session_key"),
      32,
    ));
    const authStep3 = capture(machine.onFrame(hiReply({
      returnCodeMac: asHex(hmacSha256(authPsk, Uint8Array.of(0, 0, 0, 0))),
    })));
    const authStep3Payload = payloadOf(frameOf(authStep3));
    const challenge = value(aesGcmDecryptNoPad(
      fromHex(authStep3Payload.encData as string),
      authSessionKey,
      fromHex(authStep3Payload.nonce as string),
      new TextEncoder().encode("hichain_iso_exchange"),
    ));
    const authToken = Uint8Array.from({ length: 32 }, (_, index) => 0x80 + index);
    const deviceNonce = Uint8Array.from({ length: 12 }, (_, index) => 0x30 + index);
    const encryptedToken = value(aesGcmEncryptNoPad(authToken, authSessionKey, deviceNonce, challenge));
    const authStep4 = capture(machine.onFrame(hiReply({
      nonce: asHex(deviceNonce),
      encAuthToken: asHex(encryptedToken),
    })));
    void authStep2;
    void authStep4;
    pin.fill(0);

    const bindStep1 = capture(machine.onFrame(hiReply({}, true)));
    const bindStep1Payload = payloadOf(frameOf(bindStep1));
    const bindSeed = fromHex(bindStep1Payload.seed as string);
    const bindRandSelf = fromHex(bindStep1Payload.isoSalt as string);
    const bindPsk = hmacSha256(authToken, bindSeed);
    capture(machine.onFrame(hiReply({
      isoSalt: asHex(watchSalt),
      peerAuthId: asHex(watchAuthId),
      peerUserType: 0,
      token: asHex(hmacSha256(bindPsk, concat(watchSalt, bindRandSelf, androidId, watchAuthId))),
    })));
    capture(machine.onFrame(hiReply({
      returnCodeMac: asHex(hmacSha256(bindPsk, Uint8Array.of(0, 0, 0, 0))),
    })));
    capture(machine.onFrame(hiReply({}, true)));
  } else {
    const bindStep1Frame = frameOf(afterNegotiation);
    const bindPayload = payloadOf(bindStep1Frame);
    const bindSeed = fromHex(bindPayload.seed as string);
    const bindRandSelf = fromHex(bindPayload.isoSalt as string);
    const bindPsk = hmacSha256(authKey, bindSeed);
    const bindStep2 = capture(machine.onFrame(hiReply({
      isoSalt: asHex(watchSalt),
      peerAuthId: asHex(watchAuthId),
      peerUserType: 0,
      token: asHex(hmacSha256(bindPsk, concat(watchSalt, bindRandSelf, androidId, watchAuthId))),
    })));
    void bindStep2;
    capture(machine.onFrame(hiReply({
      returnCodeMac: asHex(hmacSha256(bindPsk, Uint8Array.of(0, 0, 0, 0))),
    })));
    capture(machine.onFrame(hiReply({}, true)));
  }
  machine.destroy();
  return frames;
}

function authFlowPairs(): [number, number][] {
  const hiChain = hiChainRequest({
    operationCode: 0x02,
    requestId: 1n,
    androidId: new Uint8Array(16),
    step: 1,
    randSelf: new Uint8Array(16),
    seed: new Uint8Array(32),
  });
  assert.equal(hiChain.ok, true);
  if (!hiChain.ok) throw new Error("the synthetic HiChain request did not build");
  // A deliberately synthetic value: no real account is used anywhere in these tests.
  const syntheticAccount = "BCS-PHASE3E-TEST";
  const requests = [
    { serviceId: DEVICE_CONFIG.serviceId, commandId: DEVICE_CONFIG.linkParams },
    deviceStatusRequest(),
    securityNegotiationRequest({ authMode: 0x02, deviceUuid: new Uint8Array(16), phoneModel: "", encryptMethod: 0 }),
    pincodeRequest(),
    hiChain.value,
    sendAccountRequest(syntheticAccount),
    sendExtendedAccountRequest({ account: syntheticAccount }),
  ];
  return [...new Map(requests.map(({ serviceId, commandId }) => [`${serviceId}:${commandId}`, [serviceId, commandId] as [number, number]])).values()];
}

describe("sidecar write allowlist", () => {
  test("Python's exact service/command pairs match the TypeScript auth flow", () => {
    const declaration = pythonSidecar.match(/WRITE_ALLOWLIST\s*=\s*frozenset\(\s*\{([\s\S]*?)\}\s*\)/);
    assert.ok(declaration, "Python WRITE_ALLOWLIST declaration was not found");
    const pythonPairs = [...declaration[1].matchAll(/\(\s*(0x[\da-f]+)\s*,\s*(0x[\da-f]+)\s*\)/gi)].map(
      ([, service, command]) => [Number(service), Number(command)] as [number, number],
    );
    const sortPairs = (pairs: [number, number][]) => pairs.sort(([leftService, leftCommand], [rightService, rightCommand]) =>
      leftService - rightService || leftCommand - rightCommand,
    );
    assert.deepEqual(sortPairs(pythonPairs), sortPairs(authFlowPairs()));
  });

  test("real TypeScript machine frames in both modes pass the Python validator and invalid variants refuse", () => {
    const sessions = {
      bind: authFrames("bind").map((frame) => hexdumpUpper(frame)),
      "auth-then-bind": authFrames("auth-then-bind").map((frame) => hexdumpUpper(frame)),
    };
    const base = fromHex(sessions.bind[0]);
    const middle = Object.values(sessions).flat().map(fromHex).find((frame) => frame[3] === 0x02);
    assert.ok(middle, "the deterministic auth flows should contain a middle slice");
    const disallowed = value(encodeFrame({
      serviceId: DEVICE_CONFIG.serviceId,
      commandId: DEVICE_CONFIG.dateFormat,
      tlv: new HuaweiTlv().putEmpty(1),
      sliced: false,
      isEncrypted: false,
    }))[0];
    const helperDirectory = fileURLToPath(new URL("../", import.meta.url));
    const result = spawnSync("python3", ["-c", pythonValidator], {
      cwd: helperDirectory,
      encoding: "utf8",
      input: JSON.stringify({
        sessions,
        base: sessions.bind[0],
        nonAllowlisted: hexdumpUpper(disallowed),
        middleWithoutFirst: hexdumpUpper(middle),
      }),
    });
    assert.equal(result.status, 0, result.stderr);
    const checked = JSON.parse(result.stdout) as {
      accepted: Record<string, { ok: boolean; code?: string }[]>;
      refused: Record<string, { ok: boolean; code?: string }>;
      overBudget: { ok: boolean; code?: string }[];
    };
    assert.deepEqual(Object.keys(checked.accepted).sort(), ["auth-then-bind", "bind"]);
    for (const [mode, frames] of Object.entries(checked.accepted)) {
      assert.ok(frames.length > 0, `${mode} emitted no frames`);
      assert.equal(frames.every((frame) => frame.ok), true, `${mode} emitted a frame Python refused`);
    }
    assert.deepEqual(Object.keys(checked.refused).sort(), [
      "bad_crc",
      "bad_magic",
      "middle_without_first",
      "non_allowlisted",
      "wrong_length",
    ]);
    for (const [name, frame] of Object.entries(checked.refused)) {
      assert.equal(frame.ok, false, `${name} unexpectedly passed`);
      assert.equal(frame.code, "write-refused", name);
    }
    assert.equal(checked.overBudget.length, 65);
    assert.equal(checked.overBudget.slice(0, 64).every((frame) => frame.ok), true);
    assert.deepEqual(checked.overBudget[64], { id: 66, ok: false, code: "write-refused", error: "write budget for this connection is exhausted", errno: null });
  });

  test("the driver's quiet logger uses createLogger's address and payload scrubber", () => {
    const privateHex = "aabbccddeeff00112233445566778899";
    const original = process.stderr.write;
    let output = "";
    process.stderr.write = ((chunk: string | Uint8Array) => {
      output += chunk.toString();
      return true;
    }) as typeof process.stderr.write;
    try {
      quietLogger().info(`synthetic ${privateHex} from AA:BB:CC:DD:EE:FF`);
    } finally {
      process.stderr.write = original;
    }
    assert.equal(output.includes(privateHex), false);
    assert.equal(output.includes("AA:BB:CC:DD:EE:FF"), false);
    assert.match(output, /\[bytes redacted\]/);
    assert.match(output, /XX:XX:XX:XX:EE:FF/);
  });

  test("direct driver invocation without /dev/tty stops before reading the key or spawning Python", () => {
    const box = createSandbox("bcs-driver-gate");
    try {
      const directory = box.root;
      const keyFile = box.keyFile;
      const sidecarMarker = join(directory, "sidecar-started");
      const pythonStub = join(directory, "python3");
      const syntheticKey = "a1b2c3d4";
      writeFileSync(pythonStub, "#!/bin/sh\n: > \"$BCS_TEST_SIDECAR_MARKER\"\n");
      chmodSync(pythonStub, 0o700);
      const driver = fileURLToPath(new URL("../tools/bcs_auth.mjs", import.meta.url));
      const result = spawnSync(process.execPath, [driver], {
        detached: true,
        encoding: "utf8",
        env: {
          ...process.env,
          // A temporary HOME, so the driver's state directory is inside the sandbox: a test that
          // inherited the developer's own home could write next to a real key file.
          ...box.env(),
          PATH: `${directory}:${process.env.PATH}`,
          BCS_TEST_SIDECAR_MARKER: sidecarMarker,
        },
      });
      const output = `${result.stdout}${result.stderr}`;
      assert.equal(result.status, 2, output);
      assert.match(output, /interactive terminal/);
      assert.equal(output.includes("cannot read the auth key file"), false);
      assert.equal(output.includes(syntheticKey), false);
      assert.equal(existsSync(keyFile), false);
      assert.equal(existsSync(sidecarMarker), false);
      // Nothing reached the sandbox state directory either: the run stopped at the gate.
      assert.deepEqual(box.stateFiles(), []);
    } finally {
      box.cleanup();
    }
  });
});

describe("the SDP channel gate stays aligned with the Python side", () => {
  test("the sidecar advertises every capability the driver gates on", () => {
    const declaration = pythonSidecar.match(/CAPABILITIES\s*=\s*\(([^)]*)\)/);
    assert.ok(declaration, "Python CAPABILITIES declaration was not found");
    const advertised = [...declaration[1].matchAll(/"([a-z_]+)"/g)].map(([, name]) => name).sort();
    assert.deepEqual(advertised, ["connect", "resolve", "write"]);
    // The driver refuses to run without these two: "write" for the frames, "resolve" for the channel.
    for (const needed of ["write", "resolve"]) {
      assert.equal(advertised.includes(needed), true, `the sidecar no longer advertises ${needed}`);
    }
  });

  test("the Huawei SDP UUID is the same value on both sides", () => {
    const python = pythonBluetooth.match(/HUAWEI_SDP_UUID\s*=\s*"([0-9a-fA-F-]+)"/);
    assert.ok(python, "Python HUAWEI_SDP_UUID was not found");
    const normalize = (value: string) => value.toLowerCase().replace(/-/g, "");
    assert.equal(normalize(python[1]), normalize(HUAWEI_SDP_UUID));
  });

  test("every SDP refusal code is a code this side knows, with a sentence of its own", () => {
    const codes = [...new Set([...pythonBluetooth.matchAll(/"(sdp-[a-z-]+)"/g)].map(([, code]) => code))].sort();
    assert.deepEqual(codes, ["sdp-disagreement", "sdp-no-channel", "sdp-unavailable", "sdp-unconfirmed"]);
    const unknownSentence = safeSidecarErrorMessage("not-a-real-code");
    for (const code of codes) {
      assert.equal(isKnownErrorCode(code), true, `${code} is missing from BcsErrorCode`);
      const message = safeSidecarErrorMessage(code);
      assert.notEqual(message, unknownSentence, `${code} has no message of its own`);
      assert.match(message, /SDP/, `${code} should say what SDP did`);
    }
  });

  test("the sidecar's channel gate and the driver's refusal use one code", () => {
    assert.match(pythonSidecar, /"channel-unverified"/);
    assert.equal(isKnownErrorCode("channel-unverified"), true);
    const message = safeSidecarErrorMessage("channel-unverified");
    assert.match(message, /resolved through SDP/);
  });
});