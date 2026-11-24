# BCS Phase 2 — the Huawei packet codec

Phase 2 of the Butterfly Connectivity System, as planned in `docs/BCS_PHASE0.md`. Phase 1 opened a
classic-Bluetooth RFCOMM link to the watch; **Phase 2 is the wire format itself**, in pure code, with
no radio attached to any of it. Deliverable: `bcs/helper/src/huawei/` plus its tests.

Status: **complete and green — 225 TypeScript tests and 93 Python tests, zero failures**, of which
144 TypeScript tests are new in this phase. Nothing in `src/huawei/` opens a socket, starts a process,
sets a timer, reads a file, or holds a key.

## 1. What Phase 2 had to produce

1. A byte-exact codec for the frames the watch speaks: magic, length, slice byte, service and command
   ids, TLV payload, checksum.
2. A reassembler, because RFCOMM hands over arbitrary chunk boundaries — half a frame, two frames, a
   slice in the middle of another.
3. A **read** path for everything, so Phase 4 can decode any frame the watch sends, and a **write**
   path for only the handshake, the auth challenge and the read requests this project may legitimately
   send.
4. Typed errors, never exceptions: a codec fed a live stream will meet garbage, and garbage must
   become an error value, not a crash.
5. Verification against **upstream's own test vectors** — not against expectations re-derived from the
   code being tested — plus an independent check of the checksum, because "it round-trips" proves only
   that encoder and decoder agree with each other, not that either matches the watch.

Phase 2 does **not** authenticate, does **not** decrypt anything, holds **no key**, reads **no** auth
code, cookie or preference file, and sends **nothing** to any device. Those are Phase 3 and later.

## 2. Files added

Under `bcs/helper/`. Line counts include the file-level attribution headers.

| File | Lines | Tests | What it is |
|---|---:|---:|---|
| `src/huawei/errors.ts` | 78 | — | The typed error taxonomy (`bad-magic`, `bad-length`, `bad-crc`, `truncated`, `bad-tlv`, `missing-tag`, `bad-value`, `bad-argument`, `unsupported`) and the `CodecResult` union every byte-in entry point returns |
| `src/huawei/crc16.ts` | 50 | 9 | The frame checksum: CRC-16/XMODEM, seed 0x0000, table-free bitwise, plus a byte-level variant that takes a seed |
| `src/huawei/varint.ts` | 90 | 20 | The 7-bit VarInt that encodes TLV lengths, read and write, with a hard byte cap |
| `src/huawei/tlv.ts` | 449 | 45 | `HuaweiTlv`: build, parse, nested TLVs, and the whole typed reader set |
| `src/huawei/constants.ts` | 101 | — | The protocol numbers this phase actually uses, each with its upstream file and line |
| `src/huawei/frame.ts` | 312 | 25 | Frame encode and decode, unsliced and sliced |
| `src/huawei/stream.ts` | 172 | 31 | Reassembly: partial frames, several frames per chunk, slices, a bounded buffer |
| `src/huawei/requests.ts` | 235 | 14 | The eight request builders, plus `ALLOWED_REQUEST_IDS` / `isAllowedRequest()` |
| `src/huawei/index.ts` | 84 | — | The barrel: one import surface for the codec |
| `test/huaweiCrc16.test.ts` | 94 | 9 | |
| `test/huaweiVarInt.test.ts` | 135 | 20 | |
| `test/huaweiTlv.test.ts` | 340 | 45 | |
| `test/huaweiFrame.test.ts` | 347 | 25 | |
| `test/huaweiStream.test.ts` | 274 | 31 | |
| `test/huaweiRequests.test.ts` | 230 | 14 | |

**1571 lines of codec, 1420 lines of tests, 144 tests.** No dependency was added: Node 26 strips
TypeScript itself, so `node --test` runs the `.ts` files directly, and the helper still installs
nothing.

`bcs/helper/package.json` gained `test:codec` (the codec tests alone) and its version moved to
`0.2.0-phase2`; `bcs/helper/README.md` gained a Phase 2 section.


## 3. The wire format, as implemented

`src/huawei/frame.ts` carries the layout at the top of the file, with the upstream line number for
each field — this is the paragraph the code is written to:

```
  0      magic 0x5A
  1-2    length = (2 + tlvLength) + 1, i.e. payload + 1          HuaweiPacket.java:836
  3      slice byte, 0x00 for unsliced                           :837
  4      service id, 5 command id, then the TLV bytes            :838-840
  n-2,n-1 CRC16 over bytes 0..n-3, seeded 0x0000                 :841-844
```

Total frame length is `length + 5` in both sliced and unsliced form, which a reader can check before
parsing anything. A **sliced** frame keeps that header, sets the slice byte to 0x01 (first), 0x02
(middle) or 0x03 (last), and inserts one extra flag byte at index 4 — a counter from 0. Only the
first slice carries the service and command ids (HuaweiPacket.java:799-804); the content is
concatenated across slices until the 0x03 slice completes the packet. The defaults the code carries
are `DEFAULT_SLICE_SIZE = 0xf4` (244), `DEFAULT_MTU = 0xffff` and `PACKET_MINIMAL_SIZE = 3`; a small
table of `NON_TLV_PACKETS` plus `isNonTlvPacket()` covers the frames whose body is not a TLV at all.

Inside the frame, the payload is a TLV: a tag byte, a 7-bit VarInt length, then the value, with
nested TLVs allowed. `tlv.ts` builds and parses them and offers the typed readers upstream has, which
is what the later sync phase will use to pull the sleep samples out.

The constants this phase needs live in one file and every one of them names its upstream line:
`HUAWEI_MAGIC` 0x5A, `PROTOCOL_VERSION` 0x02, `TAG_RESULT` 0x7F, `RESULT_SUCCESS` `00 01 86 A0`
(= `RESULT_SUCCESS_INT` 0x186A0), the crypto envelope tags 0x7C/0x7D/0x7E (recognised, never
decrypted), service `0x01` device-config with its commands (link params 0x01, supported services
0x02, supported commands 0x03, date format 0x04, time 0x05, product info 0x07, battery 0x08, battery
change 0x27, auth 0x13, bond 0x0E, bond params 0x0F), service `0x1A` account (0x01, 0x05), service
`0x0B` find-phone (0x01, 0x02), and the 44 known service ids a modern device is asked about.

**Eight request builders exist**: `linkParamsRequest`, `supportedServicesRequest`,
`supportedCommandsRequest`, `productInfoRequest`, `authChallengeRequest`, `batteryLevelRequest`,
`sendAccountRequest`, `sendExtendedAccountRequest`. `ALLOWED_REQUEST_IDS` lists exactly those eight
`(service, command)` pairs and `isAllowedRequest()` is the check; a test asserts that every builder
is on the list, so the two cannot drift apart. Deliberately absent, with the reason in the file:
alarms, notifications, contacts, music, find-phone, file upload and OTA (write-type commands), and
`DeviceConfig.Bond.Request` / `BondParams.Request` (tags 0x06/0x07 are a bonding key and its IV —
key material, so it belongs to Phase 3).

## 4. How it was verified

Five independent kinds of check, because each one alone can be fooled:

1. **Upstream vectors, ported byte for byte.** `TestHuaweiTLV.java` (45 tests), `TestVarInt.java`
   (20), and the five frames of `TestHuaweiPacket.java` (25, including their input TLVs). Expected
   bytes are upstream's own, not values this code produced.
2. **The checksum against an independent implementation.** The ported loop is compared, over every
   one-byte input and over seeded and random buffers, with a deliberately naive bit-by-bit
   CRC-16/XMODEM written separately in the test file; it also reproduces all five upstream frame
   CRCs and the published check value for `"123456789"` (0x31C3). This is why the CRC variant is a
   *verified* finding rather than an assumption: `getCRC16` is CRC-16/XMODEM — polynomial 0x1021,
   init 0x0000, MSB-first, no reflection, no final XOR — and the unrelated reflected `0xA001`
   variant of `getCRC16ansi` is not what the frame uses.
3. **Encoder and decoder against each other**: build a request, frame it, decode it, and compare the
   TLV and the ids — so a change to either half is caught.
4. **Deliberate abuse, which is what a live link will do**: one valid frame split at *every* byte
   offset must reassemble to the same frame; two frames in one chunk must yield two frames; a bad
   magic, a bad length, a bad CRC and truncated input must each return their typed error and never
   throw; fuzzed bytes must not crash the codec.
5. **Refusals are asserted, not assumed**: an encrypted transaction is refused with `unsupported`,
   and each of the eight builders is checked against `ALLOWED_REQUEST_IDS`.

Nothing in `src/huawei/` imports anything but its own sibling modules (verified), and the tests
import only `node:test` and `node:assert/strict`, so the whole codec runs with no socket, no
subprocess and no install step.

## 5. Divergences from upstream, all deliberate

Every one of these is stated at the top of the file that makes it, so a reader comparing this code
with Gadgetbridge sees the reason next to the difference.

| # | Where | Upstream | Here | Why |
|---|---|---|---|---|
| 1 | all byte-in entry points | throws `HuaweiPacket.ParseException` and five subclasses (HuaweiPacket.java:185-244) | returns a `CodecResult` union carrying a typed error | a codec fed a live stream meets garbage; an exception across a read boundary is a crash waiting for a reboot |
| 2 | frame decode | reads `newPayload[0]`/`[1]` and can throw `ArrayIndexOutOfBoundsException` (:404-405) | `bad-length` when the payload cannot hold the two id bytes | bounds are checked, not assumed |
| 3 | stream reassembly | appends a fresh 0x01 slice to whatever was pending (:389-395) | a fresh 0x01 slice **replaces** an unfinished accumulation; a middle/last slice with no first slice is an error; a hard error clears the buffer | merging two different packets invents a bogus payload — losing one packet is honest, inventing one is not |
| 4 | frame encode | encrypts the TLV whenever the packet wants it and the transaction is crypted (:942-950) | asks for encryption → `unsupported` error naming Phase 3 | this phase holds no key, so it must refuse rather than quietly send plaintext; the default is upstream's own pre-key plaintext path, byte for byte |
| 5 | request scope | any request class can be built | `ALLOWED_REQUEST_IDS` + a test that every builder is listed | the write-type and key-carrying builders do not exist at all, so the scope is machine-checkable rather than a convention |
| 6 | reassembly ownership | state lives in the packet object, surplus bytes are returned to the caller (:375) | the stream owns its buffer and returns every complete frame it can build | a real RFCOMM read splits and merges frames at arbitrary points |

## 6. Source, commit, and attribution

The code was ported from Gadgetbridge read **read-only** from the GitHub mirror of the project at
commit **`a0948ee1cbc2a870f91d313f8e37df5f524465f7`** (the mirror's `master`, frozen 2024-12-22).
`docs/BCS_PHASE0.md` cites the Codeberg commit `de7c2ba8d636a3dc5b750770fb3654671a4bd260`; Codeberg
answered the automated fetch with a bot check, and that hash does not resolve on the mirror
(HTTP 422), so the frozen mirror hash — re-fetchable, immutable, with stable line numbers — is what
was actually read. Both commits are named in `NOTICE` and `docs/BCS_NOTICE.md` so no reader has to
guess which one a line number refers to.

Upstream files read for this phase: `devices/huawei/HuaweiPacket.java`, `HuaweiTLV.java`,
`HuaweiConstants.java`, `HuaweiCrypto.java` (read to define the scope, **not** ported),
`packets/DeviceConfig.java`, `packets/AccountRelated.java`, `packets/FindPhone.java` (used as a
write-type command that must be refused), `util/CheckSums.java`, and the tests `TestHuaweiPacket`,
`TestHuaweiTLV`, `TestVarInt` (ported) and `TestHuaweiCrypto` (not ported).

**Attribution is verified, not asserted:** all 7 ported source files and all 6 ported test files
carry exactly one Gadgetbridge AGPL reference and exactly one `Ported from <upstream path> @
<commit>` line naming the line ranges; `errors.ts` and `index.ts` carry zero, because they are
original. The repository-level `docs/BCS_NOTICE.md` required by `docs/BCS_PHASE0.md` §7 exists and
lists every ported file with its upstream origin, plus what was deliberately not ported. Both files
and the per-file headers were checked by script as the last step of this phase.

## 7. What Phase 2 deliberately did not do

- **No cryptography.** `HuaweiCrypto.java` was read to define the boundary and then not ported: no
  cipher, no key derivation, no auth-code path, no bonding key. The two upstream `TestHuaweiCrypto`
  vectors whose assertion is a *decrypted* payload were not ported as passing tests; the encrypt side
  is asserted to be **refused**. Phase 3 owns all of that, and its own review.
- **No write-type commands.** Alarms, notifications, contacts, calendar, music, find-phone, file
  upload and OTA have no builder in this phase, by construction rather than by discipline.
- **No key-carrying requests.** `DeviceConfig.Bond.Request` and `BondParams.Request` are absent
  because their tags 0x06/0x07 are a bonding key and its IV.
- **No live device.** Phase 2 has no transport at all: it cannot open, hold or close a link, and no
  test in it can reach a watch even if one were paired. The RFCOMM sidecar from Phase 1 is untouched
  and is not imported by any codec file.
- **No app changes.** Nothing under `src/` was touched in this phase, and the Gadgetbridge-shaped
  export plus the existing Import panel (Phase 0 §3) are untouched: wiring the codec to the importer
  is Phase 4's job, with its own approval step.
- **No data.** No sleep sample, no health value, no capture, no export and no database was read or
  written. Every test vector is bytes from public upstream test files or synthesised locally.

## 8. Uncertainties and open questions

Carried forward honestly, because a codec that matches *a* reference is not yet a codec that matches
*this* watch.

| # | Open question | Status / next step |
|---|---|---|
| 1 | Do the GT 5's real frames match these vectors? The vectors are Gadgetbridge's, not this watch's | **The largest unknown of the phase.** Phase 4's first action should be a read-only capture of the handshake and a byte-for-byte comparison against the output of `linkParamsRequest` / `supportedServicesRequest` |
| 2 | Is the CRC variant right? | **Resolved, verified — not assumed.** CRC-16/XMODEM seeded 0x0000, confirmed against an independent implementation, upstream's five frame CRCs and the published check value 0x31C3 |
| 3 | Do sliced frames ever occur on this link, and at what slice size? | Implemented from the source and unit-tested at every split offset, but never observed. The 0xF4 slice size is upstream's default, not a value the watch reported; `LinkParams` is the frame that would report the real one |
| 4 | Will the watch accept an unencrypted transaction for sleep reads? | Unknown until Phase 3 exists to compare both paths; Phase 2 can only refuse encryption, not evaluate it |
| 5 | `protocolVersion` / `authVersion`, and whether the dual channel (`0x01` / `0x3C`) is needed for sleep | Phase 3 and 4 observations; the dual channel is still refused as `unsupported`, as Phase 0 §1.2 planned |
| 6 | Do the line numbers match the Codeberg commit Phase 0 cites? | They refer to the frozen mirror copy. If the cited commit differs in these files, the ranges in the headers need re-checking — mechanical, listed so it is not forgotten |
| 7 | Can a second device authenticate with the same auth code? | Carried from Phase 1; a Phase 3 question that may change scope, and must be documented as a limitation if the answer is no |

One defect was found and fixed during this review, and is recorded because it is the kind of thing
that hides: `src/huawei/constants.ts` had its header comment pasted twice. A script assertion caught
it while checking attribution coverage; the file is now 101 lines with one header, and the suite was
re-run afterwards (225 pass).

## 9. Hard rules: what was followed, and how that was checked

| Rule | How it was checked |
|---|---|
| **No Bluetooth touched in Phase 2** | `src/huawei/*.ts` import only sibling `./` modules — no `node:net`, no `child_process`, no `node:fs`, no `node:crypto`, and no occurrence of `rfcomm`/`bluetooth`; the tests import only `node:test` and `node:assert/strict`. Verified by grepping the import lines of every codec and test file |
| **No keys, cookies, account values or preference files read** | A grep for `cookie`, `preference`, `auth_code`, `password` and `secret` across the codec and its tests returns two hits, both comments (and one error message) that *name* the Phase 3 secret key; nothing reads one |
| **No health data** | Nothing in the phase reads a sample, an export or a database; test inputs are upstream's vectors and locally built buffers |
| **Addresses masked** | No device address appears anywhere in Phase 2 — the codec never sees one. All Phase 1 material and every log line still masks to `XX:XX:XX:XX:AA:BB` |
| **No state-changing git command** | Only `git status --porcelain` (read-only) was run; nothing was staged, committed, checked out, stashed or cleaned |
| **No secret in the repository** | The auth code stays in `~/.config/aether-bcs/` (mode `0600`) and Phase 2 never asks for it; no credential exists in any file this phase added |

## 10. Checks run at the end

| Check | Result |
|---|---|
| `node --test --test-reporter=tap test/` in `bcs/helper` | **225 tests, 225 pass, 0 fail, 0 skipped** |
| `python3 -m unittest discover -s sidecar` in `bcs/helper` | **93 tests, OK** |
| Per-file breakdown, the Phase 2 codec | crc16 9, varint 20, tlv 45, frame 25, stream 31, requests 14 = **144** |
| `npm run lint` (repository root) | exit 0, nothing reported. `eslint.config.js` covers only `src/lib/**/*.{js,mjs}`, `src/components/**`, `src/pages/**` and `src/Layout.jsx`, so `bcs/` is outside the app's lint scope and the helper's guarantee is its own suite. A lint block for `bcs/**/*.ts` would need typescript-eslint, which the repo does not install — an open, optional item |
| `npm run typecheck` (repository root) | exit 2 with **pre-existing** errors in `node_modules/sql.js/dist/sql-wasm.js` and `src/components/bioage/AgeDialog.jsx`, and **zero** references to `bcs/`. `jsconfig.json` includes only `src/components/**/*.js`, `src/pages/**/*.jsx` and `src/Layout.jsx`, so Phase 2 is not type-checked by the app config; Node strips the types at run time and the tests exercise the code |
| `npm test` (repository root, the app's own suite) | 129 tests, 129 pass, 0 fail — unaffected |
| `git status --porcelain` | ` M .gitignore`, `?? bcs/`, `?? docs/` — no application file touched, nothing committed |

**Next:** Phase 3 — trust: link parameters, status, digest, the HiChain session key and the auth-code
file, with the crypto review this phase deliberately avoided. Then Phase 4 — sync v1.0: read-only
sleep, the dual channel if the watch demands it, a Gadgetbridge-shaped export, and the existing
importer, untouched.
