# BCS Phase 0 — Butterfly Connectivity System v1.0, PC helper design

Status: **design only — no helper code written, no dependency installed, no application code changed.**
Phase 1 has not started.

Scope: a local Linux helper that talks to a Huawei Watch GT 5 over classic Bluetooth
(RFCOMM/SPP), authenticates with the user's own device auth code, reads data and feeds
Aether Health's existing Gadgetbridge importer. No Aether-driven cloud calls, no Huawei
account handled by the helper, no phone required for the watch link.

Source read for this document: Gadgetbridge `master`, commit
`de7c2ba8d636a3dc5b750770fb3654671a4bd260` (source archive, read only). All `file:line`
references are to
`app/src/main/java/nodomain/freeyourgadget/gadgetbridge/...` unless stated otherwise.
Anything not verified against source is marked **UNKNOWN**.

What this phase did **not** touch: device preferences, exports, databases, and any key,
cookie or account value. No real credential was read, printed, stored or requested.

## 1. Connection sequence for the GT 5

### 1.1 Transport: classic Bluetooth SPP, not GATT

| Claim | Evidence |
|---|---|
| The GT 5 is a **BR (classic)** device, so `HuaweiBRSupport` is its transport, not `HuaweiLESupport` | `devices/huawei/huaweiwatchgt5/HuaweiWatchGT5Coordinator.java:28` (`extends HuaweiBRCoordinator`); `HuaweiBRCoordinator.java:27-34` (`ConnectionType.BT_CLASSIC`, `HuaweiDeviceType.BR`, `HuaweiBRSupport.class`); `devices/huawei/HuaweiCoordinator.java:86-93` (`enum HuaweiDeviceType { AW(0), BR(1), BLE(2), SMART(5) }`) |
| The BR transport is a **serial socket** with a large buffer | `service/devices/huawei/HuaweiBRSupport.java:53` (`super(LOG, 1032)`); `service/btbr/AbstractBTBRDeviceSupport.java:33-43` ("connected through a serial protocol, like RFCOMM BT or TCP socket", via `BtClassicIoThread`) |
| The socket is created **by SDP lookup of a service UUID**, not by a fixed channel | `AbstractBTBRDeviceSupport.java:45-51` ("No explicit RFCOMM channel" ... `getRfcommChannel()` "primary socket resolved through SDP"), `:271-277`; `service/btclassic/BtClassicIoThread.java:158` (`createRfcommSocketToServiceRecord(getUuidToConnect(uuids))`), `:159-161` (`connect()`, input/output streams) |
| That UUID is the Huawei SDP record | `HuaweiBRSupport.java:54` (`addSupportedService(HuaweiConstants.UUID_SERVICE_HUAWEI_SDP)`); `devices/huawei/HuaweiConstants.java:33` (`82FF3820-8411-400C-B85A-55BDB32CF060`); Honor variant at `:34` |
| Data is read as a stream and handed to a packet decoder | `BtClassicIoThread.java:104-126` (loop: `mProtocol.decodeResponse(parseIncoming(mInStream))`), write path `:72-86` (`mOutStream.write(bytes)` + `flush()`), socket timeout ignored `:119-120` |
| **UNKNOWN**: the numeric RFCOMM channel the GT 5's SPP record listens on. Android resolves it via SDP; Linux must query SDP (`bluetoothctl` has no browse; BlueZ's `sdptool` lives in the deprecated-tools package) or probe channels. Phase 1 must settle this. | — |
| **UNKNOWN**: whether `HuaweiBRSupport` overrides `getRfcommChannel()` / `getConnectDelayMillis()` (defaults `-1` and `0`, `AbstractBTBRDeviceSupport.java:275-290`). The file's middle was not read. | — |

### 1.2 The aux ("dual") channel — when it is needed

| Claim | Evidence |
|---|---|
| A second RFCOMM socket can be opened per connection, keyed by channel number | `AbstractBTBRDeviceSupport.java:57-59` (`mAuxQueues`), `:141-181` (`openAuxChannel`), `:183-186` (`closeAuxChannel`), `:238-254` (`getQueue(channel)`; an unavailable aux channel silently falls back to the primary) |
| The channel and its routing tables are **negotiated with the watch** by service `0x01`, command `0x3C`, and only when the device advertises dual-socket support (expand-capability bit 56) | `service/devices/huawei/requests/GetDualChannelRequest.java:28-48` (javadoc: "Service 0x01 / command 0x3C ... Only sent when the device advertises dual-socket support (expand-capability bit 56) ... Also requires a BR (RFCOMM) transport; on BLE there is no second socket to open."); packet class `devices/huawei/packets/DeviceConfig.java:2005` (`class DualChannel`) |
| Routing rules: whole services, or (service, command) pairs, or P2P destination package names; P2P services are `0x34`/`0x37`; `0x2C` file download can be forced onto aux | `service/devices/huawei/HuaweiDualChannelHelper.java:29-40`, `:119-140`, `:142-154` |
| Consequence for the helper: the GT 5 can require **two simultaneous sockets**; the helper must implement `openAuxChannel` or accept degraded behaviour on models that route file downloads to aux | derived from the above |

### 1.3 Packet framing, checksum, fragmentation

| Claim | Evidence |
|---|---|
| Magic byte `0x5A`; a bad magic is rejected on decode | `devices/huawei/HuaweiPacket.java:352-357` (`magic != HUAWEI_MAGIC ... " != 0x5A"`) |
| **CRC16** over the packet with init `0x0000`, appended as the last two bytes | `HuaweiPacket.java:392-394`, `:929-931`, `:951-954`; implementation `util/CheckSums.java:66` (`getCRC16(byte[], int crc)`), reflected polynomial `0xA001` appears in the `getCRC16ansi` variant `:82-89` |
| Header = magic + `short(length+1)` + `0x00` (+ extra slice info on some paths), footer = 2-byte CRC; body size is bounded by `paramsProvider.getSliceSize()` — i.e. **the watch's negotiated slice size drives fragmentation** | `HuaweiPacket.java:879-882` (`headerLength = 5`, `footerLength = 2`, `maxBodySize = sliceSize - header - footer`), `:892-900` |
| Body encryption is TLV-level, applied when required, using an AES counter-derived IV | `HuaweiPacket.java:959-965` (`HuaweiTLV.encryptRaw(paramsProvider, payload)`), `:1099` (`tlv.encrypt(paramsProvider)`), `:71-77` and `:155-179` (`encryptionCounter`, `encryptMethod`, `HuaweiCrypto.initializationVector(counter)`); IV builder `HuaweiCrypto.java:199-...` |
| **UNKNOWN**: `HuaweiPacket`'s packet-type table and the exact slice-info layout. Phase 2 must read `HuaweiPacket.java` in full (1162 lines) — it is the single largest portability task. | — |

### 1.4 Ordered connection sequence (BR path)

| # | Step | Evidence |
|---|---|---|
| 1 | SPP connect via the SDP UUID, then `initializeDevice` on the BR transaction builder | `BtClassicIoThread.java:158-161`; `AbstractBTBRDeviceSupport.java:292-296` (onConnectionEstablished → initializeDevice) |
| 2 | `buildDeviceState = AUTHENTICATING`; build `GetLinkParamsRequest`; the helper generates a **random MAC** and an **Android ID** for the session | `service/devices/huawei/HuaweiSupportProvider.java:516-522`; `:524-528` (`createRandomMacAddress()`, `createAndroidID()`) |
| 3 | **Link params exchange** — service `0x01`, command `0x01`. Response carries `protocolVersion`, `deviceSupportType`, `sliceSize`, `mtu`, `serverNonce` (18 bytes), `authVersion`, `bondState` | `requests/GetLinkParamsRequest.java:42-43` (ids), `:44`/`:55` (`serverNonce = new byte[18]`), `:75-84` (fields); ids `packets/DeviceConfig.java:44` (`id = 0x01`), `:47` (`LinkParams.id = 0x01`) |
| 4 | **Device status** — `GetDeviceStatusRequest(status)`; if status ∈ {−1, 0, 1} go to the HiChain branch, otherwise to `initializeDeviceNotify()` | `HuaweiSupportProvider.java:554-565` |
| 5 | **HiChain branch**: `initializeDeviceDealHiChain(linkParamsReq)` → security negotiation → one of `initializeDeviceHiChainMode()` (`:708`), `initializeDeviceHiChainModePake()` (`:725`), `initializeDeviceHiChainLiteMode()` (`:737`), or `initializeDeviceNormalMode()` (`:760`) | `HuaweiSupportProvider.java:608+`, and the grep list at those lines |
| 6 | **Auth with the device key**: the secret key is the stored `authkey` (hex) — read from device prefs, or generated once if absent — and is passed to the params provider | `HuaweiSupportProvider.java:850-861` (`createSecretKey()`: `sharedPrefs.getString("authkey", null)`, else `HuaweiCrypto.generateNonce()`, then `paramsProvider.setSecretKey(GB.hexStringToByteArray(authKey))`) |
| 7 | **Digest/challenge**: `digestChallenge()` for the watch's nonce and `digestResponse()` for ours. HMAC-SHA256 over `secretKey‖0x0100` / `secretKey‖0x0110` in the `authVersion == 0x02` mode; a **PBKDF2-SHA256 (1000 iterations, 256-bit)** variant when `authAlgo == 0x01`; a static-secret digest chain when `authMode != 0x02` | `devices/huawei/HuaweiCrypto.java:155-197`, `:112-130`, `:132-153` (`pbkdf2Sha256(..., 0x3e8, 0x100)`), `:48-79` (`SECRET_KEY_*`, `DIGEST_SECRET_*`, `MESSAGE_CHALLENGE`, `MESSAGE_RESPONSE`) |
| 8 | **HiChain handshake** — stepped (`step 0x00...0x03`), MAC-verified, and its final step sets a **session key** derived locally from the auth token (`decryptAES_GCM_NoPad(encAuthToken, sessionKey, nonce, challenge)` → `setSecretKey(authToken)`) | `requests/GetHiChainRequest.java` (steps, `returnCodeMac` check, `step == 0x03` → `setSecretKey(authToken)`; Method `processResponse()`) |
| 9 | `initializeDeviceNotify()` → `initializeDeviceConfigure()` | `HuaweiSupportProvider.java:675-682` |
| 10 | **Post-auth init queue, strictly ordered**: `GetProductInformationRequest` → `SetTimeRequest` → `GetBatteryLevelRequest` → `GetSupportedServicesRequest` (**"MUST BE LAST - it indirectly kicks off initializeDynamicServices"**), each with `initTimeout` between steps | `HuaweiSupportProvider.java:830-843` |
| 11 | Earlier services are unregistered before the queue (P2P + DataSync), because "supported services" re-registers them | `HuaweiSupportProvider.java:816-818` |
| 12 | **Periodic traffic**: a delayed "battery runner" keeps polling and is restarted on timeout — the only periodic behaviour I verified | `HuaweiSupportProvider.java:819-828` |
| 13 | **UNKNOWN**: a dedicated keep-alive/PING packet. None was found; the battery runner above is what I can cite. | — |
| 14 | **UNKNOWN**: whether a Linux-side pairing/bonding step is required before the SPP connect, and how the watch reacts to an unpaired SPP connect. Gadgetbridge relies on Android SDP/bonding; BlueZ behaviour must be tested in Phase 1. | — |
| 15 | **Out of scope, by rule**: all write paths — alarms, notifications, contacts, music, watchfaces, OTA/firmware. OTA can brick the watch. | `requests/` inventory (145+ write requests) |

Helper-side note on steps 6–8: Gadgetbridge reads `authkey` from its own stored device
preferences because Android already established it. The helper has no such store, so the
user supplies the equivalent **device auth code** once (see §5 and §8, item 3). The helper never
contacts a Huawei service itself.

## 2. Data classes, requests, and target tables

| Data class | Request(s) | Service / command | Written into (Gadgetbridge tables) | Evidence |
|---|---|---|---|---|
| **Sleep — first class to build** (`HUAWEI_SLEEP_STATS_SAMPLE` **+** `HUAWEI_SLEEP_STAGE_SAMPLE`) | `GetSleepDataCountRequest` then `GetSleepDataRequest` | `FitnessData.id = 0x07`, `MessageCount.sleepId`, `MessageData.sleepId` | `HUAWEI_SLEEP_STATS_SAMPLE` (per-night summary) **and** `HUAWEI_SLEEP_STAGE_SAMPLE` (per-minute stages) | `requests/GetSleepDataCountRequest.java:36-37,50-51`, `requests/GetSleepDataRequest.java:38-39,48`; ids `packets/FitnessData.java:33`, `:215-255`; write path `HuaweiSupportProvider.java:2887-2960` (`HuaweiSleepStatsSample` → `HuaweiSleepStatsSampleProvider.persistSamples`); stage parser `devices/huawei/HuaweiTruSleepParser.java`, `HuaweiTrueSleepSequenceDataParser.java` |
| Activity / steps / HR | `GetStepDataCountRequest` + `GetStepDataRequest`; `GetFitnessTotalsRequest` for daily totals | `FitnessData.id = 0x07`; `MessageData.stepId`; `FitnessTotals.id` | `HUAWEI_ACTIVITY_SAMPLE`; totals are forwarded to the coordinator | `requests/GetFitnessTotalsRequest.java` (steps/calories/distance → `addTotalFitnessData`); ids `packets/FitnessData.java:36`, `:507-524`; provider `devices/huawei/HuaweiSampleProvider.java` |
| Workouts | workout sync manager + P2P | P2P/`0x34`-`0x37` family | `HUAWEI_WORKOUT_SUMMARY_SAMPLE`, `HUAWEI_WORKOUT_DATA_SAMPLE` | `service/devices/huawei/HuaweiWorkoutSyncManager.java`, `HuaweiWorkoutGbParser.java` |

**Recommendation — build sleep first, and build both sleep tables together.**
1. **Aether needs both to make a night.** `HUAWEI_SLEEP_STATS_SAMPLE` supplies the night's
   bed/wake anchors, average SpO2 and breath rate; `HUAWEI_SLEEP_STAGE_SAMPLE` supplies the
   per-minute stage timeline the sleep card draws and the consistency window measures. A
   stats-only export produces a night with no stages; a stages-only export produces stages
   with no respiratory rate or SpO2. The two must be fetched, parsed and written as a pair.
2. Smallest viable slice that is still a real night: two commands in one service, no P2P file
   transfer and no aux channel required.
3. Easiest diff: one summary row per night plus a bounded stage timeline can be compared
   field-by-field against a Gadgetbridge export of the same night.
4. It exercises the whole stack we must prove anyway: link → codec → trust → sync → tables.
   `HUAWEI_ACTIVITY_SAMPLE` (per-minute rows, more traffic) is the natural second class;
   workouts (P2P + aux channel) are last.

## 3. Output contract — reuse the existing importer untouched

The app reads any Gadgetbridge export into one shape: `readTables()` returns
`{ tables: Record<string, string>, expandedBytes, shape }` where each key is an
**UPPERCASE table name** and the value is **CSV text** (header row, then rows) — from a zip
of per-table CSVs or from the SQLite DB, with identical semantics (NULL → empty cell,
blob → comma-joined decimal bytes, boolean → 1/0)
(`src/lib/importers/gadgetbridge/sqlite.ts:57-97,117-147`). `tableOf(files, name)` then
matches a table by name/prefix (`src/lib/importers/gadgetbridge/tables.ts:113`).

**Contract: the helper emits a Gadgetbridge-shaped export** — either a zip containing one
CSV per table, or a small SQLite file — and the user imports it with the existing Import
panel. Result: **zero app changes, zero new parsing, zero new scoring, existing tests still
guard the chain** (`importGadgetbridgeFiles` → `readTables` → `buildDays`/`buildWorkouts` →
`saveImport` → `recommendScores`; `src/lib/firebase/imports.js:179-230`).

Exact columns Aether reads (so the helper must write at least these, with these names):

| Table | Columns read by Aether | Evidence |
|---|---|---|
| `HUAWEI_SLEEP_STATS_SAMPLE` (phase-1 target) | `BED_TIME`, `RISING_TIME`, `AVG_OXYGEN_SATURATION`, `AVG_BREATH_RATE`, `MIN_BREATH_RATE_BASELINE`, `MAX_BREATH_RATE_BASELINE` (+ `DEVICE_ID`, `USER_ID`, `TIMESTAMP` for the row to be valid) | `src/lib/importers/gadgetbridge/days.ts:191-232` |
| `HUAWEI_SLEEP_STAGE_SAMPLE` (phase-1 target) | `TIMESTAMP`, `STAGE` | `days.ts:107-116` |
| `HUAWEI_ACTIVITY_SAMPLE` | `TIMESTAMP`, `HEART_RATE`, `STEPS`, `CALORIES`, `SPO`, `RESTING_HEART_RATE` | `days.ts:70-102` |
| `HUAWEI_HRV_VALUE_SAMPLE` | `TIMESTAMP`, `VALUE` | `days.ts:173-182` |
| `HUAWEI_TEMPERATURE_SAMPLE` | `TIMESTAMP`, `TEMPERATURE`, `TEMPERATURE_TYPE` | `days.ts:237-242` |
| `HUAWEI_WORKOUT_SUMMARY_SAMPLE`, `HUAWEI_WORKOUT_DATA_SAMPLE` | workout fields | `src/lib/importers/gadgetbridge/workouts.ts:106-158` |

Column lookup is normalised (case- and punctuation-insensitive) and falls back to substring
match (`tables.ts:199-210`), so exact upper-case spelling is not required — but the helper
should copy Gadgetbridge's own column names to keep exports interchangeable.

## 4. Language and Linux classic-Bluetooth transport

| Option | RFCOMM on Linux today | Verdict |
|---|---|---|
| **Node/TypeScript** | **No native RFCOMM.** Needs either a native addon (node-gyp build on every Node upgrade) or an out-of-process transport. Best fit for everything else: same language as the repo, same `node --test` conventions, `sql.js` already in use, the Fuse layer is a JS object. | **Recommended for codec, trust, sync, fuse, localhost service** |
| **Python 3** | **Certain, stdlib only**: `socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)` and `connect((addr, channel))`. No dependencies, no build step, works on CachyOS/Arch with BlueZ. Weak fit for the large protocol port and for the repo's test tooling. | **Recommended for the ~100-line RFCOMM sidecar only** |
| **Go** | Possible via `AF_BLUETOOTH`/`BTPROTO_RFCOMM` syscalls in `x/sys/unix` (**UNKNOWN — verify in Phase 1**). Good single-binary story; a second language to maintain. | Not now |
| **Rust** | Possible via raw syscalls / `nix`/`socket2` (**UNKNOWN — verify in Phase 1**). Best long-term packaging; slowest to iterate for a protocol this size. | Later, if the sidecar becomes a problem |

**Recommendation: TypeScript helper + a Python 3 stdlib RFCOMM sidecar**, behind:

```
interface BcsTransport {
  open(target: { address: string; channel?: number }): Promise<void>;
  openAux(channel: number): Promise<void>;         // 0x3C dual channel
  write(data: Uint8Array, channel?: number): Promise<void>;
  onData(cb: (data: Uint8Array, channel: number) => void): void;
  close(): Promise<void>;
}
```

Everything above `BcsTransport` (codec, crypto, auth, requests, table writing, localhost
service) is transport-free, so a Windows transport (paired COM port) and a BLE transport
(for the band family, later) drop in without touching upper layers. This mirrors
Gadgetbridge's own separation (`HuaweiDualChannelHelper`: "This class carries no transport;
it only answers 'primary or extra'", `HuaweiDualChannelHelper.java:36-39`).

## 5. Browser ⇄ helper on localhost — security design

- **Bind `127.0.0.1` only** (never `0.0.0.0`), ephemeral port printed by the helper; no TLS
  on loopback.
- **Host check** — reject any request whose `Host` is not `127.0.0.1:<port>` or
  `localhost:<port>`. This is the primary **DNS-rebinding** defence (a rebound request
  arrives with the attacker's hostname).
- **Origin allowlist** — echo `Access-Control-Allow-Origin` only for the exact Aether origins
  (localhost dev port and the production origin). Never `*`. Handle the preflight for
  **Private Network Access** (`Access-Control-Request-Private-Network`) only for allowed
  origins.
- **One-time pairing token** — the helper prints a short code; the user pastes it into
  Settings once. The browser exchanges the code (single use, rate-limited, expiring) for a
  long random bearer token kept in `localStorage`. All later calls require
  `Authorization: Bearer ...` **and** a custom header (`X-BCS-Token`) so a plain HTML form or
  `<img>` cannot forge a call; compare tokens with a constant-time compare. This is the
  *browser↔helper* token and is unrelated to the *device auth code* below.
- **Device auth code** (see §8, item 3): obtained by the user from their own Huawei Cloud account
  and pasted into the helper **once**, through a hidden prompt that never echoes the input —
  **never as a command-line argument**, so it cannot end up in shell history or in the
  process list. The helper writes it to `~/.config/aether-bcs/device.json` outside the repo
  with mode `0600`. It is:
  - never sent to the browser,
  - never sent to Firestore or any other network endpoint,
  - never logged, never echoed in progress output,
  - redacted from every error message and stack trace (all errors pass through a redaction
    filter that replaces the value with `[redacted]`).
  The helper stores **only** the final auth code. It never asks for, receives, stores or
  transmits a Huawei cookie or account token: any cookie the user handles while obtaining the
  code is used by the user alone, inside their own browser.
- **No endpoint returns the code.** It is read from disk at connect time, used, and never
  serialised, echoed, logged or sent anywhere.
- **Minimal surface**: `GET /status`, `POST /pair`, `POST /connect`, `POST /sync`,
  `GET /sync/progress`, `POST /disconnect`. No file-system browsing, no arbitrary-path
  endpoints.
- **On the app side**: a new opt-in Settings toggle ("Direct Connectivity", off by default,
  clearly marked experimental) and the helper URL shown as plain text so the user sees
  exactly where their data is going.

## 6. Test plan (all offline, before any live run)

1. **Java vectors → fixtures**: read `TestHuaweiPacket` (370 lines), `TestHuaweiTLV`,
   `TestHuaweiCrypto`, `TestVarInt`, `TestFitnessData`, `TestWorkout` and turn their byte
   arrays into `node:test` fixtures under the repo's existing test command. These are
   published, shareable and carry no health data.
2. **Transport replay**: a recorded local session (raw socket bytes, **gitignored, kept local,
   never pasted into any prompt**) replayed through the framer/decoder; the decoder must
   reproduce the same request/response sequence. A synthetic re-framer (byte-at-a-time, split
   packets) covers the buffer-boundary cases.
3. **Golden table diff**: helper output vs the user's own Gadgetbridge export for the same
   night — for phase 1 that means comparing the `HUAWEI_SLEEP_STATS_SAMPLE` row and the
   `HUAWEI_SLEEP_STAGE_SAMPLE` timeline row-by-row, field-by-field. This runs locally, by the
   user; only the pass/fail summary is ever shared.
4. **No live run until 1–3 pass.** The authentication run may send only the allowlisted handshake
  frames; the later sync run is read-only and refuses every request outside its read allowlist.

## 7. Risks and scope

Explicitly **out of scope** for this project: every non-authentication write path — alarms,
notifications, settings, contacts, calendar, music, watchfaces, and **firmware/OTA** (an OTA
mistake can brick the watch). The only writes permitted are the auth handshake frames enumerated
by the Phase 3C sidecar allowlist; sync remains read-only.

| Risk | Mitigation |
|---|---|
| RFCOMM channel discovery on Linux (no `sdptool` in modern BlueZ) | Phase 1 spike: try `bluez-deprecated-tools` `sdptool browse`, a channel probe loop validated against the SDP UUID, or a cached channel in the device config |
| Watch must not be connected elsewhere | Document it and detect it: see the single-connection risk below, which makes this a hard prerequisite rather than a nicety |
| Dual channel / aux socket and P2P file transfer | Deferred to phase 4+; the chosen first class needs neither |
| Firmware variance (GT 5 vs GT 6 vs newer) | Keep device-specific values in config, never in code paths; log negotiated `protocolVersion`/`authVersion` |
| Secrets | Auth code file **outside the repo**, mode `0600`, entered once through a hidden prompt (no shell history, no process list); never in Firestore, never in the browser, never logged, redacted in errors; captures gitignored |
| Health data in captures | Local only; never in prompts, issues or commits |
| Licensing | Aether is AGPL-3.0 and so is Gadgetbridge, so a port is allowed: add `docs/BCS_NOTICE.md` crediting Gadgetbridge, commit `de7c2ba8d636a3dc5b750770fb3654671a4bd260`, AGPL-3.0-or-later © the Gadgetbridge contributors, listing each ported file and its upstream origin; every ported file keeps Gadgetbridge's AGPL header plus a `Ported from <path> @ <commit>` line |
| Wrong-night attribution (timezone) | Reuse the importer's existing rule: a night belongs to the day it ends on (`days.ts:134`); never re-derive locally |
| **(a) v1.0 requires the user's own device auth code** | There is no bypass: without an auth code the watch cannot be authenticated, so v1.0 works only for users who already have one. **Users who cannot obtain an auth code are explicitly out of scope for this version**, and the README must say so plainly, before the feature is announced, in the same place the pairing steps are described — no buried caveat, no implication that the helper can obtain the code for them. |
| **(b) The watch accepts ONE active connection at a time (confirmed)** | Gadgetbridge on the phone and the helper can never be connected simultaneously; the second connector either fails or starves. The docs must tell the user to **disconnect the phone app (or turn the phone's Bluetooth off) before syncing from the PC**, and the helper should surface a clear "another device appears to hold the watch" error rather than a generic timeout. **UNKNOWN: whether the same key/auth code works from a second device**, i.e. whether the watch binds the credential to the device that first paired it. Phase 1 must test this — if it does not transfer, that is a scope-changing finding and a documented limitation, not something to work around silently. |
| **(c) The auth code comes from the user's Huawei Cloud account session** | Obtaining the code is the user's own action in their own account, and the cookies that authorise it grant access to their **entire Huawei account**, not just the watch. The docs must say, in plain language: handle those cookies only on your own machine, never share them, never log them, and never paste them into any AI tool, chat, issue tracker or bug report. The helper must reinforce this by never asking for a cookie at all. Add an item to check **Huawei's terms of service** for this kind of third-party local access before announcing the feature. |

Phases: **Link** (socket, channel, framing, byte-exact replay) → **Codec** (`VarInt`,
`HuaweiTLV`, `HuaweiPacket`, `CheckSums`, `HuaweiCrypto` vs vectors) → **Trust** (link params,
status, digest, HiChain session key, auth-code file) → **Sync v1.0** (read-only sleep:
`HUAWEI_SLEEP_STATS_SAMPLE` + `HUAWEI_SLEEP_STAGE_SAMPLE` → Gadgetbridge-shaped export →
existing importer) → **UX** (Settings toggle, pairing code, progress, honest errors). Then, and
only then: BLE for the band family, Android app, more data classes.

## 8. Decisions recorded

1. **First data class: sleep — `HUAWEI_SLEEP_STATS_SAMPLE` + `HUAWEI_SLEEP_STAGE_SAMPLE` together.**
   Aether needs both tables to build a night: stats give bed/wake, average SpO2 and breath
   rate; stages give the per-minute timeline the sleep card draws and the consistency window
   measures. Neither alone produces a usable night. Rationale and evidence in §2; required
   columns in §3.
2. **Delivery: file-first export.** The helper writes a **Gadgetbridge-shaped export** (tables
   as CSV, zipped, or a small SQLite file) that the **existing Import panel** consumes
   unchanged. **Live push from the helper into Aether** (the localhost API in §5) is
   explicitly a **later phase**, after the export path is proven, so phase 1 needs no app
   change and opens no new trust boundary.
3. **Key handling: the user's own device auth code, entered once.** The user obtains their
   device auth code from their own Huawei Cloud account and pastes it into the helper once
   through a **hidden prompt** — never a command-line argument, so it stays out of shell
   history and the process list. The helper saves it to a `0600` file **outside the repo**,
   e.g. `~/.config/aether-bcs/device.json`. It is **never sent to the browser, never sent to
   Firestore, never logged**, and is **redacted from every error message**. The helper stores
   only the final auth code: it **never asks for or stores a cookie or account token**; any
   Huawei cookie the user handles while obtaining the code is used by the user alone, on their
   own machine.

Still open, to be answered in Phase 1 (not in this phase):

- The GT 5's RFCOMM channel and whether Linux must pair/bond before the SPP connect (§1.1).
- Whether the same auth code works from a second device, or the credential is bound to the
  first pairing (§7 (b)). This one can change scope.
- The full `HuaweiPacket` type table and slice-info layout, and the exact `CheckSums`
  CRC16 loop (§1.3).
- Whether a real keep-alive is required during a long sync (§1.4 step 13).