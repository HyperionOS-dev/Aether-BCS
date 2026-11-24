# BCS helper vs upstream Gadgetbridge — a read-only comparison

**What this is.** A line-by-line comparison of our Huawei BR/HiChain implementation (`bcs/helper`,
version `0.3.0-phase3g`, `package.json:4`) against the public Gadgetbridge sources on this machine
(`~/Aether Dev/gb-upstream/gadgetbridge/`, app `versionName = "2026.11.1"`, `app/build.gradle:96`).
It answers six questions — link security (A), key derivation (B), the opening frames (C), post-auth
encryption (D), timing (E) and the account frame (F) — and nothing else.

**How it was produced.** File reads only. No Bluetooth was touched, no live run, no git command, no
package install, no driver execution. Every address in this document is masked; every value used to
compute a frame length was synthetic (a 32-byte filler id, fixed fill bytes for keys and nonces, a
fixed `requestId`). Nothing was read from `~/.config/aether-bcs`, `~/.local/state/aether-bcs`, any
key, account or capture directory.

**The one thing that was executed.** Our own offline suites, to report counts rather than assert
them: `node --test test/` → **354 tests, 70 suites, 0 failed**; `python3 -m unittest discover -s
sidecar -t . -p 'test_*.py'` → **161 tests, OK**. Python is **3.14.9**. Throw-away scripts under `/tmp`
imported our own TypeScript modules to recompute the frame lengths and slice counts in section C with
synthetic inputs; those scripts are not repository files, and no repository file was added, modified or
deleted except this document.

**The upstream snapshot.** The commit id was not read (that needs a git command, which the brief
forbids) → **UNVERIFIED**. The tree is identified by `app/build.gradle:96` (`2026.11.1`) and by the
features present in it (Honor PAKE, dual-channel RFCOMM, HiChain3), which place it at or near the
2026-11 line of `master`.

---

## 0. Summary — everything DIFFERENT, in one table

| # | Item | Upstream | Ours | § |
|---|---|---|---|---|
| D1 | **RFCOMM link security** | *secure* socket: `createRfcommSocketToServiceRecord` (`BtBRQueue.java:341`); no insecure variant anywhere in the tree (grep: 0 hits) | raw `AF_BLUETOOTH`/`BTPROTO_RFCOMM` socket, `settimeout` then `connect`; **no `setsockopt`, no `BT_SECURITY`, anywhere** (`bcs_bt.py:177-184`, `:202`) | A |
| D2 | **Bond precondition** | bonds first through the Android pairing flow (default `BONDING_STYLE_ASK`, `AbstractDeviceCoordinator.java:728-730`); a failed bond does not abort pairing (`PairingStateMachine.kt:167`) | connects to whatever channel SDP named, with no bond check at all (`rfcomm_sidecar.py:167-205`) | A |
| D3 | **Self auth id, character case** | uppercase hex of 16 random bytes (`HuaweiSupportProvider.java:929` + `GB.java:431`), 32 chars | lowercase hex of 32 nibbles (`tools/bcs_auth.mjs:178`), 32 chars | B |
| D4 | **Self auth id, entropy** | `SecureRandom` (`HuaweiCrypto.java:100-105`) | `Math.random` (`tools/bcs_auth.mjs:178`) | B |
| D5 | **A locally generated key can be mistaken for the auth key** | `createSecretKey()` generates one only for HiChainLite/normal (`HuaweiSupportProvider.java:735-777`, `:848-860`); the HiChain path overwrites it with the watch's token (`GetHiChainRequest.java:242`) | `--set-key --generate` writes a random 16-byte key (`bcs_auth.sh:13`, `:234-260`, `:307-308`) and it is offered as *the* way to get one (`bcs_auth.mjs:155`) | B |
| D6 | **SecurityNegotiation tag 0x07** | `Build.MODEL` (`GetSecurityNegotiationRequest.java:67`) | `"Aether Health BCS"` by default (`authMachine.ts:134`) | B, C |
| D7 | **Account frame** | 0x1A/0x05 queued after auth, gated on two capabilities, value from prefs, sent **encrypted** (`HuaweiSupportProvider.java:1054`, `SendExtendedAccountRequest.java:41-55`) | never sent: `--with-account` refuses before the sidecar starts, exit 3 (`bcs_auth.mjs:360-390`, `:500-503`) | F |
| D8 | **Post-auth encryption** | every packet that does not opt out is wrapped in 0x7C/0x7D/0x7E (`HuaweiPacket.java:274`, `:1097-1105`) | refused by design, typed `unsupported` (`frame.ts:292-300`); an account frame cannot be encoded at all (`account.ts:138-151`) | D, F |
| D9 | **RFCOMM connect timeout** | none — `mBtSocket.connect()` blocks (`BtBRQueue.java:207`); only a pre-connect *delay* knob, default 0 (`AbstractBTBRDeviceSupport.java:288-290`) | 10 s default, `timeout_ms` clamped to 1–30 s (`rfcomm_sidecar.py:41-42`, `:189-192`; `sidecarTransport.ts:122`) | E |
| D10 | **Non-HiChain auth paths** | HiChainLite, normal mode, Honor PAKE all implemented (`HuaweiSupportProvider.java:735-777`, `:723-733`) | `auth-unsupported`, deliberately (`authMachine.ts:333-337`, `:364-368`) | B |
| D11 | **Empty account value** | sends the frame with tag 0x01 = `0x00` (`AccountRelated.java:63-67`) | refuses an empty account before a frame exists (`account.ts:71-73`) | F |

Items marked **MATCH** are in the per-section tables (B4, C); they are not repeated here.

---

## A. Link security

### A1. How our sidecar creates and connects the socket

`sidecar/bcs_bt.py:177-184` builds a bare socket and applies only a *timeout*:

```
handle = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
handle.settimeout(timeout)
```

and `sidecar/bcs_bt.py:198-208` connects with `handle.connect((address, channel))`, closing the
handle and re-raising a classified error on any failure.

**No security level is set.** `grep` over every `*.py`, `*.ts` and `*.mjs` in `bcs/helper` for
`setsockopt` or `BT_SECURITY` returns nothing. The socket therefore runs at whatever level BlueZ's
client default is; from our code alone that value cannot be stated → **UNVERIFIED** (it would take a
live `btmon` observation). What is certain is that we never *ask* for one.

Upstream hands the UUID to Android instead: `mBtSocket =
btDevice.createRfcommSocketToServiceRecord(mService)` (`BtBRQueue.java:341`). That is the
authenticating/encrypting variant of the two the platform offers; the insecure sibling
(`createInsecureRfcommSocketToServiceRecord`) does not appear anywhere in the tree (grep: 0 hits), so
Gadgetbridge never requests an unauthenticated link. The exact level Android negotiates for that
socket is a stack property, not visible in these sources → **UNVERIFIED from code**; the API name is
the only evidence available here.

### A2. The Linux constants, and whether Python 3.14 exposes them

From the headers on this machine — `/usr/include/bluetooth/bluetooth.h:48-61` and
`/usr/include/bits/socket.h:162`:

| Name | Value | Note |
|---|---:|---|
| `SOL_BLUETOOTH` | 274 | socket level |
| `BT_SECURITY` | 4 | option |
| `struct bt_security` | `{ uint8_t level; uint8_t key_size; }` | the optval is **2 bytes**: level, then key size |
| `BT_SECURITY_SDP` | 0 | |
| `BT_SECURITY_LOW` | 1 | |
| `BT_SECURITY_MEDIUM` | 2 | |
| `BT_SECURITY_HIGH` | 3 | |
| `BT_SECURITY_FIPS` | 4 | |

Python **3.14.9** (`python3 -c "import socket; ..."`, run here) exposes all of them as
`socket.SOL_BLUETOOTH`, `socket.BT_SECURITY`, `socket.BT_SECURITY_SDP/LOW/MEDIUM/HIGH/FIPS`, with
exactly those integers. **No ctypes, no constant table of our own, and no new dependency is needed.**

One trap worth writing down: `setsockopt` takes a *buffer*, and `struct bt_security` is 2 bytes.
Passing `socket.BT_SECURITY_MEDIUM` as a bare `int` makes CPython encode it as a C `int` (4 bytes) —
the wrong length for this option. The value has to be `struct.pack("BB", level, 0)` or
`bytes([level, 0])`.

### A3. Proposed smallest change (implemented in Phase 3G — see `docs/BCS_PHASE3.md` §12)

Two independent, explicitly opt-in behaviours, both **default off**:

1. **`--bt-security {none,low,medium,high}`** (sidecar CLI) and a matching `bt_security` field on the
   `connect` command. `none` = today's behaviour. When set, the socket factory applies
   `setsockopt(SOL_BLUETOOTH, BT_SECURITY, bytes([level, 0]))` *before* `connect()`, in the same place
   `settimeout()` is applied now (`bcs_bt.py:183`). The driver passes it through, so the choice is
   visible in the run log.
2. **`--require-bond`** (sidecar CLI, plus `require_bond` on `connect`). Before any socket exists —
   in `_connect_command` (`rfcomm_sidecar.py:167-188`), alongside the SDP channel gate — run the same
   `bluetoothctl info <address>` probe the SDP path already uses (`bcs_bt.py:330-344`) and require a
   `Bonded: yes` line; otherwise refuse with a new code (`not-bonded`) and a sentence that says the
   watch must be paired first. This mirrors what Android gives Gadgetbridge for free (a secure socket)
   and what GB's pairing flow guarantees before the first connect
   (`AbstractDeviceCoordinator.java:728-730`, `PairingStateMachine.kt:118-170`).

Files that would change:

| File | Change |
|---|---|
| `sidecar/bcs_bt.py` | `rfcomm_socket(timeout, level=None)` with `setsockopt` before `connect`; a bond probe sharing the existing `bluetoothctl info` parse; an error mapping for "the stack refused for want of a bond" (today `EACCES`/`EPERM` becomes "permission denied … check your user's access to the Bluetooth daemon", `bcs_bt.py:67-68`, which would be a *misleading* sentence here) |
| `sidecar/rfcomm_sidecar.py` | two flags, two `connect` fields, validation, refusal **before** the socket, `CAPABILITIES` (currently `("connect","write","resolve")`, `:48`) if a new capability is advertised |
| `src/sidecarTransport.ts` | new optional fields on `open()`/`connect`, passed as-is (`:274-275`) |
| `src/sidecarProtocol.ts`, `src/types.ts` | the new codes and sentences (`not-bonded`, `security-refused`) |
| `tools/bcs_auth.mjs`, `tools/bcs_auth.sh` | flags, `--help`, plan output, and the refusals that go with them |
| `README.md`, `docs/BCS_PHASE3.md` | the new options and what they do *not* guarantee |
| `sidecar/test_bcs_bt.py` | a fake socket that records `setsockopt` calls; bond-probe parsing (`Bonded: yes` / `no` / absent); assert the option is 2 bytes, not 4 |
| `sidecar/test_rfcomm_sidecar.py` | flag/field validation; that `--require-bond` refuses **before** `connect` is called (the fake connect must not run) |
| `sidecar/test_tools.py` | the driver passes the option, `--help` documents it, `--sdp-only` does not connect |
| `test/sidecarTransport.test.ts` | the option reaches the `connect` line |
| `test/sidecarProtocol.test.ts` | the new codes map to the new sentences |
| `test/sidecarWriteAllowlist.test.ts` | only if `CAPABILITIES` changes |

Design notes for whoever implements it: (a) do **not** make MEDIUM the default — on an unbonded watch
the connect then fails with `EACCES`/`EPERM`, and the current classifier would blame the user's
Bluetooth permissions; (b) `--require-bond` is a *precondition check*, not a pairing feature — it must
never trigger `pair`; (c) both options have to be refused or ignored by `--sdp-only`, which must stay
radio-silent.

---

## B. Key derivation

### B1. What upstream derives, and what we derive, step by step

Upstream, first connect (`firstConnection == true`, `HuaweiBRSupport.java:74-77` sets it), runs
`GetPincodeRequest` → `GetHiChainRequest(operation 0x01)` → `GetHiChainRequest(operation 0x02)`
(`HuaweiSupportProvider.java:706-720`, `:710-713`):

| Step | Upstream | File:line |
|---|---|---|
| PIN | request = one empty tag 0x01; reply = tag 0x01 (ciphertext) + tag 0x02 (IV), decrypted with the **static** digest secret, never the user's key | `DeviceConfig.java:1693-1731`, `HuaweiCrypto.java:248-257` |
| op1 s1 | `seed` = 32 random bytes, `randSelf` = 16 random bytes; JSON `isoSalt`=randSelf, `seed`=seed, `peerAuthId`=hex(selfAuthId) | `GetHiChainRequest.java:107-113`, `DeviceConfig.java:1077-1082` |
| op1 s1 reply | `key = SHA-256(UTF-8(hex(pinCode)))` — the **hex text** of the pin, uppercase (`GB.HEX_CHARS`), digested | `GetHiChainRequest.java:206-209`, `GB.java:431` |
| | `psk = HMAC-SHA256(key, seed)` | `GetHiChainRequest.java:213` |
| | verify `HMAC(psk, randPeer‖randSelf‖authIdSelf‖authIdPeer) == token` | `:214-224` |
| op1 s2 | send `HMAC(psk, randSelf‖randPeer‖authIdPeer‖authIdSelf)` | `:115-123` |
| op1 s2 reply | verify `HMAC(psk, 00000000) == returnCodeMac` | `:229-236` |
| op1 s3 | `sessionKey = HKDF-SHA256(psk, randSelf‖randPeer, "hichain_iso_session_key", 32)`; `encData = AES-GCM(challenge16, sessionKey, nonce12, AAD "hichain_iso_exchange")` | `:126-141` |
| op1 s3 reply | `authToken = GCM-decrypt(encAuthToken, sessionKey, nonce, AAD = challenge)`; `setSecretKey(authToken)` — **this is the long-term key** | `:237-243` |
| op1 s4 | `encResult = GCM(00000000, sessionKey, nonce, AAD "hichain_iso_result")` | `:147-156` |
| op2 (bind) | new request, operation 0x02, `psk = HMAC-SHA256(getSecretKey(), seed)`; **no step 3** | `:181-185`, `:210-213`, `:143-144` |
| op2 s4 reply | `final = HKDF-SHA256(sessionKey, randSelf‖randPeer, "hichain_return_key", 32)`; `setSecretKey(final)` persists it as `authkey` | `:186-196`, `HuaweiSupportProvider.java:872-880` |

Ours (`src/huawei/authMachine.ts`) computes the same values in the same order:

| Step | Ours | File:line |
|---|---|---|
| PIN | `parsePincodeResponse` decrypts with the static secret; the value is used only on the auth path | `:371-381`, `authPackets.ts:196-206` |
| op1 s1 | `randSelf = random(16)`, `seed = random(32)` | `:232-233`, `:243-244` |
| op1 s1 reply | `pinKey = sha256(utf8(hexdumpUpper(pinCode)))`, `psk = hmacSha256(pinKey, seed)` | `:411-416` |
| | verify `HMAC(psk, randPeer‖randSelf‖androidId‖authIdPeer)` | `:422-427` |
| op1 s2 | send `HMAC(psk, randSelf‖randPeer‖authIdPeer‖androidId)` | `:428-430` |
| op1 s2 reply | `HMAC(psk, 00000000)` compared in constant time | `:432-439` |
| s3/s4 | `hkdfSha256(psk, randSelf‖randPeer, "hichain_iso_session_key", 32)` | `:253-256` |
| op1 s3 | `encData = aesGcmEncryptNoPad(challenge16, sessionKey, nonce12, "hichain_iso_exchange")` | `:257-262` |
| op1 s3 reply | `aesGcmDecryptNoPad(encAuthToken, sessionKey, nonce, challenge)` → `key = decrypted` | `:441-450` |
| op1 s4 | `aesGcmEncryptNoPad(0000, sessionKey, nonce, "hichain_iso_result")` | `:451-454` |
| op2 | new operation, `psk = hmacSha256(key, seed)`, no step 3, step 4 sent with the captured message id 3 | `:456-468`, `:417-418`, `:264-267` |
| op2 s4 reply | `hkdfSha256(sessionKey, randSelf‖randPeer, "hichain_return_key", 32)` → `finalKey` | `:468-474` |

**Answer to B1:** the operation-1 key is `SHA-256` of the *uppercase hex string* of the decrypted PIN
(not the PIN bytes); `psk` is `HMAC-SHA256(that, seed)`; the final session/long-term key is the
watch-issued `authToken` used as the bind key, and then the bind's **return key**
(`HKDF(..., "hichain_return_key")`). Our implementation matches all of it — this is the strongest
single result in this document.
### B2. Does our design assume a locally generated key?

Yes, and that assumption is only valid for paths we deliberately do not implement.

- Upstream's `createSecretKey()` (`HuaweiSupportProvider.java:848-860`) makes a **random 16-byte**
  key when none is stored and uses it as the secret key. It is called from exactly three places:
  HiChainLite (`:737`), normal mode (`:760`), and the Honor PAKE path where it only opens the
  asynchronous-response gate and is never used as a cipher key (`:786-787`).
- On the HiChain path that key is **overwritten twice**: by the watch-issued token
  (`GetHiChainRequest.java:242`) and then by the bind return key (`:196`). A locally generated key can
  therefore never complete a HiChain bind — the watch performs the same HMAC check we do
  (`GetHiChainRequest.java:214-224`), so a random key fails at step 1.
- Our tooling: `--set-key --generate` writes 16 random bytes as 32 hex characters
  (`bcs_auth.sh:13`, `:49`, `:234-238`, `:257-260`, `:307-308`) — exactly upstream's
  `createSecretKey()` shape — and our own failure text offers it as *the* way to get a key
  (`bcs_auth.mjs:155`); `readKey()` documents "32 for a 16-byte key" (`bcs_auth.mjs:154`).
- Where a locally generated key **is** correct: HiChainLite (authType 0x01/0x02) and normal mode,
  where the phone's key *is* the shared secret used by the legacy digest challenge
  (`GetAuthRequest.java:73`, `:79`, `:104`). Both paths are refused by Phase 3 on purpose
  (`authMachine.ts:333-337`, `:364-368`).

**So:** for the only auth path we implement, a generated key is useless, and offering `--generate`
beside `--set-key` invites a user to produce one and then wonder why the bind fails. The fix is a
rename or a refusal (§G, item 2), not a change in the crypto.

### B3. Our "self auth id" versus upstream's

| | Upstream | Ours |
|---|---|---|
| Value | hex of 16 random bytes → **32 uppercase** chars | 32 chars drawn from `0123456789abcdef` → **32 lowercase** chars |
| Source | `HuaweiCrypto.generateNonce()` (`SecureRandom`, 16 bytes) + `StringUtils.bytesToHex` | `Math.random()`, one nibble at a time |
| Storage | device preference `PREF_FAKE_ANDROID_ID`, written once | `identity.json` in the state dir, `0600`, written once |
| On the wire | `getAndroidId()` = **UTF-8 bytes of the 32-char string** (32 bytes) | the 32 ASCII bytes of the string |
| Used as | SecurityNegotiation tag 0x05 (`GetSecurityNegotiationRequest.java:66`); HiChain `selfAuthId` (`GetHiChainRequest.java:101`); JSON `peerAuthId` / `peerDeviceId` / `connDeviceId` (`DeviceConfig.java:1079`, `:1112`, `:1198-1199`) | the same four places (`authMachine.ts:352`, `authPackets.ts:297-304`) |
| Lines | `HuaweiSupportProvider.java:924-939`, `GB.java:431`, `HuaweiCrypto.java:100-105` | `tools/bcs_auth.mjs:171-181`, `:575` |

Same construction, same length, **different characters** (case), and a weaker generator on our side.
Whether a watch that already trusts a Gadgetbridge-created id would accept our lowercase variant as
the same peer is device behaviour → **UNVERIFIED**. The id is not a secret, so this is an
interoperability risk, not a disclosure risk.

### B4. Every difference, marked

| # | Item | Upstream | Ours | Verdict |
|---|---|---|---|---|
| 1 | PIN digest input | `SHA-256(UTF-8(hex(pin)))`, uppercase hex | identical, `hexdumpUpper` | **MATCH** |
| 2 | `psk` (op1) | `HMAC(key, seed)` | identical | **MATCH** |
| 3 | `psk` (op2) | `HMAC(authToken, seed)` | identical | **MATCH** |
| 4 | `seed` / `randSelf` sizes | 32 B / 16 B | 32 B / 16 B | **MATCH** |
| 5 | Token verify order | `randPeer‖randSelf‖self‖peer` | identical (the upstream quirk is ported verbatim) | **MATCH** |
| 6 | Token send order | `randSelf‖randPeer‖peer‖self` | identical | **MATCH** |
| 7 | `returnCodeMac` | `HMAC(psk, 00000000)` | identical | **MATCH** |
| 8 | Session key | HKDF info `hichain_iso_session_key` | identical | **MATCH** |
| 9 | op1 s3 | GCM, AAD `hichain_iso_exchange`, nonce 12, challenge 16 | identical | **MATCH** |
| 10 | op1 s4 / op2 s4 | GCM, AAD `hichain_iso_result`, plaintext 4 × 0x00 | identical | **MATCH** |
| 11 | Auth token → key | `setSecretKey(authToken)` | `key = decrypted` | **MATCH** |
| 12 | Final key | HKDF info `hichain_return_key` | identical | **MATCH** |
| 13 | Bind step 4 message id | captured pre-increment `3` → `3 | 0x10` | `messageId: 3` | **MATCH** |
| 14 | JSON key order and set | `authForm, payload, groupAndModuleVersion, message`, then the op1 extras; `isDeviceLevel` only op2 s1/s2 | identical | **MATCH** |
| 15 | Where the key lives | device prefs `"authkey"`, hex text | memory; `derived.key` `0600` only with `--save-derived` | **DIFFERENT** (container, not value) |
| 16 | Self auth id case | uppercase hex | lowercase hex | **DIFFERENT** (D3) |
| 17 | Self auth id RNG | `SecureRandom` | `Math.random` | **DIFFERENT** (D4) |
| 18 | Locally generated key offered | Lite/normal only | `--set-key --generate`, presented generally | **DIFFERENT** (D5) |
| 19 | HiChainLite / normal / PAKE | implemented | refused | **DIFFERENT** (D10) |
| 20 | Request id | `System.currentTimeMillis()` | `BigInt(Date.now())` | **MATCH** |
| 21 | Whether the watch accepts a lowercase id | — | — | **UNVERIFIED** |
| 22 | Key files interchangeable between tools | same bytes, same hex text | — | **MATCH** in form; cross-tool use not tested → **UNVERIFIED** |

---

## C. Opening frames — the length our builders produce

**How these numbers were obtained.** The builders in `src/huawei/` were driven from a throw-away
script in `/tmp` with synthetic inputs (a 32-byte filler auth id, fill bytes for `randSelf`, `seed`,
`token`, `nonce`, `encData`, `encResult`, a fixed 13-digit `requestId`). The length reported is the
**whole packet** as it would be serialised — magic + 2-byte length + slice byte + service + command +
TLV + CRC16, i.e. `TLV + 8` (`frame.ts:18-30`, `:196-229`) — which is the same unit the real numbers
are quoted in: our op1 step 1 TLV is 687 bytes and the real frame is 695 = 687 + 8.

On the wire a packet is then sliced at the negotiated slice size (default `0xF4` = 244,
`constants.ts:107`), so a 695-byte packet leaves as three frames of 244 / 244 / 222
(`frame.ts:236-289`). The slice counts implied by the real sizes — 3, 3, 3, 3, 3, 2, 2 — are exactly
what ours produce, verified by running the splitter: op1 step 1 comes back as 3 frames of
244 / 244 / 222 (710 bytes on the wire), and the seven HiChain packets give 3, 3, 3, 3, 3, 2, 2.

| Frame (service/command) | Real GB | Ours | Match |
|---|---:|---:|---|
| LinkParams request (0x01/0x01) | 16 | **16** | yes |
| DeviceStatus request (0x01/0x16) | 10 | **10** | yes |
| SecurityNegotiation request (0x01/0x33) | 65 | **65** when `authMode` 4 and the model is 7 characters; 54 for `authMode` 2; 69 for an 11-char model | conditional — see below |
| PinCode request (0x01/0x2C) | 10 | **10** | yes |
| HiChain op1 step 1 | 695 | **695** | yes |
| HiChain op1 step 2 | 616 | **616** | yes |
| HiChain op1 step 3 | 573 | **573** | yes |
| HiChain op1 step 4 | 569 | **569** | yes |
| HiChain op2 step 1 | 547 | **547** | yes |
| HiChain op2 step 2 | 331 | **331** | yes |
| HiChain op2 step 4 | 262 | **262** | yes |

Where the two columns come from, stated plainly: the **Real GB** column is what a live Gadgetbridge
pairing on this machine logged during earlier work on this project (the capture itself is outside the
repository). This task did not repeat that session and did not re-read the capture, so that column is a
*record*. Everything in the **Ours** column was recomputed here by running our builders, with the
inputs listed above, and all eleven totals came out on the nose; the probe also reproduced the slice
split quoted above.

Seven HiChain frames from eight buildable steps is not a coincidence: the bind operation never sends
step 3 (`GetHiChainRequest.java:143-144`), so the sequence is op1 s1-s4 then op2 s1, s2, s4. (Our op2
step 3, which we *can* build, would be 266 bytes.)

**SecurityNegotiation is the only opening frame whose length is not fixed.** Its TLV is
`0x01` authMode, optional `0x02`, `0x05` = the auth id (2 + 32), `0x03`, `0x04`, plus `0x06` + `0x07`
only in mode 4, plus `0x0D` only when the watch asked for `encryptMethod == 1`
(`DeviceConfig.java:1865-1876`; ours `authPackets.ts:139-147`). Hence:

- mode 2 → 46-byte TLV → **54**;
- mode 4 → `58 + len(phoneModel)` → **65** for a 7-character model (`"Pixel 7"`), 69 for 11
  (`"Pixel 7 Pro"`), **75** for our own default `"Aether Health BCS"` (17);
- `+3` if `encryptMethod == 1` (the extra `0x0D` tag).

So a real 65 means `authMode` 4, a 7-character `Build.MODEL`, `encryptMethod != 1`, and a 32-byte auth
id. That is consistent with `GetSecurityNegotiationRequest.java:63-68` (it passes `Build.MODEL`).
Which branch *our* watch takes depends on its `deviceSupportType` (0x04 → mode 4, else mode 2,
`authMachine.ts:326`; upstream the same, `HuaweiSupportProvider.java:610-613`) — for our watch that
value is **UNVERIFIED** here, because reading it requires a live LinkParams reply and this task may not
touch the state directory.

**Fixed versus varying HiChain lengths.** All seven are fixed for a given auth-id length and clock:
every hex field is a fixed-size crypto output (isoSalt 16 B → 32 chars, seed 32 B → 64, token 32 B →
64, nonce 12 B → 24, encData 32 B → 64, encResult 20 B → 40 — see `authPackets.ts:242-266` and
`GetHiChainRequest.java:107-155`), and everything else in the JSON is a literal (`authPackets.ts:282-307`,
`DeviceConfig.java:1176-1202`). They would only change if the self auth id stopped being 32 characters
or `requestId` stopped having 13 decimal digits.

**What size agreement does and does not prove.** A single missing, extra or reordered JSON key, or one
hex field of a different size, would change these totals; seven independent exact matches therefore
say the field sets and their encoded sizes are the same as Gadgetbridge's. It is **not** a byte-for-byte
comparison of the JSON content, which would need a capture → **UNVERIFIED** at that level.

---

## D. Post-auth encryption — the Phase 4 spec

Everything below is read off `HuaweiPacket.java`, `HuaweiTLV.java`, `HuaweiCrypto.java`,
`HuaweiConstants.java` and `DeviceConfig.java`; no code was written.

1. **When a packet is encrypted.** `isEncrypted` defaults to `true` (`HuaweiPacket.java:274`).
   `serialize()` wraps the payload iff `isEncrypted && paramsProvider.areTransactionsCrypted()`
   (`:1097-1105`); otherwise the TLV goes out as-is (`:1103-1105`). `transactionsCrypted` also
   defaults to `true` (`:69`) and is set per device from the `force_encryption` preference, falling
   back to `HuaweiCoordinator.isTransactionCrypted()`, which returns `true`
   (`HuaweiSupportProvider.java:411-417`, `HuaweiCoordinator.java:87-89`).
2. **The envelope.** `HuaweiTLV.encryptRaw` returns a fresh TLV of exactly three entries
   (`HuaweiTLV.java:391-403`):
   `0x7C` = `0x01` (encrypted flag), `0x7D` = the IV, `0x7E` = the ciphertext. The tags are
   `CryptoTags.encryption/initVector/cipherText = 124/125/126` (`HuaweiConstants.java:47-51`).
   The ciphertext is over the *serialised TLV* of the original payload (`HuaweiTLV.java:405-408`).
3. **Cipher mode.** AES-GCM when `encryptMethod == 0x01 || deviceSupportType == 0x04`, AES-CBC with
   PKCS#7 padding otherwise (`HuaweiTLV.java:394-398`; `HuaweiCrypto.encrypt`/`decrypt`
   `:259-277`). `encryptMethod` is LinkParams tag `0x0C` (`DeviceConfig.java:113-114`), i.e. the
   **watch** decides. GCM is used with **no AAD** (`...GCM_NoPad(message, key, iv, null)`,
   `HuaweiCrypto.java:262`) and therefore carries a 16-byte tag appended to the ciphertext.
4. **IV and counter.** `ParamsProvider.getIv()` (`HuaweiPacket.java:150-160`):
   - `deviceSupportType == 0x04` → 16 fresh random bytes per packet (`HuaweiCrypto.generateNonce`,
     `:100-105`);
   - otherwise → `HuaweiCrypto.initializationVector(counter)` (`:199-210`): **12 random bytes**, then
     a **4-byte big-endian counter** in bytes 12-15. The counter is incremented *before* use, wraps
     from `0xFFFFFFFF` to `1` (`ENCRYPTION_COUNTER_MAX`, `:82`, `:200-204`), and is read back out of
     the IV's last four bytes into the provider (`HuaweiPacket.java:157`). Because 12 bytes are fresh
     each time, the IV never repeats even if the counter did.
5. **The key.** `paramsProvider.getSecretKey()` (`HuaweiTLV.java:392`, `:411`) — that is the *final*
   HiChain key from bind step 4 (`GetHiChainRequest.java:186-196`), or the locally chosen key in
   Lite/normal mode (`HuaweiSupportProvider.java:848-860`). Both are 16 bytes on the Lite/normal path
   and 32 bytes after a HiChain bind, per the two `setSecretKey` call sites.
6. **Packets sent *without* encryption.** Every `isEncrypted = false` site in `DeviceConfig.java` (the
   base default is `true`, `HuaweiPacket.java:274`): LinkParams request and response (`:63`, `:84`),
   SupportedCommands **response** (`:308`), ProductInfo **response** (`:472`), DeviceStatus request and
   response (`:907`, `:921`), Bond request and BondParams request and response (`:526`, `:571`, `:586`),
   PinCode request and response (`:1707`, `:1718`), Auth request and **response** (`:648`, `:679`),
   BatteryLevel **response** (`:717`), SecurityNegotiation request and response (`:1880`, `:1906`), the
   whole HiChain packet class (`:1057`) and the HiChain response (`:1440`). Note the shape of that list:
   a *request* can be encrypted while its *reply* is not (SupportedCommands, ProductInfo, Auth,
   BatteryLevel), so "we sent ciphertext and got plaintext back" is the normal case for those four and
   must not be treated as an error. Everything else — SupportedServices, account, and every data
   service — is encrypted once a key exists.
7. **How replies are decrypted.** The generic parser splits and CRC-checks the frame, then dispatches
   on `(serviceId, commandId)` to the matching subclass `fromPacket(this)`
   (`HuaweiPacket.java:437-470`). `fromPacket` keeps `isEncrypted` if the subclass wanted ciphertext,
   otherwise calls `attemptDecrypt()` (`:315-318`). `attemptDecrypt()` looks for tag `0x7C` with a
   truthy value and, if present, calls `HuaweiTLV.decrypt(paramsProvider)` (`:282-300`), which
   decrypts `0x7E` with the IV in `0x7D` and re-parses the plaintext into the TLV
   (`HuaweiTLV.java:410-423`). "Expected ciphertext, received plaintext" is not an error — it is a
   TODO comment (`HuaweiPacket.java:294-298`).
8. **Order of operations.** Encrypt the TLV, *then* slice (`:1097-1113`); on receive, reassemble the
   slices and check the CRC before decrypting (`:335-415`). So the envelope is span-of-packet, never
   span-of-slice.

**Two notes for our Phase 4 implementation.** (a) Our `encodeFrame` currently defaults
`transactionsCrypted` to `false` (`frame.ts:294`) while upstream's equivalent default is `true`
(`HuaweiPacket.java:69`); when the cipher lands, that default has to flip or the first "encrypted"
transaction would silently go out as plaintext. (b) The counter is **per connection**, not per packet
type: one monotonic value for every encrypted packet on the link (`HuaweiPacket.java:71`, `:155-158`),
so it belongs on the transport object, not in a packet builder.

---

## E. Timing

### E1. Upstream

| Wait | Value | Where |
|---|---:|---|
| LinkParams reply | **no timeout at all** | the request is created without `setupTimeoutUntilNext` (`HuaweiSupportProvider.java:517-518`, `:539`), `Request.timeout` stays `null` (`Request.java:120`) and the timer is only armed when non-null (`:367-369`) |
| HiChain, first connect | **30 000 ms** | `GetHiChainRequest.java:57`, `:64-66` — the comment on `:56` is explicit: the user may have to confirm on the device |
| HiChain, later connects | **5 000 ms** | `GetHiChainRequest.java:58`, `:67-69` |
| Each request of the post-auth init queue | **2 000 ms** | `HuaweiSupportProvider.java:254`, applied at `:835-839` |
| Configure step | on timeout: log, `reportPairingError`, state → `WAITING_FOR_RECONNECT` | `HuaweiSupportProvider.java:684-691` |
| **RFCOMM connect** | **none** | `mBtSocket.connect()` blocks (`BtBRQueue.java:207`); the only knob is `mConnectDelayMillis`, a sleep *before* connecting, default `0` (`:195-202`, `AbstractBTBRDeviceSupport.java:288-290`), and Huawei does not override it |

So the ~41 s a failed connect took in the real log is the Linux/BlueZ connect timeout, not a
Gadgetbridge timer — GB has nothing that would cut it. Conversely, GB would also wait happily forever
for a LinkParams reply.

### E2. Ours

| Wait | Value | Where |
|---|---:|---|
| Sidecar connect (default) | **10 s** | `DEFAULT_CONNECT_TIMEOUT` (`rfcomm_sidecar.py:41`), applied as `settimeout()` before `connect()` (`bcs_bt.py:183`, `:202`) |
| Sidecar connect (per command) | `timeout_ms` clamped to **1–30 s** | `rfcomm_sidecar.py:189-192`, `MAX_CONNECT_TIMEOUT` (`:42`) |
| TS client | `connectTimeoutMs` default **10 000**, sent as `timeout_ms`, answer awaited for timeout + 1 s | `sidecarTransport.ts:122`, `:274-275` |
| Idle read | 1 s, then loop | `rfcomm_sidecar.py:40`, `:196-198` |
| Auth, per state | 5 000 ms, 30 000 ms for the first HiChain step and the pin code | `authMachine.ts:127-129`; applied at `bcs_auth.mjs:307-311` |
| Whole run | 120 000 ms | `bcs_auth.mjs:142`, `:595-599` |

### E3. Should the connect timeout change?

No — but the *sentence* should.

- A good connect is under 0.5 s in the observed log, so 10 s is a 20× margin; no plausible healthy
  connect needs more.
- The 41 s case is a pathological failure, and our 10 s cap (30 s maximum) cuts it earlier than the
  stack would — strictly better for the user, and the harness stays bounded even if a future kernel
  waits longer. Note that the cap of 30 s is *below* the observed 41 s, so a stuck link is always cut
  by us, never by the kernel.
- The real defect is diagnostic: `classify_connect_error` maps both `ETIMEDOUT` and Python's
  `socket.timeout` to the same "the connection attempt timed out; the watch may be off, out of range,
  or busy" (`bcs_bt.py:165`, `:170-171`). When *we* cut at 10 s that sentence blames the watch for a
  decision we made. A one-line distinction ("no answer within the 10 s this helper allows" vs "the
  Bluetooth stack reported a timeout") costs nothing and removes a false lead.
- A change to the default would need evidence of a *good* connect taking longer than 10 s; there is
  none here → the current value stays, and `--connect-timeout` / `timeout_ms` remain the documented
  escape hatch.

One more timing note that belongs with section A: if `--bt-security medium` is ever made the default,
an unbonded watch fails the connect with `EACCES`/`EPERM`, which today becomes "permission denied for
Bluetooth sockets; check your user's access to the Bluetooth daemon" (`bcs_bt.py:67-68`) — the wrong
advice for that failure. That mapping has to be fixed in the same change.

---

## F. The account frame

### F1. What upstream does

- **One frame**: service `0x1A`, command `0x05`, `SendExtendedAccountToDevice`
  (`AccountRelated.java:52-74`). The legacy `0x01` (`:25-43`) still exists in the code but nothing
  queues it.
- **Queued where**: in `initializeDynamicServices()`, i.e. **after** the whole handshake and the first
  four init requests — `initRequestQueue.add(new SendExtendedAccountRequest(this))`
  (`HuaweiSupportProvider.java:996`, `:1054`). It belongs to the dynamic-services queue, not to
  authentication.
- **Gate**: `requestSupported()` returns
  `getDeviceState().supportsAccountJudgment() && ...supportsAccountSwitch()`
  (`SendExtendedAccountRequest.java:41-43`; the two flags are at `HuaweiState.java:516-522`). If the
  watch does not advertise both, the request is skipped.
- **Value**: `PREF_HUAWEI_ACCOUNT`, trimmed, defaulting to `""` (`SendExtendedAccountRequest.java:47-49`).
  Tag `0x01` = the digits as UTF-8, or `0x00` when the value is empty; tag `0x03` = `0x01` iff the
  device supports the "diff account pairing optimization" (`AccountRelated.java:62-72`;
  `SendExtendedAccountRequest.java:52-54`).
- **Encryption**: the packet sets no `isEncrypted = false`, so it keeps the default `true`
  (`HuaweiPacket.java:274`) and goes out inside the 0x7C/0x7D/0x7E envelope with the final key — it is
  exactly the frame that cannot exist before §D does.

### F2. What our code does with the account today

| Layer | What it does | File:line |
|---|---|---|
| Builders | `sendAccountRequest` (0x1A/0x01) and `sendExtendedAccountRequest` (0x1A/0x05) with tag 0x01 + optional 0x03, identical to upstream's constructors | `src/huawei/requests.ts:206-235` |
| Validation | 17-19 digits, digits only, trimmed; refusals carry the length, never the value | `src/huawei/account.ts:46-91` |
| Plan | `accountFramePlan` returns the packet plus `needsTransactionCipher: true` and the digit count | `src/huawei/account.ts:93-130` |
| Encoding | refuses **every** form except `transactionsCrypted === false`, with code `account-needs-cipher` | `src/huawei/account.ts:138-151` |
| Driver | `--with-account` reads the file, validates, builds the plan, calls the encoder and exits **3** on the refusal — before the sidecar is spawned | `tools/bcs_auth.mjs:342-358`, `:360-390`, gated at `:500-503` |
| Storage | `--set-account` writes it `0600`, directory `0700`, value never displayed | `tools/bcs_auth.sh:339`, `:373-388` |
| Sidecar | `(0x1A,0x01)` and `(0x1A,0x05)` are in the write allowlist so the gate cannot reject a frame the builder produces | `sidecar/rfcomm_sidecar.py:51-65` |

Net: **no account byte has ever been sent.** The path stops at a typed refusal, and a run that would
send it exits before a socket exists. That is deliberate and documented (`bcs_auth.sh:511-512`,
`:556-560`, `:649-661`).

### F3. What Phase 4 must add

1. **The cipher (§D) first** — the frame is meaningless unencrypted; upstream always encrypts it.
2. **A post-auth send step** in the driver: after the bind produces `finalKey`, build 0x1A/0x05,
   encrypt with that key and write it through the existing allowlisted sidecar path. Ordering anchor:
   upstream sends it in the dynamic-services queue (`HuaweiSupportProvider.java:1054`), which runs
   after `initializeDeviceConfigure` (`:779-845`) — after auth, never during it.
3. **A capability gate.** Upstream's two flags come from its own capability table
   (`SendExtendedAccountRequest.java:41-43`) and are themselves two command probes:
   `supportsAccountJudgment()` is `supportsCommandForService(0x1A, 0x05)` and
   `supportsAccountSwitch()` is `supportsCommandForService(0x1A, 0x06)`
   (`HuaweiState.java:512-522`). So the faithful local gate is the watch's `SupportedCommands` reply
   (0x01/0x03, already buildable: `requests.ts:122-146`) advertising **both** `(0x1A, 0x05)` and
   `(0x1A, 0x06)` — note that 0x06 is only ever *probed* here, never written, which is why the write
   allowlist holds only `(0x1A, 0x01)` and `(0x1A, 0x05)` (`rfcomm_sidecar.py:63-64`). Whether
   "advertises both commands" is a faithful substitute for upstream's two flags is **UNVERIFIED** —
   it is the closest thing we can read without GB's device database, and the code should say so.
4. **Reply handling** — upstream only logs (`SendExtendedAccountRequest.java:61-64`); ours should
   record "sent / no reply / refused" in the run journal, never the value.
5. **Decide the empty case.** Upstream *sends* tag 0x01 = `0x00` when the pref is empty
   (`AccountRelated.java:66`); we refuse an empty account before a frame exists (`account.ts:71-73`).
   Either is defensible; the difference has to be explicit (D11).
6. Keep the value out of the sidecar and out of every log line — already true and worth preserving:
   the account is read by the driver only (`bcs_auth.mjs:342-358`), and the sidecar never sees it.

---

## G. Recommended order of fixes

Cheapest and highest-risk-first; each item names its §. Items 1–5 (D3, D5/D4, D1/D2, E3, D6) were
implemented in Phase 3G without changing any default — see `docs/BCS_PHASE3.md` §12.

One divergence this document did not list was closed in the same phase. The pin code on the
auth-then-bind path is now the watch's, not the user's: `PinCode.Request` (`0x01`/`0x2C`) is sent and its
reply decrypted with the **static** digest secret — exactly the shape §B4 row 1 and §C already require of
the digest input, and never the auth key (`DeviceConfig.java:1419-1462`,
`HuaweiSupportProvider.java:564-578`, `GetHiChainRequest.java:206-213`). The prompt that used to supply it
is now opt-in (`--pin`), so a default run no longer asks a person for a value upstream reads off the wire.
`docs/BCS_PHASE3.md` §13 has the two paths side by side.

1. **D3 — self auth id case** (`tools/bcs_auth.mjs:178`). One line: uppercase hex, as `GB.java:431`
   does. Cheapest change here and the one most likely to decide whether a watch that already trusts a
   Gadgetbridge id treats us as the same peer. It is also the only item where "different" may already
   be breaking interoperability today.
2. **D5 — stop presenting `--set-key --generate` as a way to obtain *the* auth key**
   (`bcs_auth.mjs:155`, `bcs_auth.sh:13`). Either rename it (`--generate-lite`) or have the driver
   refuse a generated key once the negotiated path is HiChain. A message change that removes a whole
   class of "the bind fails and I do not know why" runs. D4 folds in here if the id is regenerated at
   the same time.
3. **D1/D2 — opt-in link security and bond precondition** (§A3). New sidecar flags, two new codes, a
   bond probe before the socket, and a corrected `EACCES`/`EPERM` sentence. Keep both default-off so
   nothing that works today can regress.
4. **E3 — the connect-timeout sentence** (`bcs_bt.py:160-174`). Tiny, diagnostic-only, and it removes
   a false lead from every future failed run. Do it with item 3, because the same function gains the
   bond-refusal branch.
5. **D6 — the phone model in SecurityNegotiation** (`authMachine.ts:134`). Cosmetic per our own
   comment, but it is a visible wire difference and it is the one opening frame whose length we cannot
   match without knowing upstream's input. Make it configurable, or send a GB-like value.
6. **D8 → D7 — Phase 4: the cipher, then the account**, in that order, enforced by the code.
   `encodeAccountFrame` is what keeps the order honest today (`account.ts:142-149`); after the cipher
   lands, flip `encodeFrame`'s `transactionsCrypted` default (§D note (a)) in the *same* commit as the
   first encrypted builder, or a plaintext frame could slip out.
7. **D10 — HiChainLite / normal / Honor PAKE.** Largest scope by far and the only item needing new
   cryptographic constructions (legacy digest challenge, PBKDF2, the PAKE/STS exchange). Nothing else
   in this list depends on it.

---

## What this document could not verify

Listed so nobody has to guess later.

- **The upstream commit id** — reading it needs a git command, which the brief forbids. The tree is
  identified by `app/build.gradle:96` (`2026.11.1`) only.
- **The security level BlueZ gives our client socket today**, and the level Android negotiates for
  `createRfcommSocketToServiceRecord` (§A1).
- **Whether our watch accepts a lowercase self auth id** it has not seen before (§B3).
- **Our watch's `deviceSupportType`**, and therefore which `authMode` and which SecurityNegotiation
  length our own runs would produce (§C). That needs a live LinkParams reply, which this task may not
  obtain.
- **Byte-for-byte equality of the HiChain JSON with a real session.** The seven lengths match exactly,
  which is strong evidence but not a content comparison (§C).
- **Whether advertising `(0x1A, 0x05)` and `(0x1A, 0x06)` is equivalent to upstream's
  `supportsAccountJudgment && supportsAccountSwitch`** (§F3).

---

*One file was created by this task: `docs/BCS_UPSTREAM_COMPARE.md`. No code, test, tool, doc or
configuration was modified. The frame-length and slicing figures in §C were recomputed here with a
throw-away script under `/tmp` that imports our own TypeScript modules with synthetic inputs; that
script is not part of the repository and no capture, key or account file was read.*
