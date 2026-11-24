# BCS Phase 3 — trust: the HiChain authentication state machine

Phase 3 of the Butterfly Connectivity System, as planned in `docs/BCS_PHASE0.md`. Phase 1 opened a
classic-Bluetooth RFCOMM link to the watch; Phase 2 made the wire format; **Phase 3 is what the phone
and the watch say to each other before either of them trusts the other** — the app-level handshake,
ported from Gadgetbridge's HiChain flow, in pure code, with no transport attached to any of it.

Deliverable: `bcs/helper/src/huawei/{crypto,authErrors,authPackets,authMachine}.ts` plus their tests,
and one live script that is written and deliberately not run (`bcs/helper/tools/bcs_auth.sh`).

Status: **complete and green — 369 TypeScript tests and 209 Python tests, zero failures**, of which 68
TypeScript tests are new in this phase. Nothing in Phase 3 opens a socket, starts a process, sets a
timer, reads a file, or writes a byte to any watch. The key is copied on construction, lives in
memory, and is zeroed by `destroy()`.

## 1. What Phase 3 had to produce

1. The **crypto primitives** the flow needs — SHA-256, HMAC-SHA256, HKDF-SHA256, PBKDF2-SHA256,
   AES-GCM, AES-CBC, AES-ECB, and the hexdump convention that feeds the digest inputs.
2. The **auth packets**: link parameters, device status, security negotiation, pin code, and the
   HiChain JSON envelope with its four steps.
3. The **sequence**: a state machine that, given the frame it is waiting for, returns the frames the
   caller should send — and a typed stop for anything else.
4. The **key derivations**: `psk = HMAC(key, seed)`, the session key, the auth-token hand-off, and the
   final key the bind operation returns.
5. A guarantee that can be checked rather than asserted: **no key material in an error, a log line,
   or the bytes sent** (`test/authKeyLeak.test.ts`).

Phase 3 does **not** open a link (Phase 1), does **not** frame or reassemble bytes (Phase 2), and does
**not** read the user's auth code itself — the caller supplies the key bytes. Actually using it
against a watch is Part 3B, which is written down and not executed.

## 2. Files added

Under `bcs/helper/`. Line counts include the file-level attribution headers.

| File | Lines | Tests | What it is |
|---|---:|---:|---|
| `src/huawei/crypto.ts` | 379 | 19 | SHA-256, HMAC-SHA256, HKDF-SHA256, PBKDF2-SHA256, AES-GCM/CBC/ECB, `hexdumpUpper`, `hexToBytes`, `zeroBytes`, `bytesEqualConstantTime`, the three digest secrets, `generateNonce`, and `createHuaweiCrypto` (`computeDigest`, `computeDigestHiChainLite`, `digestChallenge`, `digestResponse`, `decryptPinCode`) |
| `src/huawei/authErrors.ts` | 71 | — | The auth error taxonomy (`auth-unsupported`, `auth-state`, `auth-truncated`, `auth-refused`, `auth-mac-mismatch`, `auth-token-mismatch`, `auth-negotiation`, `auth-pincode-missing`, `bad-key`, `bad-argument`, `bad-length`, `crypto-failed`) and `isHuaweiAuthError` |
| `src/huawei/authPackets.ts` | 420 | 24 | `parseLinkParams`, `authPathFor`, `deviceStatusRequest`/`parseDeviceStatus`, `securityNegotiationRequest`/`parseSecurityNegotiation`, `isHiChain3`, `pincodeRequest`/`parsePincodeResponse`, `hiChainRequest`, `parseHiChainResponse` |
| `src/huawei/authMachine.ts` | 478 | 23 | `createAuthMachine`: the state machine, the MAC checks, the key derivations, `destroy()` |
| `src/huawei/constants.ts` | +7 | — | Four command ids added to `DEVICE_CONFIG`: `deviceStatus 0x16`, `hiChain 0x28`, `pinCode 0x2C`, `securityNegotiation 0x33` |
| `src/huawei/index.ts` | +73 | — | Phase 3 re-exported from the barrel (89 value exports in total, checked by importing it) |
| `test/huaweiCrypto.test.ts` | 365 | 19 | Published vectors (see §7) plus hand-rolled second implementations |
| `test/huaweiAuthPackets.test.ts` | 420 | 24 | Every request and every parse, against values read from upstream |
| `test/huaweiAuthMachine.test.ts` | 761 | 23 | The sequence, the arithmetic and every refusal, driven by synthetic frames |
| `test/authKeyLeak.test.ts` | 347 | 2 | The leak guarantee, and a control proving the detectors work |

**1348 lines of Phase 3 code, 1893 lines of tests, 68 tests.** No dependency was added: Node strips
the TypeScript itself, so `node --test` runs the `.ts` files directly.

`bcs/helper/package.json` gained `test:auth` (the four Phase 3 test files); `test:codec` is unchanged
for Phase 2. Its current version is `0.3.0-phase3g` (Phase 3G, §12 and §13), which is the sub-phase the
sidecar advertises as `VERSION = "bcs-helper-phase3g"`; the two strings name the same tree.

## 3. The flow, in the order the watch sees it

Each row is one state of `createAuthMachine`; the machine produces the request for that state and
waits for the reply it names. Anything else is a typed stop in state `failed` — there is no path back
into the flow and nothing is retried.

| State | We send | We wait for | Ported from |
|---|---|---|---|
| `start` | — | — | — |
| `link-params` | `DeviceConfig.LinkParams.Request` (`0x01`/`0x01`) | the watch's link parameters: authVersion, server nonce, deviceSupportType, authAlgo, encryptMethod, slice size | `HuaweiSupportProvider.java:405-473`, `DeviceConfig.java:43-123` |
| `device-status` | `DeviceStatus.Request` (`0x01`/`0x16`) | a status byte: `-1`, `0` or `1` means "authenticate now" | `:451-465`, `DeviceConfig.java:858-902` |
| `security-negotiation` | `SecurityNegotiation.Request` (`0x01`/`0x33`), authMode 4 for deviceSupportType 4, otherwise 2 | an authType: `0x186A0` or the two HiChain3 values (5, 6) | `:497-529`, `DeviceConfig.java:1575-1640` |
| `pincode` (auth-then-bind, no pin supplied) | `PinCode.Request` (`0x01`/`0x2C`) | the pin code, AES-encrypted with the **static digest secret** | `:564-578`, `DeviceConfig.java:1419-1462` |
| `hichain-bind-step1` | step 1: `isoSalt` (randSelf), `seed`, `operationCode 2`, `pkgName`, `serviceType`, `keyLength`, message `0x11` | `isoSalt`, `peerAuthId`, `token` | `GetHiChainRequest.java:60-125` |
| `hichain-bind-step2` | step 2: `peerAuthId`, `token`, message `0x12` | `returnCodeMac` | `:126-135` |
| `hichain-bind-step4` | step 4 directly — the bind operation never sends step 3 — message `0x13` (see §4.1) | the result (a non-zero type, raw data in tag `0x01`) | `:136-155`, `:186-197` |
| `done` | — | — | the final key is `HKDF(sessionKey, randSelf‖randPeer, "hichain_return_key", 32)` |

The `auth-then-bind` mode runs the auth operation (`operationCode 1`, messages `1..4`, the requestId
and group block in the envelope) first, and on its step-4 reply starts a **new** bind operation keyed
by the auth token the watch just returned — exactly the "finished auth operation, go to bind"
transition upstream makes at `:181-185`.

The two derivations that matter (`GetHiChainRequest.java:113-132`):

```
psk        = HMAC(authKey, seed)                       (bind)      :113-120
psk        = HMAC(SHA256(hexdump(pin)), seed)           (auth)      :207-209
sessionKey = HKDF(psk, randSelf ‖ randPeer, "hichain_iso_session_key", 32)   :126-132
key        = HKDF(sessionKey, randSelf ‖ randPeer, "hichain_return_key", 32) :186-197
```

## 4. Findings — what was verified rather than assumed

### 4.1 The bind operation's step 4 really does send message `0x13`, not `0x14`

Upstream captures `int messageId = step;` at `GetHiChainRequest.java:105`, increments `step` at `:144`
on the bind path only, and then builds `StepFour` with the **captured** value at `:154`. So the bind
operation's messages are `0x11`, `0x12`, `0x13`, while the auth operation's are `1`, `2`, `3`, `4`.
The commented-out lines in `StepFour` (`:1094-1098`) show the upstream author meeting the same
question and leaving the captured value in place. This port reproduces it, with a `messageId` override
on `HiChainStepInput` that exists for this one call site, and a test that fails if it changes.

### 4.2 The step-2 token is sent in one order and verified in the other

The token **we send** at step 2 is `HMAC(psk, randSelf ‖ randPeer ‖ authIdPeer ‖ authIdSelf)`
(`:115-123`); the token **we verify** from the watch at step 1 is
`HMAC(psk, randPeer ‖ randSelf ‖ authIdSelf ‖ authIdPeer)` (`:214-220`). Same four blocks, mirrored
order. Both are reproduced as they are: "fixing" either would break interop, so
`test/huaweiAuthMachine.test.ts` asserts both orders, and asserts that they differ.

### 4.3 `GB.hexdump` is uppercase, and that matters

`HEX_CHARS = "0123456789ABCDEF"` (`util/GB.java`). Every hex string that goes into a digest or a MAC —
`isoSalt`, `seed`, `token`, the pin code's digest input, the HiChainLite key — is uppercase. A
lowercase hexdump would produce a different MAC and a handshake that fails on the watch with no
diagnostic. `hexdumpUpper` is the only hexdump in this codebase, and the crypto tests assert the case.

### 4.4 Upstream ships almost no crypto vectors

`TestHuaweiCrypto.java` has exactly **one** test: a nonce is 16 bytes and varies over 1000 rounds.
Everything else in this phase is therefore checked against published, external vectors — FIPS-197
(AES-128/ECB), NIST SP 800-38A F.2.1 (AES-128/CBC), RFC 4231 case 1 (HMAC-SHA256), RFC 5869 case 1
(HKDF-SHA256), and the standard PBKDF2-SHA256 `c=1`/`c=2` vectors — plus a second, hand-rolled
implementation of each chain in the test file. The one upstream behaviour that *is* ported as a vector
is the nonce test.

### 4.5 Two real defects, found by the first test run

Recorded because they are the point of writing the tests:

1. `authMachine.ts` used `DEVICE_CONFIG` without importing it. TypeScript stripping does not
   type-check, so this was a `ReferenceError` at the first `onFrame` — the whole suite failed until
   the import was added. It is the kind of defect a type checker would have caught, and this
   project's `jsconfig.json` does not cover `bcs/`.
2. `destroy()` mid-flow wiped the handshake's secrets, and the next `onFrame` handed `null` to
   `crypto.createHmac`, throwing `ERR_INVALID_ARG_TYPE` out of a function whose contract says every
   failure is a typed stop. Three guards were added (step 1 without a seed, step 2 without a psk, the
   bind result without a session key); each now stops with `auth-state` and
   "…no handshake in progress". A destroyed machine refuses; it does not crash.

## 5. Deliberate divergences from upstream

| Upstream | Here | Why |
|---|---|---|
| throws `RequestCreationException`, `ParseException` subclasses, `CryptoException` | every failure is a `CodecResult` error with a `HuaweiAuthErrorCode` | a state machine fed a live link must return its failures, and the caller needs to know *which step* stopped |
| logs digests, hexdumps and the session key at debug level | nothing is logged, and no function here accepts a logger | a key that never reaches a logger cannot leak through one |
| holds the key in a `SecretKeySpec` for the life of the service | copies the key on construction, zeroes every intermediate buffer, and `destroy()` zeroes the lot | least time in memory; best effort, since the runtime keeps its own copies |
| `HuaweiCrypto.createSecretKey(macAddress)` (`:207-229`), `Bond`/`BondParams` | not ported | they belong to the bonding path, which Phase 3 does not implement |
| compares MACs with `Arrays.equals` | `bytesEqualConstantTime` compares in constant time after a length check | a MAC check that leaks timing is a MAC check that can be probed |

## 6. What Phase 3 deliberately does not do

- **No transport.** `createAuthMachine` never opens, reads, writes or closes anything, and the phase
  imports no `node:net`, no `child_process` and no socket. Bytes come in as `HuaweiFrame` values and
  go out as `Uint8Array`s; that is the whole interface.
- **No timers and no retries.** The machine reports `timeoutMs` for the current state and leaves the
  waiting to the caller. Each number below names the step it belongs to, and says whether it is
  upstream's or this port's:
  - **2 000 ms — upstream's initialization timeout, which this port does *not* use.**
    `HuaweiSupportProvider.initTimeout = 2000` (`HuaweiSupportProvider.java:203`) is what upstream
    arms for every request in the initialization queue (`:665`, `:668`, `:833`, `:841`), i.e. for
    LinkParams, DeviceStatus and SecurityNegotiation. Those are the "5 s steps" below: this port
    reports 5 000 ms there, deliberately more than upstream's 2 s, because a live run over a slow
    link should not be called a silence at 2 s.
  - **30 000 ms — the first HiChain step of an `auth` operation.**
    `GetHiChainRequest.firstAuthenticateTimeout = 30 * 1000` (`GetHiChainRequest.java:57`), armed
    only for a first connection (`:64-66`) because the person may have to confirm on the watch.
    Ported as `FIRST_HI_CHAIN_TIMEOUT_MS` and returned for `hichain-auth-step1` only
    (`authMachine.ts:127-129`, `:274-279`).
  - **5 000 ms — a later HiChain step.** `GetHiChainRequest.authenticateTimeout = 5000`
    (`GetHiChainRequest.java:58`), armed when the connection is not the first one (`:67-69`). Ported
    as `STEP_TIMEOUT_MS`; it is also what this port reports for every other step, including bind
    step 1, which upstream does not bound with 30 s — only the `auth` operation is
    (`authMachine.ts:274-279`).
  - **30 000 ms — the pin-code step, and this number is the port's choice, not upstream's.**
    `GetPincodeRequest` never calls `setupTimeoutUntilNext` (`GetPincodeRequest.java:32-36`), so
    `Request.timeout` stays `null` and upstream arms no timer at all (`Request.java:350-351`): it
    would wait forever. This port reuses the 30 s "a person is reading the watch" bound instead,
    because that is exactly what the step waits for.
- **No HiChainLite.** `deviceSupportType 0x02`, a `normal` device, and a legacy digest `authType`
  all stop with `auth-unsupported` and a message naming what was negotiated. The legacy digest path
  in service `0x01` command `0x13` is not implemented, and pretending otherwise would be worse than
  refusing.
- **No bonding path.** `createSecretKey`, `Bond`, `BondParams` and the mac-address-derived key are
  out of scope.
- **No key storage.** The phase reads no file, no cookie, no account value and no preference. Where
  the key comes from is the caller's business; Part 3B reads it from
  `~/.config/aether-bcs/auth-key.txt` with mode `0600`.
- **No health data.** Nothing in this phase reads a sample, an export or a database.

## 7. How it is verified

| What | How |
|---|---|
| The crypto | Published vectors: FIPS-197 AES-128/ECB, NIST SP 800-38A F.2.1 AES-128/CBC, RFC 4231 case 1 HMAC-SHA256, RFC 5869 case 1 HKDF-SHA256, PBKDF2-SHA256 `c=1` and `c=2`; plus a hand-rolled second implementation of each chain, and the one upstream vector that exists (nonce length and spread) |
| The packets | Values read from upstream and re-derived by hand: the JSON key order, the `0x10` message mask, `isDeviceLevel` only on bind steps 1-2, the requestId as a big-endian 8-byte long, the tag numbers of every request |
| The sequence | `test/huaweiAuthMachine.test.ts` drives the machine from `start` to `done` with synthetic frames, a fixed RNG and a fixed request id, and recomputes every token, MAC, session key and final key independently of the machine's own code |
| The refusals | Wrong key → `auth-token-mismatch`; tampered MAC → `auth-mac-mismatch`; out-of-order step → `auth-state` naming both steps; non-zero `errorCode` → `auth-refused`; missing JSON field → `auth-truncated` naming the field; HiChainLite / `normal` / legacy digest → `auth-unsupported`; empty key → `bad-key`; a destroyed machine → `auth-state` |
| The key-leak rule | `test/authKeyLeak.test.ts` runs nine paths (eight of which fail) plus one full success with a synthetic key, then searches every error string, every rendered error object and every byte the machine asked to send for that key's uppercase hex, lowercase hex, base64, unpadded base64 and raw bytes — and for the derived key as well. A control test proves the detectors find a deliberate leak, and the console is captured to prove the machine never writes to it |

## 8. Part 3B — the live script, written and not run

`bcs/helper/tools/bcs_auth.sh` (529 lines) plus `bcs/helper/tools/bcs_auth.mjs` (407 lines) are the
live step. They mirror the Phase 1 script's conventions on purpose:

- `--plan` prints exactly what a live run would do and touches nothing; `--self-test` runs the Phase 3
  suites offline and reports whether the live path is blocked.
- A live run refuses to start without a terminal, and then requires the word `AUTHENTICATE` typed by a
  person. There is no unattended mode, by design.
- The key is read from `~/.config/aether-bcs/auth-key.txt`, mode `0600` checked first, and is never in
  argv, never echoed and never written to a log. The pin code is asked of the watch rather than of the
  user: `PinCode.Request` (`0x01`/`0x2C`) is sent and its reply decrypted in memory with the static
  digest secret (§13). `--pin` is the opt-in fallback for a watch that does not answer that request, and
  only then is a pin typed at a hidden prompt and piped on stdin — not in argv, not in the environment,
  not in a file.
- Every line the driver produces goes through a masker, so an address that slipped into a message
  still leaves as `XX:XX:XX:XX:AA:BB`.
- The derived key is never printed. It is kept only with `--save-derived`, and then only in
  `$XDG_STATE_HOME/aether-bcs/derived.key` with mode `0600`, as Phase 4 material.
- Exit codes: 0 done, 1 flow stopped (typed code printed), 2 could not start, 3 blocked, 4 timed out,
  5 link ended.

The live step remains intentionally unrun. Phase 3C adds a `write` command restricted to the five
service/command pairs emitted by the auth flow, with complete frame, CRC, size and connection-budget
validation before `sendall`. The driver and shell wrapper query the running sidecar's `ping`
capabilities and require `write`; neither inspects sidecar source. The allowlist drift test derives
the expected ids from `constants.ts` and `authPackets.ts`.

### 8.1 The key file: hex, generated locally, and what it is *not*

`readKey()` in the driver and `set_key()` in the wrapper accept exactly one representation: non-empty,
**even-length hexadecimal text**, decoded to bytes. Two ways to fill the file:

| Command | What it does |
|---|---|
| `bash tools/bcs_auth.sh --set-key --generate` | `node -e 'require("node:crypto").randomBytes(16)'` → 32 lowercase hex characters, written straight to `auth-key.txt` with mode `0600`. Prints only `key generated and saved: <path>` — the value is never displayed, logged or passed in an argument |
| `bash tools/bcs_auth.sh --set-key` | the same file, filled from an existing key typed twice at a hidden prompt |

Both paths keep the rules that were already there: an interactive terminal is required, a symlink at
the key path is refused, and an existing file can only be replaced by typing `OVERWRITE`. The zeroed
`umask 077`, the `chmod 700` directory and the `chmod 600` file are unchanged. A generated key travels
only as a shell variable between `node` and `printf`; it is never in argv, never in the environment,
never in a log line and never in the report.

**A 17–19 digit Huawei account ID is not this value, and the helper does not use it.** Verified at the
pinned commit `a0948ee1cbc2a870f91d313f8e37df5f524465f7`:

- the HiChain key comes from the `authkey` preference, decoded with `GB.hexStringToByteArray`
  (`HuaweiSupportProvider.java:677-709`, decoder at `GB.java:391-399`) — hexadecimal text to bytes,
  with no length rule and no digit rule; the normal generated value is 16 bytes
  (`HuaweiCrypto.java:99-104`);
- `huawei_account` is a **separate** preference (`HuaweiConstants.java:93`), read only by
  `SendAccountRequest.java:42-46` and `SendExtendedAccountRequest.java:49`, and sent as a TLV **string**
  `0x01` in service `0x1A` (`AccountRelated.java:36-40`, `:63-71`, queued at
  `HuaweiSupportProvider.java:787`). It is never hashed, never HMAC'd and never set as a secret key;
- its only length constraint is a UI one: `res/xml/devicesettings_huawei_account.xml:10` is
  `android:maxLength="17"` at the pin, raised to `19` in current upstream. Neither version validates
  that the value is digits;
- `GB.hexStringToByteArray` cannot even represent a 17-character value: it allocates `length / 2` bytes
  and reads `charAt(i + 1)`, so an odd length throws and a non-hex character decodes to `-1`.

So the account string has no upstream bytes-to-key conversion to copy. The key format is unchanged by
any of this, and a 17-digit value typed as a key is still refused with an explanation rather than a
bare "not hexadecimal". What the helper now does with the account is §8.2: it stores it in its own
file, validates it, builds the frame, and refuses to send it until the transaction cipher exists.

### 8.2 The account ID — what it is for, and how far this helper goes

`strings.xml:3366-3367` says it plainly: *"Huawei account used in pairing process. Setting it allows
to pair without factory reset."* The code behind that sentence, at the pinned commit, is narrower than
the sentence suggests, so this is what was verified:

| Question | Answer, with citation |
|---|---|
| Where is it sent? | `SendExtendedAccountRequest` is the **second** request of `initializeDynamicServices` (`HuaweiSupportProvider.java:786-787`), a phase reached only from `GetSupportedCommandsRequest` (`:91-102`), i.e. after LinkParams (`:407`), DeviceStatus (`:445`), SecurityNegotiation (`:505`), the pin code (`:569`), and the HiChain auth/bind (`:566`, `GetHiChainRequest.java:180-196`). Never before or during them |
| Which commands? | `0x1A/0x05` is the one queued (`:787`); `0x1A/0x01` exists (`AccountRelated.java:26`) but has no instantiation in the tree read |
| What is in the payload? | One TLV: tag `0x01` = the value as a UTF-8 string (`AccountRelated.java:63-64`; `HuaweiTLV.java:197-202`). `0x1A/0x01` sends an empty tag `0x01` instead when the value is empty (`:39`); `0x1A/0x05` sends a single `0x00` byte and adds `0x03 = 0x01` when the pairing optimisation applies (`:66`, `:69-71`) |
| When is it sent at all? | Only when the watch advertises **both** `(0x1A,0x05)` and `(0x1A,0x06)` (`SendExtendedAccountRequest.java:41-43`, `HuaweiCoordinator.java:585-591`) |
| What does the watch answer? | **Unknown.** Both `Response` classes are empty `HuaweiPacket` subclasses (`AccountRelated.java:45-49`, `:76-80`) and both `processResponse()` methods only log. Nothing is parsed, and upstream has no test for `0x1A` |
| Is it in the HiChain math? | **No.** `PREF_HUAWEI_ACCOUNT` is read in exactly two places, both for this packet (`SendAccountRequest.java:42-44`, `SendExtendedAccountRequest.java:47-49`). The HiChain math uses the authkey/token, the pin code, `seed`, `isoSalt`, `peerAuthId` and `androidId` only |
| How long may it be? | Upstream validates **nothing**; its own text field caps at 17 (`res/xml/devicesettings_huawei_account.xml:6`, still 17 on master). This helper accepts **17 to 19 digits**, refuses anything else, and says why |

**The cipher, and why the helper stops short.** `AccountRelated` sets no `isEncrypted` flag, so the
packet keeps `HuaweiPacket`'s default `true` (`HuaweiPacket.java:260`) and `serialize()` wraps the
payload in `{0x7C: 0x01, 0x7D: iv, 0x7E: ciphertext}` whenever `isEncrypted && areTransactionsCrypted()`
(`:934-950`, condition at `:942-944`), keyed with `paramsProvider.getSecretKey()` — which after bind
step 4 *is* the derived key (`GetHiChainRequest.java:194-196`). `transactionCrypted` defaults to true
(`HuaweiCoordinator.java:87`). Every packet this helper has ever sent is plaintext only because its
upstream class opts out (`DeviceConfig.java` has 17 `isEncrypted = false` assignments, including
`LinkParams :67` and `HiChain.BaseStep :996`). So an account frame is the first packet this project
would have to encrypt, and `src/huawei/frame.ts` refuses encrypted transactions by design.

The result, stated plainly:

- **Done offline.** `tools/bcs_auth.sh --set-account` stores the ID in `~/.config/aether-bcs/account.txt`
  (mode `0600`, directory `0700`, hidden prompt twice, `OVERWRITE` gate, symlink refused, digits only,
  17–19, never echoed and never in a report). `src/huawei/account.ts` validates the value and builds the
  real packet through the Phase 2 builders; both pairs are in `ALLOWED_REQUEST_IDS` and now in the
  sidecar's `WRITE_ALLOWLIST`, kept in step by the drift test.
- **Not done, deliberately.** `encodeAccountFrame()` refuses the wire form with
  `unsupported` / `account-needs-cipher`, and `bcs_auth.sh --with-account` exits **3** before the radio
  opens, as does the driver on its own (exit 3, sidecar never spawned). No unencrypted account frame is
  ever sent, because the watch would reject it and calling that success would be a lie.

What could **not** be verified: the reply's contents, whether the account actually helps *before* a
first bind (no upstream code path sends it earlier — the strings.xml sentence has no code behind it),
whether `0x06` really gates `0x05` on the watch, and the real digit range (upstream validates none).

Receive behavior is now explicit: by default, Python emits only byte counts. In that mode
`SidecarTransport.onData` receives no bytes, because it decodes `hex` only when present in a data
event. The auth driver alone starts the sidecar with `--emit-hex`; the bytes then travel as a JSON
field over the child stdout pipe to Node, are decoded and passed to `onData`, and are never written
to stderr, terminal output or logs. The sidecar rejects `--emit-hex` unless stdout is a private channel: a FIFO (a shell pipe) or the
AF_UNIX socketpair Node's `spawn` gives a child. A terminal, a regular file or a device is refused.
That distinction is not academic — §8.3 is the first live run dying on exactly it.

The key file follows upstream's stored representation. At pinned commit
`a0948ee1cbc2a870f91d313f8e37df5f524465f7`,
[`HuaweiSupportProvider.java`](https://github.com/Freeyourgadget/Gadgetbridge/blob/a0948ee1cbc2a870f91d313f8e37df5f524465f7/app/src/main/java/nodomain/freeyourgadget/gadgetbridge/service/devices/huawei/HuaweiSupportProvider.java#L676-L699)
stores `authkey` with `StringUtils.bytesToHex` and reads it with `GB.hexStringToByteArray`;
[`GB.java`](https://github.com/Freeyourgadget/Gadgetbridge/blob/a0948ee1cbc2a870f91d313f8e37df5f524465f7/app/src/main/java/nodomain/freeyourgadget/gadgetbridge/util/GB.java#L387-L403)
allocates `length / 2` bytes and parses successive character pairs. Upstream imposes no fixed key
length: any positive byte length represented by valid, even-length hexadecimal text is accepted;
the normal generated key is 16 bytes, as asserted in
[`TestHuaweiCrypto.java`](https://github.com/Freeyourgadget/Gadgetbridge/blob/a0948ee1cbc2a870f91d313f8e37df5f524465f7/app/src/test/java/nodomain/freeyourgadget/gadgetbridge/devices/huawei/TestHuaweiCrypto.java#L48-L73).
The driver now accepts that representation only and refuses malformed or odd-length input before it
starts a sidecar. §8.1 adds the local generation path (`--set-key --generate`), which produces exactly
that form — 16 bytes, 32 lowercase hex characters — without ever displaying it.

The live path has not been run. Syntax checks and offline tests use only synthetic key text, fake
sidecar responses or a nonexistent config path; none opens a radio or reads a real credential.

### 8.3 The first real run stopped at the ping, not at the watch

The first live attempt passed the AUTHENTICATE gate, printed two `[warn] sidecar emitted a diagnostic
line` lines, and then reported `cannot start: the sidecar did not answer its live capability ping`,
exit 2. Stopping there was correct: nothing had opened a radio. The cause was in this repository, in
the sidecar's own stdout guard, and every existing check was blind to it.

| | |
|---|---|
| What the driver does | `spawnSidecar({ scriptPath, emitHex: true })` → `spawn("python3", [script, "--emit-hex"], { stdio: ["pipe","pipe","pipe"] })` |
| What Node actually gives the child | libuv hands the child one end of an **AF_UNIX socketpair**, so its fd 1 is `S_IFSOCK` (mode `0o140777`), not a FIFO |
| What the sidecar required | `stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode)` before accepting `--emit-hex` |
| What happened | the sidecar printed its banner, then `--emit-hex requires a pipe; …`, then `return 2` without ever reading a command, so the ping could never be answered (`sidecar-exited`). Those two lines are exactly the two `[warn]` lines the driver printed |
| Why `--self-test` passed | its capability probe pipes the ping through the shell, and a shell pipeline (`printf … \| python3 …`) really is a FIFO |
| Why the suites passed | `subprocess.run(capture_output=True)` and `subprocess.PIPE` are FIFOs too, and the transport tests use an in-memory double: no test anywhere had the child's own descriptor shape |

The first fix accepted both a FIFO and an AF_UNIX socket. **§14 supersedes that policy:** payload hex
is now restricted to the AF_UNIX socketpair, the shell capability ping no longer requests hex, and
normal startup emits no banner or link-option diagnostics. The original failure and its reproduction
remain useful history; the tests below still pin the real Node descriptor shape.

Two tests pin it, both of which start the real sidecar and send nothing but a ping:
`test_emit_hex_is_accepted_when_stdout_is_the_socketpair_nodes_spawn_uses` (Python, which passes a
real `socket.socketpair()` end as the child's stdout, so it reproduces the actual descriptor type)
and `test/sidecarProcess.test.ts` (Node, which calls the driver's own `spawnSidecar` with
`emitHex: true`). Reverting the one return line to `S_ISFIFO` alone makes both fail with the exact
symptom above, which is how the diagnosis was confirmed rather than guessed: with the old guard the
same reproduction prints two diagnostics and `sidecar-exited`; with the fix it answers
`["connect","write","resolve"]` in milliseconds. `--self-test` now runs the Node test as well, so the path that
failed first can never again pass the offline check.

### 8.4 The channel comes from SDP, and every run leaves its own evidence

The first live bind exposed three gaps that had nothing to do with crypto, so all three are closed
here, and each one has a test that fails when the rule is removed.

**The channel is evidence, not a guess.** `18` used to be a remembered probe result. Now nothing may
be connected to unless SDP named that channel *in this session*:

- `sidecar/bcs_bt.py` — `SdpResult` carries the evidence next to the number (`method`, `channel`,
  `matched_uuid`, `matched_serial`, `confirmed`), `serial_channel_record()` says *which* record the
  channel came from, and `lookup_sdp()` records it. `verify_sdp_channel()` turns an answer into
  `(ok, code, message)` and refuses with its own code per case: `sdp-unavailable` (no `sdptool`, no
  `bluetoothctl`), `sdp-no-channel` (a tool answered but named no serial channel), `sdp-unconfirmed`
  (a channel, but no Huawei-UUID or serial-port record behind it — a dump guess, not a resolution),
  `sdp-disagreement` (SDP named something other than the saved channel). Every refusal happens
  before a socket exists, and none of them falls back to a probe.
- `sidecar/rfcomm_sidecar.py` — a new `resolve_channel` command (refusing any UUID but
  `82ff3820-8411-400c-b85a-55bdb32cf060` with `bad-uuid`), a `_verified_channel` that only a
  successful resolve can set, and a `connect` gate that answers `channel-unverified` for any channel
  it did not resolve itself. `ping` now advertises `("connect", "write", "resolve")`.
- `tools/bcs_auth.mjs` resolves through SDP before `open()`, refuses when the saved channel and the
  SDP answer differ, and requires `resolve` in the live ping. `tools/bcs_auth.sh` requires `write`
  **and** `resolve` in its `sidecar_ready` probe and says in `--plan`/`--status` that a missing
  `sdptool` means `sdp-unavailable` rather than a probe.
- `probe-channel --json` now reports `sdp_confirmed` and `channel_matches_sdp`, so the probe and the
  gate describe the same evidence. `src/huawei/constants.ts` holds the UUID once, and
  `test/sidecarWriteAllowlist.test.ts` proves both sides agree on it and on every refusal code.

**One log and one report per run, never overwritten.** `$STATE_DIR/auth-run-<UTC stamp>-<pid>.log`
and `$STATE_DIR/auth-report-<UTC stamp>-<pid>.txt` (`$STATE_DIR/auth-report-<stamp>.txt` when the
driver runs alone). The first live bind's report was a single fixed name, so the next attempt
replaced the only evidence of the first — that cannot happen now, and the Python test asserts it from
the directory: six runs, six logs, each one new, each `0600`, none of the earlier ones gone.

**The channel can be looked up without a run.** `bash tools/bcs_auth.sh --sdp-only` does the SDP
resolution and nothing else: it requires `SDPLOOKUP` at the terminal (not `AUTHENTICATE`, so a lookup
can never be typed by reflex at a handshake prompt), asks the sidecar's `resolve_channel`, prints the
masked watch address, the service UUID, the channel, the method that named it and the evidence behind
it (`huawei uuid: yes/no`, `serial record: yes/no`), writes those lines plus the stage trail to its own
per-run report, and exits. It reads no key, writes no identity file, opens no RFCOMM connection and
sends no frame — the driver returns from `main()` before `readKey()` and before
`spawned.transport.open()` — and every one of those claims has a test that reads the stub sidecar's own
command log and the sandbox directory. It asks with no `expect_channel`, so the answer shows what SDP
actually said; a channel that differs from `--channel` is still printed, then refused as
`sdp-disagreement` with exit 2, the same code a live run stops with. Exit 3 means the sidecar did not
advertise `resolve`, the only capability a lookup needs.

**The report says which stage was reached and how many bytes arrived.** `src/runJournal.ts` is a pure
counter (no clock, no socket, no file), and the driver puts its lines in every report: the stage, the
trail of stages after it, bytes received, frames received, frames written. Its `silence()` sentence
separates the three cases a timeout can mean — *no bytes at all* (a link or radio problem), *bytes
that never framed* (a stream problem), and *frames that were not the reply* (a protocol or channel
problem). That distinction is the one the first live bind could not make.

**Tests cannot touch the real config or state directory.** `testutil/sandbox.ts` builds a temporary
`HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` per test, and
`test/testIsolation.test.ts` fails if any test file that starts a child (`spawnSidecar`,
`node:child_process`, `bcs_auth.*`, `rfcomm_sidecar.py`) does not import it — a structural check on
the sources, not a promise in prose. Two more tests fingerprint `~/.config/aether-bcs` and
`~/.local/state/aether-bcs` before and after a sandboxed sidecar ping and a sandboxed `--plan`, and
assert nothing changed; a control test proves the fingerprint notices a new file, so a clean result
is not vacuous. The guard itself was checked the only way that counts: a test file that spawns a
child without the sandbox was dropped into `test/`, the guard failed, and it named that file.

## 9. Open questions carried forward

| # | Question | State |
|---|---|---|
| 1 | Does this watch accept the bind operation with a key the *user* supplies, or does it demand the auth operation first? | Both paths are implemented and tested offline; which one the hardware wants is Part 3B's first finding |
| 2 | Is the derived key the data-transport key, or is there another exchange? | `hichain_return_key` is what upstream derives and what this port derives; Phase 4 will confirm by using it |
| 3 | Does the same auth code work on a second device? | Carried from Phase 1/2; the bind operation registers the phone identity, so a second phone is a second binding |
| 4 | What does the watch do after N failures? | Unknown, and exactly why the machine never retries: one attempt, then stop, so this tool cannot cause a lockout |
| 5 | Does a factory-reset watch require the pin-code path? | Implemented and tested offline, unverified against hardware |
| 6 | Is a Huawei account ID (17–19 digits) needed anywhere? | Upstream keeps it in its own preference and only sends it as a service `0x1A` TLV string after a finished bind (§8.1, §8.2). The helper stores it (`--set-account`) and builds the frame, but refuses to send it until the transaction cipher exists (`--with-account` exits 3 before the radio). Whether the watch wants it *before* a first bind is still unanswered |

## 10. Hard rules: what was followed, and how that was checked

| Rule | How it was checked |
|---|---|
| **No Bluetooth touched in Phase 3D** | No Bluetooth commands or live mode ran. Python validation uses injected fake sockets; subprocess tests use fake Python or a nonexistent config path |
| **No real credential read or emitted** | Key-format and lifecycle tests use synthetic temporary key files; `--set-key` tests use a synthetic value and assert it is absent from output. The no-TTY test points at a nonexistent key and verifies the sidecar marker is absent |
| **A generated key is never displayed** | `--set-key --generate` tests assert the file holds exactly 32 lowercase hex characters (16 bytes), mode `0600` in a `0700` directory, and that neither the key nor any 32-hex run appears in the output; another test writes a 17-digit account-looking value and asserts both the wrapper and the driver refuse it before the sidecar is spawned |
| **The account ID is treated as personal data** | `--set-account` tests assert mode `0600` in a `0700` directory, the `OVERWRITE` gate, the symlink refusal, that the value never appears in the output, and that the key file is not created. Driver tests assert a missing, malformed and valid account each leave the sidecar unspawned, that the value never appears in the output or the report, and that only its digit count is recorded. `test/huaweiAccount.test.ts` searches every refusal string the module can produce for the value, with a positive control proving the value *is* in the frame it would send |
| **No health data** | Nothing in the phase reads a sample, an export or a database; every input is a synthetic buffer or a constant read from upstream |
| **Addresses masked** | No device address appears anywhere in Phase 3: the machine sees only `androidId`, a self-chosen 32-character identity, and Part 3B's wrapper masks every line it prints |
| **No git command** | None was run in Phase 3D; the user handles commits |
| **No secret in the repository** | The auth key stays in `~/.config/aether-bcs/` (mode `0600`); no credential exists in any file this phase added, and the leak test's key is a synthetic constant that is thrown away |
| **The diagnosis of §8.3 stayed offline** | `py_compile`, a descriptor inspection of a `spawn`ed child's stdio, a raw `subprocess` spawn of the sidecar, and the driver's own `spawnSidecar` with a single ping. No Bluetooth call, no pairing, no config file read, no key, no account, no git command |
| **The live step was not run** | Only syntax checks and offline tests ran. Driver lifecycle coverage uses a fake Python process; all real sidecar subprocess tests use a nonexistent config and never connect. The sidecar-start tests added after §8.3 only ping — the `--emit-hex` one included, since that flag changes what a *data* event carries and no data event exists without a watch |

## 11. Checks run at the end

| Check | Result |
|---|---|
| `node --test test/` in `bcs/helper` | **369 tests, 71 suites, 369 pass, 0 fail, 0 skipped** |
| The Phase 3 files alone (`npm run test:auth`) | 68 tests: crypto 19, authPackets 24, authMachine 23, authKeyLeak 2 — 0 fail |
| The account work alone (`node --test test/huaweiAccount.test.ts`, `test/sidecarWriteAllowlist.test.ts`) | 19 tests: 11 for the ID rule and the frame (`huaweiAccount`, 0 fail), and 8 for the sidecar side (`sidecarWriteAllowlist`, 0 fail) — 3 that keep the Python write gate in step with the TypeScript auth flow, one that proves the driver logger uses the shared secret scrubber, and 4 for the SDP gate: the sidecar advertises every capability the driver gates on, the Huawei UUID is one value on both sides, every SDP refusal code is a code the transport knows with its own sentence, and the sidecar's `channel-unverified` and the driver's refusal share one code |
| `node --test test/sidecarProcess.test.ts` (starts the real sidecar, no stub) | 6 tests, 0 fail: the driver's own `spawnSidecar({ emitHex: true })` ping — the §8.3 regression, which failed with two diagnostics and `sidecar-exited` before the fix — the same ping without the flag, `stop()` really ending the child, a child that dies before answering rejecting with the typed `sidecar-exited`, and the two SDP-gate facts from the driver's own path: `resolve_channel` with no saved address is a coded refusal that never queries SDP, and `connect` before any resolve is `channel-unverified` so no socket is opened |
| `node --test test/runJournal.test.ts` (new) | 13 tests in 4 suites, 0 fail: the stage trail (in order, no repeats, blank names ignored), separate byte and frame counters for reads and writes, the three-way `silence()` sentence — no bytes at all, bytes that never framed, frames that were not the reply — the report lines themselves, and a stage name that somehow carried an address arriving masked. Pure counting: the journal reads no clock, socket or file, so every line a live run would report can be asserted exactly |
| `node --test test/testIsolation.test.ts` (new) | 5 tests, 0 fail: the sandbox is a temporary tree with the helper's own layout inside it; a structural check over `test/*.ts` fails and names every file that starts a child (`spawnSidecar`, `node:child_process`, `bcs_auth.*`, `rfcomm_sidecar.py`) without importing `testutil/sandbox.ts`; a control test proves the directory fingerprint notices a new file; and two tests fingerprint `~/.config/aether-bcs` and `~/.local/state/aether-bcs` before and after a sandboxed sidecar ping and a sandboxed `bcs_auth.sh --plan` and assert nothing changed. Non-vacuousness was checked the only way that counts: a test file that spawns a child without the sandbox was added to `test/`, the guard failed and named that file, and it was removed |
| Reproduction of the first live failure | The raw spawn (`python3 sidecar/rfcomm_sidecar.py --emit-hex` with a `subprocess` stdout) answered the ping in every configuration, which is what pointed at the descriptor *type* rather than the protocol: a `spawn`ed child's stdout is `S_ISSOCK` (`0o140777`), not a FIFO. Reverting only the guard's return line to `S_ISFIFO` reproduced the exact two-warning, `sidecar-exited` failure through the driver's own path; with the fix the same path answers `["connect","write","resolve"]`. Ping only: no Bluetooth, no config file read, no key, no account |
| `python3 -m unittest discover -s sidecar -t . -p 'test_*.py'` in `bcs/helper` | **209 tests, 0 failures, OK** — the 130 from the key and account work plus the 22 that close §8.4 (SDP evidence, `verify_sdp_channel()`'s four refusals, `probe-channel`'s new fields, the sidecar's `resolve_channel` and its connect gate, the per-run log naming). Of the original 130: the 114 from the key work plus fourteen for the account plus two for the `--emit-hex` stdout shapes (see the end of this row): eleven around `--set-account` and the shell's `--with-account` gate (bounds, non-digits, mode `0600`, mismatched entries, overwrite gate, symlink, `--set-key` clash, no terminal, and both refuse-before-the-radio paths) and three driver tests proving a missing, malformed or valid account never spawns the sidecar — and that the valid case exits 3 with the typed cipher refusal. The pseudo-terminal deadlines in these tests are 30 s: a repeated run under deliberate CPU load exposed one observed failure caused by a slow Node start, not by the code under test, and a 30 s deadline still fails a genuine hang. The last two start the real sidecar and send only a ping: `--emit-hex` is accepted when stdout is one end of a `socket.socketpair()` (the shape Node's `spawn` gives a child, §8.3) and refused when it is a regular file, which must stay empty. Nine of the 161 are `--sdp-only`: eight run the real shell and the real driver on a pseudo-terminal against a stub `python3` that answers the ping and `resolve_channel` and records every command it was asked for — the lookup prints the masked address, the channel, the method, the UUID and the evidence and leaves exactly one `0600` report and one `0600` log; a word other than `SDPLOOKUP` starts nothing, asks the sidecar nothing and writes no report; each SDP refusal keeps its own code; a sidecar without `resolve` is blocked with only the ping asked for; a channel other than the saved one is `sdp-disagreement` with the evidence still printed; `--with-account`, `--save-derived`, `--set-key`, `--set-account` and `--self-test` are each refused beside `--sdp-only`; a run with no terminal refuses before it creates anything; and `--help` and `--plan --sdp-only` document the word and write nothing. The stub hands every other `python3` call back to the real interpreter, so the shell's stream masker still runs. The ninth is the sidecar's own: `resolve_channel` names the watch it asked about, masked, and never the address |
| `npm run lint` (repository root) | exit 0, nothing reported. `eslint.config.js` covers only `src/lib/**/*.{js,mjs}`, `src/components/**`, `src/pages/**` and `src/Layout.jsx`, so `bcs/` is outside the app's lint scope and the helper's guarantee is its own suite |
| `npm run typecheck` (repository root) | exit 2 with **pre-existing** errors in `node_modules/sql.js/dist/sql-wasm.js` and `src/components/bioage/AgeDialog.jsx`, and **zero** references to `bcs/`. `jsconfig.json` does not include `bcs/`, which is how §4.5's missing import survived until a test ran |
| `npm test` (repository root, the app's own suite) | 129 tests, 129 pass, 0 fail — unaffected |
| `node --check tools/bcs_auth.mjs`, `bash -n tools/bcs_auth.sh` | both parse (exit 0); neither file was executed against a watch. `--help`, `--plan`, `--plan --with-account` and the no-terminal `--set-account` refusal were each run offline (exit 0, 0, 0 and 2), and `--self-test` exits 0 |

## 12. Phase 3G — the opt-in link options, and what they do not guarantee

Phase 3G implements the fixes `docs/BCS_UPSTREAM_COMPARE.md` ranked first (D1–D6) without changing a
single default: every option below is off unless it is named, so a run that does not mention them builds
exactly the link, and the frames, that Phase 3F built.

| Option | What it does | Default |
|---|---|---|
| `--bt-security none\|low\|medium\|high` (sidecar flag, `bt_security` on the connect command) | applies `setsockopt(SOL_BLUETOOTH, BT_SECURITY, bytes([level, 0]))` before `connect()`; the optval is the two-byte `struct bt_security`, never a bare `int` | `none`: no option is set at all, which is what every earlier phase did |
| `--require-bond` (sidecar flag, `require_bond` on the connect command) | runs the same `bluetoothctl info` probe the SDP path already uses and refuses with `not-bonded` unless the answer carries `Bonded: yes`; the check runs before any socket exists | off |
| `--phone-model <1-32 printable ASCII>` (env `BCS_PHONE_MODEL`) | the model string SecurityNegotiation tag 0x07 carries, validated before a frame exists | `"Aether Health BCS"`, unchanged |
| `EACCES`/`EPERM` with a level set | a new `security-refused` code and sentence ("the watch is probably not bonded to this computer"), not the local-daemon sentence | — |
| timeouts | our own `settimeout()` cut says "no answer within the N s this helper allows"; a stack `ETIMEDOUT` says "the Bluetooth stack reported a timeout" | — |

Two more fixes ride along. New self auth ids are 32 **uppercase** hex characters from
`crypto.randomBytes(16)` (D3/D4), and a stored lowercase id is rewritten in place on load — the same 32
characters, not a new identity. And the messages around `--set-key --generate` no longer present a
generated key as *the* way to obtain the auth key (D5): on the HiChain path the watch issues the
long-term key, so a generated one can only ever suit HiChainLite/normal mode, which this helper refuses.
The flag keeps working; the wording and a warning changed.

**What these options do NOT guarantee.**

- They are a *request* and a *precondition*, not a report. The sidecar never learns which security level
  the stack actually granted, so "bt-security medium" in a run log means "we asked for medium".
- `--require-bond` never pairs anything, and it cannot tell "the watch is not paired" from
  "bluetoothctl could not say". Both are `not-bonded` refusals: an unverifiable precondition is never
  treated as a pass.
- They do not weaken the channel rule. SDP is still the only source of the channel, and
  `--require-bond` sits beside that gate rather than replacing it.
- `--phone-model` changes one tag's bytes. It is not an identity, not a secret, and it does not make
  this helper indistinguishable from Gadgetbridge.
- None of the three is accepted with `--sdp-only`, which stays radio-silent: a lookup opens no link,
  sets no socket option and probes no bond.
- The account frame, the transaction cipher and the write allowlist are untouched by this phase.

**Checks run for Phase 3G.** `node --test test/` → **365 tests, 71 suites, 0 failed**;
`python3 -m unittest discover -s sidecar -t . -p 'test_*.py'` → **199 tests, OK** (§13 adds four of them,
all for the pin code's source); `node --check tools/bcs_auth.mjs`, `bash -n tools/bcs_auth.sh` and
`py_compile` on both sidecar modules all parse. Every new test is offline: fake sockets record the
`setsockopt` call, a fake `bluetoothctl` answer covers `Bonded: yes` / `no` / absent, and the
driver-level runs use a stub `python3` and a pseudo-terminal. Nothing was run against a watch, no key or
account file was read, and no git command was used.

## 13. Where the pin code comes from: the watch, not the user

`--mode auth-then-bind` used to stop unless the pin code was typed at a hidden prompt. Upstream never
asks: on the first connect it sends `PinCode.Request` (`0x01`/`0x2C`), decrypts the reply with the
**static digest secret** — never the auth key, which does not exist yet at that point — and then digests
the pin's uppercase hex text for the auth operation's step 1 (`HuaweiSupportProvider.java:564-578`,
`DeviceConfig.java:1419-1462`, `GetHiChainRequest.java:206-213`). The machine now does the same, so a
default run types nothing and reads nothing: it waits for the `AUTHENTICATE` word and the watch's frames.

| | Default (`--mode auth-then-bind`) | Opt-in (`--mode auth-then-bind --pin`) |
|---|---|---|
| Where the pin comes from | the watch: the machine sends `PinCode.Request` `0x01`/`0x2C` (a 10-byte frame) from its `pincode` state and decrypts the reply in memory | this terminal: `read -s`, 4-12 digits, piped to the driver on stdin by the wrapper — never argv, never the environment, never a file |
| How the machine gets it | from `parsePincodeResponse`, decrypted with the static digest secret of the negotiated version (upstream's `createSecretDigest`), which is the only caller of `decryptPinCode` | as the `pinCode` option, already in hand at construction: the request is skipped |
| Waits up to | 30 000 ms for the reply — the watch may ask you to confirm on its own screen | the hidden prompt itself; there is no reply to wait for |

The two paths converge immediately: both digest the pin's **uppercase hex** text with SHA-256 and key the
auth operation's step 1 from it (`GetHiChainRequest.java:206-209`; ours: `authMachine.ts:447-462`). Both
are refused for every other operation. `--pin` is refused with `--mode bind` — the bind operation keys its
handshake from the stored key — and with `--sdp-only`, which opens no link for a pin to travel on: in the
wrapper before the driver runs, and again in the driver itself, before the terminal gate, before the key
is read and before any state directory exists. The pin's *source* is named in the run log and in the
report (`pin code: asked of the watch (PinCode 0x01/0x2C), decrypted in memory` or `pin code: typed at a
hidden prompt (--pin), delivered on stdin`), never the value; `--plan` says which of the two a run would
use, and neither path prints, logs or stores the pin.

**Checks run for §13.** Four new Python tests, one repurposed, a third sub-case in the wrapper's
exit-status test and two extended refusal lists — 199 tests in total, OK:

- `test_the_default_auth_then_bind_run_asks_the_watch_and_never_prompts` runs the real driver against a
  stub sidecar that answers the ping, the SDP resolve and the connect and then falls silent. The run
  passes the gate, opens the link, starts the auth-then-bind operation and ends on its own deadline with
  exit 4, printing the watch as the pin's source and no prompt at all. That the machine then sends
  `0x01`/`0x2C` and digests the decrypted pin is the contract `test/huaweiAuthMachine.test.ts` covers
  frame by frame.
- `test_driver_status_is_preserved_in_pin_and_no_pin_branches` drives the real wrapper on a
  pseudo-terminal through `bind`, `auth-then-bind` and `auth-then-bind --pin`. With `--pin` a stub driver
  reads the typed digits off its stdin and records only their *count* in the run log; without it the same
  stub fails the test if a prompt ever appears, and no stdin is connected to it at all.
- `test_a_typed_pin_that_never_arrives_stops_the_fake_sidecar_child` is the old missing-pin test,
  repurposed: with `--pin` and nothing on the closed pipe, the run stops with exit 2 and stops the child
  it had already spawned.
- `test_the_driver_refuses_a_typed_pin_for_an_operation_that_never_uses_one` and
  `test_the_shell_refuses_a_pin_without_the_operation_that_uses_it` pin the two refusals, both before the
  terminal gate and before anything is created; `--pin` also joined the `--sdp-only` refusal list on both
  sides.
- `test_help_and_plan_document_where_the_pin_code_comes_from` reads `--help`,
  `--plan --mode auth-then-bind` and `--plan --mode auth-then-bind --pin`, and requires each to say where
  the pin comes from and that both plans still write nothing.

Nothing here was run against a watch: the sidecar is a stub that never opens a socket, the pin used in the
tests is the four digits `1234`, and no key or account file was read.

## 14. Phase 3 hardening and upstream socket audit

This last Phase 3 pass fixes the live-driver diagnostics and preconditions without adding Phase 4
encryption, account transmission, health fetchers, or a probed-channel fallback.

- **Quiet, typed sidecar operation.** The two unconditional startup banners were the two diagnostic
  warnings; normal startup now writes none. `child.stdin` has an `error` listener, so an early child
  exit or broken pipe follows the ordinary sidecar-ended path instead of becoming an unhandled stream
  exception. Error-event codes pass through `isKnownErrorCode`; known timeout/reset events keep their
  structured code and safe sentence, and an invented code becomes the single structured `unknown`.
  The driver's `quietLogger` is now a `createLogger` sink, so its output gets the same MAC masking and
  long-hex redaction as every other helper logger.
- **Payload delivery is AF_UNIX-only.** `--emit-hex` accepts the Unix-domain socketpair Node creates
  for a spawned child. FIFOs, terminals, regular files and non-Unix sockets are refused. The shell's
  capability-only ping no longer passes `--emit-hex`, because it carries no payload and its stdout is
  a FIFO. Real-process tests cover both a clean socketpair ping with zero diagnostics and FIFO refusal.
- **SDP evidence and sleeping links.** UUID128 matching is case-insensitive, accepts omitted dashes,
  and recognises both Bluetooth full-byte reversal and mixed-endian display forms. Evidence remains
  tied to the record that supplied the channel. A `Connected: no` answer gets at most three total
  attempts, with 250 ms then 500 ms backoff; other answers are not retried. The TypeScript SDP bound
  is 65 seconds so three 20-second tool attempts plus backoff fit. A successful resolve is still the
  only thing that can verify a channel, and `--sdp-only` still requires its separate `SDPLOOKUP`
  confirmation. No probe result can become a connect target.
- **The correct auth key precondition.** Default `auth-then-bind`, with or without `--pin`, passes an
  empty in-memory key to the state machine. Operation 1 then derives from the watch's `PinCode
  (0x01/0x2C)` response (or the explicitly typed fallback), not `auth-key.txt`. `bind` and an explicit
  `--key` path retain the strict mode-0600 file precondition. The shell banner and `--plan` now say
  exactly which path reads a key, and the driver lifecycle test runs the default with no key file.
- **Pairing prompt.** `bcs_pair.sh` prints BlueZ's actual `Confirm passkey` line as soon as the agent
  question arrives, before asking for confirmation. Numeric Comparison is yes/no: the user confirms
  that BlueZ's number matches the watch's number, not that they should type the six digits as the
  answer. A six-digit answer is explicitly declined.

### 14.1 Byte-for-byte `LinkParams` and RFCOMM setup

Upstream `GetLinkParamsRequest.java` selects `DeviceConfig.id`/`LinkParams.id` and passes the BR device
type. `DeviceConfig.java` therefore emits empty tags 0x01, 0x02, 0x03 and 0x04 in that order (0x06 is
AW-only), with `complete=true`, `isEncrypted=false`, and `isSliced=false`. Our builder has the same
four tags and flags. The regression test pins all 16 bytes, including the unsliced header and XMODEM
CRC:

```
5A 00 0B 00 01 01 01 00 02 00 03 00 04 00 F1 3B
```

`BtBRQueue.java` uses Android's secure `createRfcommSocketToServiceRecord`; it exposes no equivalent
of a Linux `BT_POWER` setsockopt in the audited path. Our optional `BT_SECURITY` behavior is unchanged.
In addition, `rfcomm_socket()` now requests `BT_POWER_FORCE_ACTIVE_ON` (one-byte option value) before
connect, using the Python constants when present and Linux values 9/1 otherwise. Only `ENOPROTOOPT`
is ignored; every other failure closes the socket. This is intended to keep the controller active
while `link-params` waits, but **whether it prevents sniff mode or changes a real watch's timeout was
not live-tested**, because this pass ran no Bluetooth command and opened no RFCOMM link.

The pairing helper's prompt timing and wording, quiet startup, logger scrubbing, typed events, SDP
forms/retries, power-option ordering/fallback, Unix-socket restriction, and key preconditions all have
synthetic regression coverage. Final full runs: **369 TypeScript tests in 71 suites, 209 Python tests,
zero failures**. The TypeScript and Python logs are `/tmp/ts_phase3.log` and `/tmp/py_phase3.log`.

**Next:** Part 3B is unblocked in code but still needs an explicitly approved live run. Phase 4 —
sync v1.0 — remains read-only sleep, the dual channel if the watch demands it, a
Gadgetbridge-shaped export, and the existing importer, untouched.