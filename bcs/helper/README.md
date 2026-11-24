# BCS helper — Phase 1: the link, Phase 2: the codec, Phase 3: trust

This directory is the PC-side helper for the Butterfly Connectivity System. **Phase 1 (the link)**
proves one thing: **a classic-Bluetooth RFCOMM link to the watch can be opened.** **Phase 2 (the
codec)** is the wire format itself: frames, TLVs and checksums, in pure code with no radio attached.
**Phase 3 (trust/auth)** is the app-level HiChain handshake: the crypto, the auth packets and the state
machine, again in pure code — the key is held in memory only and is never logged, printed or sent.
The link layer sends only allowlisted authentication frames when the auth driver requests them;
Phase 2 holds no key.

Licence and attribution: see `NOTICE`. The repository-root `LICENSE` is the licence text.

## What Phase 1 is and is not

| Phase 1 does | Phase 1 does not |
| --- | --- |
| Find the watch's RFCOMM channel (`probe-channel`) | Send arbitrary commands or non-auth frames |
| Open the link and count data; auth sends use the allowlist | Read or store an auth key in Phase 1 |
| Count arriving bytes and timestamp them; auth opts in to pipe delivery | Log or store any payload |
| Write only allowlisted auth-frame pairs; refuse every other frame | Open the dual/aux channel (Phase 4, service `0x01` cmd `0x3C`) |

`write()` sends one frame through the sidecar pipe. The sidecar checks frame length, magic, XMODEM
CRC, auth-flow service/command ids, and per-connection write budgets before `sendall`; refused
frames return `write-refused` without echoing their payload. The fake transport remains opt-in for
tests that need to assert that no frame was sent.

## Prerequisites

- Linux with BlueZ (developed against BlueZ 5.87) and a working Bluetooth adapter.
- Python 3, standard library only. Nothing to install, no virtualenv.
- Node.js **22.6 or newer** for the TypeScript tests (`node --test`, no dependencies). Run against
  Node 26.
- Optional: `sdptool` from `bluez-deprecated-tools`. For `probe-channel` it is an optimisation: it is the
  only BlueZ tool that reports an RFCOMM channel number, so with it the probe usually needs one connect
  instead of a sweep. For a **live auth run it is required**: the channel comes from SDP or the run
  stops (`sdp-unavailable`) before any socket exists, and a probed channel is never connected to.

## Saved watch address

The watch's address is **not** treated as a secret, but it is never committed, never printed in
full and never passed on a command line (so it cannot land in your shell history, a process list or
a log). It lives in one file outside this repository, mode 0600:

```
~/.config/aether-bcs/watch.json
```

```bash
cd bcs/helper
python3 tools/watch-address.py list    # devices this machine knows, addresses masked
python3 tools/watch-address.py save    # hidden prompt: type the address
python3 tools/watch-address.py show    # what is saved, masked
```

`list` reads BlueZ's cache, so the watch appears only if this machine has seen it. If the list is
empty, run `bluetoothctl scan on` in another terminal with the watch awake and Bluetooth visible,
then run `list` again. Anything these tools print is already masked as `XX:XX:XX:XX:AA:BB`: only
the last two octets are kept on purpose, because those are the part that tells two watches apart.

One exception to "never on a command line", stated rather than glossed: to read the SDP record the
sidecar runs `sdptool browse <address>`, because that is the only way that tool is used and it needs
the address. So the address appears in that one child's argv for as long as the query lasts — outside
anything this helper can mask — while every line the helper itself prints or reports stays masked.

## Before you probe: the watch accepts one connection

A Huawei watch will drop or refuse a new classic link while the phone holds it. So:

1. Turn Bluetooth on in the watch's settings and leave the watch awake.
2. Disconnect the watch from the phone (Huawei Health > disconnect, or turn the phone's Bluetooth
   off). If you use Gadgetbridge, stop it from connecting.
3. Keep the watch within a metre or two of the PC.

**UNKNOWN, to be settled live:** whether this watch accepts an SPP connection without a prior
pair/bond (`bluetoothctl pair <address>`). If `probe-channel` reports `permission`, or the link is
dropped the moment it is accepted, pairing first is the next thing to try. The channel number is
also not known yet: that is exactly what the probe finds.

## The probe

```bash
cd bcs/helper
python3 probe-channel                     # sdptool first, otherwise channels 1-30
python3 probe-channel --sdp-only          # ask SDP, connect to nothing
python3 probe-channel --channels 1-30 --timeout 3 --verbose
python3 probe-channel --json              # one JSON object, for a script
```

What it prints, and nothing else: the masked address, what SDP said, the channel that accepted and
a one-line tally of failure codes. It connects, closes immediately, and stops at the first channel
that accepts. It never retries a channel, it stops early when the failure is about the link rather
than the channel (`busy`, `permission`, `unreachable`), and it stops at `--budget` seconds (90 by
default) so one run cannot walk 30 channels at 3 s each and hang.

```
masked_address: XX:XX:XX:XX:AA:BB
sdp: bluetoothctl -> no channel (no SDP browser on this machine …)
probed: 1-30 (timeout 3.0s each, first accept wins)
channel: 15
result: accepted
```

The probe is **diagnostic, not authoritative.** A probe says "a channel accepted"; it cannot say that
channel is the watch's serial service. So a probe's answer is never what an auth run connects to: the
driver asks the sidecar to resolve the channel through SDP first, and refuses if SDP cannot be read
(`sdp-unavailable`), names no serial record (`sdp-no-channel`), names a record carrying neither the
Huawei UUID nor the serial-port profile (`sdp-unconfirmed`), or disagrees with the channel you passed
(`sdp-disagreement`). `--json` reports the evidence as well — `sdp_confirmed` and
`channel_matches_sdp` — so you can see whether the probe and SDP agree. UUID128 matching accepts case
changes, omitted dashes, and Bluetooth byte-order display variants. A bonded watch answering
`Connected: no` gets at most three attempts, with 250 ms then 500 ms backoff; other answers are not
retried. This changes neither the evidence requirement nor the ban on using a probed channel.
RFCOMM sockets request `BT_POWER_FORCE_ACTIVE_ON` before connecting; kernels that answer
`ENOPROTOOPT` are supported, while other option failures close the socket.

Exit codes: `0` a channel accepted, `1` no channel accepted, `2` it could not even try (no saved
address, unreadable config, no Bluetooth socket support in this Python).

Run it **once**. If it reports `busy`, the watch is almost certainly still connected to the phone:
disconnect it there and run the probe again rather than in a loop.

## The sidecar

`sidecar/rfcomm_sidecar.py` is the process the TypeScript transport talks to. It reads JSON
commands on stdin and writes JSON responses and events on stdout; human diagnostics go to stderr,
masked. The address is never an argument: the sidecar reads it from the config file itself.

```bash
python3 sidecar/rfcomm_sidecar.py --config ~/.config/aether-bcs/watch.json
# then, on stdin:
#   {"id":1,"cmd":"ping"}
#   {"id":2,"cmd":"resolve_channel","uuid":"82ff3820-8411-400c-b85a-55bdb32cf060","expect_channel":18}
#   {"id":3,"cmd":"connect","channel":18,"timeout_ms":10000}
#   {"id":4,"cmd":"write","hex":"<allowlisted auth frame>"}
#   {"id":5,"cmd":"close"}
```

Events are `{"event":"data","bytes":37,"at":"…","channel":15}` by default (count, time and channel),
plus `{"event":"closed",…}` and `{"event":"error","code":"reset",…}`. Only the auth driver enables
`--emit-hex`; the sidecar refuses that option unless stdout is a private channel — a pipe, or the
AF_UNIX socketpair Node hands a spawned child with `stdio: "pipe"`; FIFOs, terminals, files and other
sockets are refused. Normal sidecar startup is silent, so a clean ping produces zero diagnostic
warnings.
The bytes travel only on that pipe, and the logger and stderr continue to receive counts only.
`open_aux` is refused with `unsupported`: the dual channel is Phase 4.

`ping` advertises `connect`, `write` **and** `resolve`. `connect` is refused with
`channel-unverified` unless `resolve_channel` named that same channel in this session, so a
remembered number, a typo or a probed channel never becomes a socket — the refusal happens before one
exists. `resolve_channel` answers with the channel *and* its evidence (`method`, `matched_uuid`,
`matched_serial`), or with the coded refusal that says why no channel is proven: `sdp-unavailable`,
`sdp-no-channel`, `sdp-unconfirmed`, `sdp-disagreement`, `bad-uuid`, `no-config`.

The TypeScript side is `src/sidecarTransport.ts` (the client), `src/sidecarProcess.ts` (the real
child process) and `src/fakeTransport.ts` (the in-memory one used by tests). Everything above a
transport is written against `BcsTransport` in `src/types.ts`, never against a socket.

## Phase 2 — the packet codec (no radio at all)

`src/huawei/` is the Phase 2 codec: the wire format the watch speaks, ported from Gadgetbridge and
tested against Gadgetbridge's own vectors. It touches no socket, no process, no timer and no key. It
takes bytes and returns objects, and the reverse:

| Module | What it does |
| --- | --- |
| `crc16.ts` | The frame checksum: CRC-16/XMODEM, seeded 0x0000 (`CheckSums.getCRC16`) |
| `varint.ts` | The 7-bit VarInt that encodes TLV lengths |
| `tlv.ts` | TLV build and parse, nested TLVs, the full typed reader set |
| `frame.ts` | Frame encode/decode: magic, length, slice bytes, service/command ids, CRC |
| `stream.ts` | Reassembly: split reads, merged reads, sliced packets, bounded buffer |
| `requests.ts` | The eight handshake/auth/read requests this phase may build |
| `errors.ts` | The typed error taxonomy: returned, never thrown at a byte boundary |

```ts
import { createHuaweiStream, decodeFrames, encodeFrame, HuaweiTlv } from "./src/huawei/index.ts";

// Build the first request of a session and frame it, unsliced and unencrypted.
const frames = encodeFrame({ serviceId: 0x01, commandId: 0x01, tlv, sliced: false, isEncrypted: false });

// Feed whatever the link delivers, in whatever pieces it arrives.
const stream = createHuaweiStream();
const { frames: decoded, error } = stream.push(chunk);
```

Scope, in the code rather than in a comment: **decode** works for every frame and every tag, while
**encode** exists only for the handshake, the auth challenge and read requests. Alarms,
notifications, contacts, music, OTA, and the two bonding requests that carry key material, are not
buildable — `isAllowedRequest()` is the machine-checkable list, and the tests assert that every
builder is on it. Encryption is refused with a typed `unsupported` error naming Phase 3, never
silently downgraded; the one plaintext path upstream itself uses before a key exists is preserved
byte for byte.

Everything is deterministic and offline. `docs/BCS_NOTICE.md` and `NOTICE` record exactly which
Gadgetbridge files and commit each module was read from.

## Phase 3 — trust/auth (no radio either)

`src/huawei/` also holds the Phase 3 authentication: the sequence the phone and the watch run before
either trusts the other, ported from Gadgetbridge's HiChain flow. It takes a `HuaweiFrame` and returns
the frames a caller should send, or a typed stop. No socket, no timer, no retry, no logging.

| Module | What it does |
| --- | --- |
| `crypto.ts` | SHA-256, HMAC-SHA256, HKDF-SHA256, PBKDF2-SHA256, AES-GCM/CBC/ECB, `hexdumpUpper`, `zeroBytes`, the three digest secrets, and `createHuaweiCrypto` |
| `authPackets.ts` | Link params, device status, security negotiation, pin code, and the HiChain JSON envelope with its four steps |
| `authMachine.ts` | `createAuthMachine`: the state machine, the MAC checks, the key derivations, `destroy()` |
| `authErrors.ts` | The auth error taxonomy: `auth-token-mismatch`, `auth-mac-mismatch`, `auth-unsupported`, and the rest |

```ts
import { createAuthMachine } from "./src/huawei/index.ts";

const machine = createAuthMachine({ key, androidId });   // the key is copied, never logged
let step = machine.start();                              // frames to write, or a typed failure
// ... write step.value.out, feed the reply back in:
step = machine.onFrame(frame);
// when step.value.done: machine.finalKey holds the 32 bytes the bind operation returned
machine.destroy();                                       // zeroes everything the machine held
```

What it refuses, by design: a watch that negotiated HiChainLite or the legacy digest auth
(`auth-unsupported`), a wrong key (`auth-token-mismatch`), a tampered MAC (`auth-mac-mismatch`), a
replayed or out-of-order step (`auth-state`), and a destroyed machine (`auth-state`, never a crash).
The bonding path and the legacy digest auth are not ported.

`tools/bcs_auth.sh` (+ `tools/bcs_auth.mjs`) is **Part 3B, the live step: written, never run.** It
mirrors `tools/bcs_pair.sh` — masked output, the key read from `~/.config/aether-bcs/auth-key.txt`
(mode 0600) and never from an argument, a typed `AUTHENTICATE` gate, and the derived key never
printed. It requires `write` **and** `resolve` in the sidecar's live ping capabilities before opening
the link, and the channel it connects to is the one SDP named in that same run — never a remembered or
probed number. The key file holds **even-length hexadecimal text** and nothing else:
`bash tools/bcs_auth.sh --set-key --generate` writes a fresh 16-byte key from `node:crypto`
(32 lowercase hex characters) and prints only that it was saved, while `bash tools/bcs_auth.sh
--set-key` stores a key you already have after two hidden entries. Replacing an existing file
requires typing `OVERWRITE`, a symlink at the key path is refused, and neither path ever displays the
value. A 17–19 digit Huawei account ID is a different value with its own file: `bash tools/bcs_auth.sh
--set-account` stores it in `~/.config/aether-bcs/account.txt` (mode 0600, hidden prompt twice, digits
only, 17–19, `OVERWRITE` gate, symlink refused, never shown). `--with-account` asks for the account
step upstream sends after a finished bind, and today stops with exit 3 *before* the radio opens,
because that frame has to be encrypted with the derived key and the transaction cipher (0x7C/0x7D/0x7E)
is not part of this phase — the ID, its validation and its frame are all built and tested offline.
`bash tools/bcs_auth.sh --sdp-only` is the same SDP resolution without the run: it requires
`SDPLOOKUP` at the terminal (never `AUTHENTICATE`), asks the sidecar to resolve the channel, prints the
masked watch address, the service UUID, the channel, the method that named it and the evidence behind
it, writes those lines to this run's own report, and exits — before any RFCOMM connection is opened,
before the key file is read, before the identity file is touched and before a frame exists. A channel
that disagrees with `--channel` still ends as `sdp-disagreement`, the code a live run refuses with.
`--plan`, `--plan --sdp-only` and `--self-test` are the offline ways to read those flows.

Phase 3G adds three opt-in options, all off by default, so a run that does not name them builds exactly
the link it always did. `--bt-security none|low|medium|high` asks the stack for that `BT_SECURITY` level
before `connect()` (the optval is the two-byte `struct bt_security`); it records what we asked for, never
what the stack granted, and with a level set a refused secure link is reported as `security-refused`
rather than as a local permission problem. `--require-bond` runs the same `bluetoothctl info` probe the
SDP path uses and refuses with `not-bonded` unless the answer carries `Bonded: yes` — before any socket
exists, and it never pairs a watch. `--phone-model <1-32 printable ASCII>` sets the model string security
negotiation advertises, with the helper's own default kept when it is not given. None of the three is
accepted with `--sdp-only`. Run identities are now 32 uppercase hex characters from `node:crypto`, and a
stored lowercase identity is rewritten in place on first use: the same 32 characters, not a new one.
See `docs/BCS_PHASE3.md` §12 for what the options do *not* guarantee.

The pin code on the auth-then-bind path is the watch's, not yours. `--mode auth-then-bind` sends
`PinCode.Request` (`0x01`/`0x2C`) and decrypts the reply in memory with the *static* digest secret —
never the auth key — then digests the pin's uppercase hex for the auth operation's step 1, which is
exactly what Gadgetbridge does (`DeviceConfig.java:1419-1462`, `HuaweiSupportProvider.java:564-578`,
`GetHiChainRequest.java:206-213`). Nothing is typed and nothing is read from the terminal for it, so a
default run waits only for the `AUTHENTICATE` word. `--pin` is the fallback for a watch that does not
answer that request: it reads 4–12 digits at a hidden prompt and pipes them to the driver on stdin —
never argv, never the environment, never a file — and it is refused with any operation other than
`auth-then-bind` and with `--sdp-only`. The pin's *source* is named in the run log and the report; the
value never is. `docs/BCS_PHASE3.md` §13 has the two paths side by side.

Every run writes its own evidence, and nothing is overwritten:
`$XDG_STATE_HOME/aether-bcs/auth-run-<UTC stamp>-<pid>.log` (masked output) and
`$XDG_STATE_HOME/aether-bcs/auth-report-<UTC stamp>-<pid>.txt` (states, codes and counts only; the
driver alone names it `auth-report-<stamp>.txt`). The report starts from a run journal that records the
stage reached, the stages before it, and how many bytes and frames crossed the link in each direction —
so a failed run says whether the watch was silent, answered with bytes that never framed, or answered
with frames that were not the reply it needed. Those are different problems, and the first live bind
could not tell them apart because only step names were reported.

## Tests

```bash
cd bcs/helper
npm test          # TypeScript: transport, pipe, masking, logger and Phases 2-3D (node --test)
npm run test:codec # TypeScript: just the Phase 2 codec, against Gadgetbridge's own vectors
npm run test:auth  # TypeScript: just Phase 3 — crypto, auth packets, the machine, the leak test
npm run test:py    # Python: Bluetooth facts, probe, sidecar protocol, both CLI tools
npm run test:all   # both suites
```

At the time of writing: **369 TypeScript tests, 209 Python tests, no failures**, and nothing in
`src/huawei/` needs a socket to run. The codec tests include Gadgetbridge's vectors byte for byte, a
round trip through the encoder and decoder, a split of one valid frame at *every* byte offset, and
fuzzed garbage that must produce a typed error instead of a throw. The Phase 3 tests drive the whole
handshake on synthetic frames with an injected RNG, recompute every token, MAC and key independently,
and finish with a search of everything the machine produced for the key in five spellings.

Nothing here needs hardware: every socket, clock, subprocess and Bluetooth tool call is a fake.
`test/sidecarProcess.test.ts` and a few Python tests do start the real sidecar process: they ping it,
ask it to resolve a channel (which stops at `no-config`, because the config path does not exist), and
prove that a `connect` before any resolve is `channel-unverified`. None of them opens a socket or
reads a watch address. They are the exception on purpose: the first live run failed because Node hands
a spawned child a socketpair rather than a pipe, and no fake had that shape. `--self-test` runs the
Node one for the same reason. If a test ever needs a real link, that is a bug in the test.

Every test that starts a child takes its `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` from
`testutil/sandbox.ts`, and `test/testIsolation.test.ts` fails if one forgets — it scans the test
sources, and fingerprints `~/.config/aether-bcs` and `~/.local/state/aether-bcs` before and after a
sandboxed sidecar and a sandboxed `--plan`. The helper's own runs are the only thing that may write
those directories.

## Still unknown after Phase 1

- The RFCOMM channel number. SDP resolves it for a live run; `probe-channel` only reports what it sees.
- Whether pairing/bonding is required before an SPP connect.
- Whether a second device can authenticate with the same credential (an auth-key question, not
  Phase 1, but it shapes later phases).
- How the watch reacts to a link that is opened and closed with no data. Phase 1 reports what
  happens instead of predicting it.

## Privacy rules carried into the code

- The address is masked in every log line, every event and every test assertion.
- No auth code, cookie or account token is read, requested or stored in Phase 1.
- Bytes received from the watch are never logged: only the count, the channel and the time. The
  auth driver alone receives opt-in payload bytes over its child pipe, never stderr or terminal output.
- In Phase 3 the key is passed in as bytes, copied, and zeroed (`destroy()` or completion). Nothing in
  that phase logs, no error carries key material, and `test/authKeyLeak.test.ts` searches everything
  the machine produces for the key and the derived key in five spellings each.
- Part 3B requires `~/.config/aether-bcs/auth-key.txt` (mode 0600 checked first) only for `bind` or an
  explicit `--key` path. Default `auth-then-bind` reads no key file: operation 1 derives from the watch's
  `PinCode 0x01/0x2C` response, decrypted in memory with the static digest secret. A hidden stdin prompt
  is used only with `--pin`. The derived key is never printed and every output line is masked.
  `--set-key --generate` makes a local key with `node:crypto` and writes it directly to the file.
- The Huawei account ID is personal data and lives in its own file, `~/.config/aether-bcs/account.txt`
  (mode 0600, written by `--set-account` from a hidden prompt twice, never displayed, never in a log,
  never in a report — only its digit count is ever recorded). `--with-account` refuses before the radio
  opens, because the account frame must be encrypted with the derived key and that cipher is not part
  of this phase.
- `--sdp-only` reads no key at all: it resolves the channel, prints only the masked watch address and
  the SDP evidence, writes its own private log and report, and stops. The transport masks that address
  again if a sidecar ever sent it unmasked, so a full address cannot reach a printed line or a report.