# BCS notice — Gadgetbridge attribution

Copyright (C) 2026 HyperionOS Project. The repository-root `LICENSE` (AGPL-3.0-or-later) is the
licence text.

The BCS helper (`bcs/helper/`) speaks a protocol that was learned from, and in Phases 2 and 3 partly
ported from, **Gadgetbridge** — <https://codeberg.org/Freeyourgadget/Gadgetbridge> — which is
AGPL-3.0-or-later, © the Gadgetbridge contributors. The repository is AGPL-3.0 too, so a port is
permitted; this file and `bcs/helper/NOTICE` credit it, as `docs/BCS_PHASE0.md` §7 requires.

## The reference this code was actually read from

| | |
|---|---|
| Repository | `Freeyourgadget/Gadgetbridge` (GitHub mirror of the Codeberg project), read-only over HTTPS |
| Commit | `a0948ee1cbc2a870f91d313f8e37df5f524465f7` — the mirror's `master`, which is frozen at 2024-12-22 |
| Why this commit | The mirror is immutable and fetchable by hash, so every ported line can be re-checked. `docs/BCS_PHASE0.md` cites the Codeberg commit `de7c2ba8d636a3dc5b750770fb3654671a4bd260`; Codeberg answered the automated fetch with a bot check, and that hash does not resolve on the mirror (HTTP 422), so the frozen mirror HEAD was used instead. Both are the same project; the line numbers in Phase 2 files are those of the mirror copy. |

Upstream files read for Phase 2, all under
`app/src/main/java/nodomain/freeyourgadget/gadgetbridge/` unless stated:

```
devices/huawei/HuaweiPacket.java            1006 lines   frame, CRC, slicing, parse/serialise
devices/huawei/HuaweiTLV.java                452 lines   TLV, VarInt, tag/type readers
devices/huawei/HuaweiCrypto.java             273 lines   read for scope in Phase 2; ported in Phase 3
devices/huawei/HuaweiConstants.java           99 lines   magic, protocol version, crypto tags
devices/huawei/packets/DeviceConfig.java    1756 lines   handshake, auth and read request shapes
devices/huawei/packets/AccountRelated.java    82 lines   account handshake request shapes
devices/huawei/packets/FindPhone.java         61 lines   a write-type command, used as a refusal test
util/CheckSums.java                          193 lines   CRC16
util/StringUtils.java / util/GB.java                   hex helpers, read to match case exactly
app/src/test/java/.../devices/huawei/
  TestHuaweiPacket.java                      269 lines   ported vectors
  TestHuaweiTLV.java                         532 lines   ported vectors
  TestHuaweiCrypto.java                       77 lines   one nonce test, ported in Phase 3
  TestVarInt.java                             72 lines   ported vectors
```

Upstream files read for Phase 3, same commit:

```
util/CryptoUtils.java                                  AES, HMAC, SHA-256, HKDF, PBKDF2     ported
devices/huawei/HuaweiCrypto.java            273 lines  secrets, digests, pin code         ported
service/devices/huawei/HuaweiSupportProvider.java      the sequence around the handshake   ported
service/devices/huawei/requests/GetHiChainRequest.java 38-262, the step machine            ported
service/devices/huawei/requests/GetSecurityNegotiationRequest.java                        ported
service/devices/huawei/requests/GetPincodeRequest.java                                    ported
service/devices/huawei/requests/GetDeviceStatusRequest.java                                ported
service/devices/huawei/requests/GetBondRequest.java        read only: the bonding path, out of scope
```

One more reference fact is read but not ported: `devices/huawei/HuaweiConstants.java:33` holds the Huawei
SDP service UUID `82FF3820-8411-400C-B85A-55BDB32CF060`. The helper uses that value as a constant and
resolves the RFCOMM channel from it with BlueZ's own `sdptool`; the resolving, the evidence matching and
the connect gate are original code, and nothing else about SDP is taken from upstream.

## Files ported from Gadgetbridge

Each of these carries Gadgetbridge's AGPL header reference and a `Ported from <path>:<lines>`
line naming the commit above:

| Phase 2 file | Ported from |
|---|---|
| `bcs/helper/src/huawei/crc16.ts` | `util/CheckSums.java:59-73` (`getCRC16`) |
| `bcs/helper/src/huawei/varint.ts` | `devices/huawei/HuaweiTLV.java:384-452` (`VarInt`) |
| `bcs/helper/src/huawei/tlv.ts` | `devices/huawei/HuaweiTLV.java:39-380` |
| `bcs/helper/src/huawei/frame.ts` | `devices/huawei/HuaweiPacket.java:246, 321-421, 767-847, 934-960` |
| `bcs/helper/src/huawei/stream.ts` | `devices/huawei/HuaweiPacket.java:321-361, 375, 388-402` |
| `bcs/helper/src/huawei/constants.ts` | `HuaweiConstants.java:33-45`; `packets/DeviceConfig.java:48-135, 182, 422, 607, 668`; `packets/AccountRelated.java:23, 26, 53` |
| `bcs/helper/src/huawei/requests.ts` | `packets/DeviceConfig.java:53-70, 137-146, 240-282, 424-446, 609-627, 668-678`; `packets/AccountRelated.java:28-43, 55-74` |
| `bcs/helper/test/huaweiCrc16.test.ts` | `util/CheckSums.java` + the CRC bytes of `TestHuaweiPacket.java` |
| `bcs/helper/test/huaweiVarInt.test.ts` | `TestVarInt.java:22-72` |
| `bcs/helper/test/huaweiTlv.test.ts` | `TestHuaweiTLV.java:59-532` |
| `bcs/helper/test/huaweiFrame.test.ts` | `TestHuaweiPacket.java:19-269` |

`bcs/helper/src/huawei/errors.ts` and `bcs/helper/src/huawei/index.ts` are original: the error
taxonomy is this project's, deliberately returned rather than thrown.

## Files ported from Gadgetbridge, Phase 3 (trust/auth)

| Phase 3 file | Ported from |
|---|---|
| `bcs/helper/src/huawei/crypto.ts` | `util/CryptoUtils.java:44-141`; `devices/huawei/HuaweiCrypto.java:48-79, 99-192, 243-252` |
| `bcs/helper/src/huawei/authPackets.ts` | `devices/huawei/packets/DeviceConfig.java:50-123, 858-902, 970-1462, 1575-1640`; `HuaweiConstants.java:30`; `service/devices/huawei/HuaweiSupportProvider.java:474-495, 497-529, 564-578`; `service/devices/huawei/requests/Get{HiChain,SecurityNegotiation,Pincode,DeviceStatus}Request.java` |
| `bcs/helper/src/huawei/authMachine.ts` | `service/devices/huawei/requests/GetHiChainRequest.java:38-262`; `service/devices/huawei/HuaweiSupportProvider.java:405-473, 497-529, 535-578, 677-699` |
| `bcs/helper/src/huawei/authErrors.ts` | original: the typed error taxonomy, returned rather than thrown |
| `bcs/helper/test/huaweiCrypto.test.ts` | `TestHuaweiCrypto.java`'s single nonce test, plus FIPS-197, NIST SP 800-38A F.2.1, RFC 4231, RFC 5869 and the standard PBKDF2-SHA256 vectors |
| `bcs/helper/test/huaweiAuthPackets.test.ts` | the request/reply shapes of the `DeviceConfig.java` and `GetHiChainRequest.java` ranges above |
| `bcs/helper/test/huaweiAuthMachine.test.ts` | the step machine and the surrounding sequence |
| `bcs/helper/test/authKeyLeak.test.ts` | original: this project's guarantee, checked rather than asserted |

Three upstream behaviours are reproduced against intuition and are written down so nobody "fixes" them
by accident; `docs/BCS_PHASE3.md` §4 gives the evidence for each:

1. the bind operation's step 4 sends message `0x13`, not `0x14`, because upstream captures the step
   before incrementing it;
2. the step-2 token is *sent* as `HMAC(psk, randSelf‖randPeer‖authIdPeer‖authIdSelf)` and *verified*
   as `HMAC(psk, randPeer‖randSelf‖authIdSelf‖authIdPeer)` — the same four blocks, mirrored;
3. `GB.hexdump` is uppercase, and every hex string that feeds a digest or a MAC depends on it.

## What Phase 2 deliberately did not port

- `HuaweiCrypto.java` and `TestHuaweiCrypto.java`: encryption, the key derivation and the auth-code
  path — Phase 2 was pure framing and held no key. **Phase 3 ported them** (see above); the one vector
  whose assertion is a *decrypted* payload is now exercised with the ported crypto.
- `DeviceConfig.Bond` / `BondParams` request builders: they carry a bonding key and its IV. Still not
  ported in Phase 3 either.
- Everything on the out-of-scope list of `docs/BCS_PHASE0.md` §7: alarms, notifications, contacts,
  calendar, music, watchfaces, firmware/OTA.

## What Phase 3 deliberately did not port

- `HuaweiCrypto.createSecretKey(macAddress)` (`:207-229`) and the whole bonding path around it.
- The legacy digest auth (HiChainLite, service `0x01` command `0x13`): a device that negotiates it is
  refused with `auth-unsupported` rather than half-supported.
- Upstream's debug logging of digests and session keys, and its exception-per-failure style. Nothing
  in Phase 3 logs, and every failure is a typed code.

## Divergences from upstream, all deliberate

`bcs/helper/NOTICE` lists them per file. In summary: typed errors instead of exceptions, a bounds
check where upstream would read off the end of an array, fresh restart of a sliced packet instead of
upstream's append-on-desync, and a hard refusal (not silent plaintext) when encryption is requested.

## Privacy

Phase 2 reads no key, no cookie, no account value, no preference file, no export and no database.
Test vectors come only from the public Gadgetbridge source. No Bluetooth address, no payload byte and
no health datum appears in any Phase 2 file or test.

Phase 3 handles a key for the first time, and narrows the rule rather than breaking it:

- the key is passed in as bytes by the caller; no Phase 3 file reads a file, a cookie, an account
  value or a preference, and no function in it accepts a logger;
- key material is copied, used, and zeroed (`destroy()`, or automatically when the flow finishes);
- no key byte, key hex, key base64 or key-derived value reaches an error `message` or `detail`, a log
  line, or the bytes sent to the watch — `test/authKeyLeak.test.ts` checks exactly that, with a
  control test proving the search would have found a leak;
- the leak test's key is a synthetic constant that is thrown away; no real credential, address or
  health datum appears anywhere in Phase 3's files or tests;
- Part 3B (`bcs/helper/tools/bcs_auth.sh`, written and not run) reads the key from
  `~/.config/aether-bcs/auth-key.txt` with mode `0600` and never prints it or the derived key. The same
  script can generate that key (`--set-key --generate`, 16 bytes from `node:crypto`) and writes it to
  the file without displaying it.
- The Huawei account ID (17–19 digits) is personal data, kept in its own file (`account.txt`, mode
  `0600`), typed at a hidden prompt by `--set-account`, and never printed, logged or reported — only
  its digit count is. `--with-account` refuses before the radio opens: the account frame has to be
  encrypted with the derived key, and that cipher is not implemented. The account is not the auth key:
  the key is hexadecimal, the account is digits.
- Resolving the RFCOMM channel runs `sdptool browse <address>` from `sidecar/bcs_bt.py`, so the address
  is that one child process's argv for as long as the query lasts. It is the only place the address
  leaves the helper unmasked, the tool requires it, and nothing is written to disk by it. Everything
  the helper prints, reports or returns — including every protocol line the sidecar emits, through
  `mask_text()` — keeps only the last two octets.
- Each run writes its own log and report under `$XDG_STATE_HOME/aether-bcs/`, and no run overwrites the
  run before it: the name carries a UTC stamp, plus the shell's pid when `tools/bcs_auth.sh` is the
  caller, and a driver started on its own adds its own pid if its default name is already taken. The
  shell sets `umask 077` and the driver creates the report with mode `0600`, so both files are private.
  A report holds stage names, coded refusals and byte/frame counts only: no key, no account value, no
  payload and no unmasked address.
- A `--sdp-only` lookup reads no key at all: it resolves the channel, prints only the masked watch
  address and the SDP evidence, opens no RFCOMM connection, sends no frame, and leaves the same pair
  of private per-run files as a live run.
