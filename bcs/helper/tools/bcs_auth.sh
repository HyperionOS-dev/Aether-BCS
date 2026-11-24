#!/bin/bash
# BCS helper — Phase 3 / Part 3B (trust/auth, LIVE): authenticate against the watch, once, by hand.
# Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
# See NOTICE in the helper directory for attribution and privacy rules (../NOTICE from here).
#
# WRITTEN, NEVER RUN. Nothing in the repository invokes this script; it is here so the live step can
# be read before anyone presses the button. Phase 3 proved the sequence offline; Part 3B is the same
# sequence against a real watch, with a real key, and it is a deliberate, manual act.
#
#   bash bcs/helper/tools/bcs_auth.sh --plan         # what a live run would do; touches nothing
#   bash bcs/helper/tools/bcs_auth.sh --self-test    # offline: the suites and the real sidecar's ping
#   bash bcs/helper/tools/bcs_auth.sh --set-key      # securely store a hex key; hidden prompt twice
#   bash bcs/helper/tools/bcs_auth.sh --set-key --generate   # a fresh 16-byte key here (HiChainLite
#                                                # or normal mode only: a HiChain bind needs the key
#                                                # the watch issues, so this cannot complete one)
#   bash bcs/helper/tools/bcs_auth.sh --set-account  # store the Huawei account ID; hidden prompt twice
#   bash bcs/helper/tools/bcs_auth.sh --with-account # a live run that also wants the account step
#   bash bcs/helper/tools/bcs_auth.sh --sdp-only     # which channel does SDP name? nothing is opened
#   bash bcs/helper/tools/bcs_auth.sh --bt-security medium --require-bond   # opt-in link checks
#   bash bcs/helper/tools/bcs_auth.sh --phone-model 'Pixel 7'               # what the watch is told
#   bash bcs/helper/tools/bcs_auth.sh --mode auth-then-bind   # auth first, then bind. The pin code is
#                                                # the watch's own reply (0x01/0x2C), so nothing is
#                                                # typed here unless you pass --pin
#   bash bcs/helper/tools/bcs_auth.sh --mode auth-then-bind --pin   # opt in to typing the pin code at
#                                                # a hidden prompt instead
#   bash bcs/helper/tools/bcs_auth.sh                # the real thing, in your own terminal
#
# Exit codes: 0 = the handshake completed, 1 = it ran and the flow stopped (the typed code is on
# screen and in the report), 2 = it could not start (no key file, no account file, wrong mode, no
# terminal, or SDP refused to name the channel), 3 = blocked (the live sidecar ping did not advertise
# allowlisted writes and SDP resolution, or --with-account was asked for and the account frame cannot
# be sent yet), 4 = a step timed out, 5 = the link ended underneath the flow. A --sdp-only run returns
# 0 when SDP named the channel and it matches --channel, 2 when SDP refused or disagreed, and 3 when
# the sidecar cannot resolve at all.
#
# The channel is not this script's to choose. Upstream never connects to a channel number: it
# registers HuaweiConstants.UUID_SERVICE_HUAWEI_SDP and asks the stack for a socket to that service
# record. A live run resolves the channel through SDP, refuses to start if SDP cannot be read or names
# no serial channel, and refuses if SDP disagrees with --channel. A channel found by probe-channel is
# never used instead, and the sidecar refuses to connect to a channel it did not resolve itself.
#
# --sdp-only is that same resolution without the run. It asks the sidecar to resolve the channel
# through SDP, prints the masked watch address, the service UUID, the channel, the method that named
# it and the evidence behind it (a Huawei-UUID record, a serial-port record), writes those lines to
# this run's report file, and exits. It stops before opening any RFCOMM connection, before reading the
# auth key, and before a single frame is sent. Its gate is the same terminal gate as a live run, with
# a different word — SDPLOOKUP, never AUTHENTICATE — so a lookup can never be mistaken for a
# handshake, and it reads no key and writes no identity file.
#
# Every run writes its own pair of files, named with the UTC stamp and this shell's pid, so a failed
# run can never destroy the evidence of the run before it: $RUN_LOG (masked output) and $REPORT (the
# stage reached, the typed codes, and the byte and frame counts — the difference between "the watch
# said nothing" and "the watch said something else").
#
# Privacy, and the rules this file is built to keep:
#   * bind reads the auth key from ~/.config/aether-bcs/auth-key.txt (mode 0600), as does an
#     explicit --key path. Default auth-then-bind reads no key file: operation 1 derives from the
#     watch's PinCode response. A key value is never passed in an argument, echoed, logged or printed.
#   * a generated key comes from node:crypto randomBytes(16) and is written straight to that file;
#     it is never printed, never logged and never leaves this machine except to the watch. It is NOT
#     a way to obtain the HiChain key: on the path this helper implements, the watch issues the
#     long-term key during the bind, and a locally generated one cannot complete a bind. --generate
#     exists for HiChainLite and normal mode, which this helper refuses, so treat it as a testing
#     convenience and store the key your watch and Gadgetbridge agree on with --set-key.
#   * the Huawei account ID (17-19 digits) lives in its own file, ~/.config/aether-bcs/account.txt,
#     written by --set-account from a hidden prompt, mode 0600, never echoed and never in a report.
#     It is NOT the auth key: the key is hexadecimal, the account is digits, and Gadgetbridge keeps
#     them in two different preferences. See docs/BCS_PHASE3.md §8.1 and §8.2.
#   * --with-account asks for the account step that upstream sends after a finished bind. Until this
#     helper can encrypt that frame (it must be wrapped in 0x7C/0x7D/0x7E with the derived key), a
#     --with-account run stops with exit 3 BEFORE the radio opens, and says so. It never sends an
#     unencrypted account frame.
#   * the pin code is asked of the watch, not of you. On the auth-then-bind path the watch is sent
#     PinCode.Request (0x01/0x2C) and its reply is decrypted in memory with the *static* digest secret,
#     exactly as upstream does (DeviceConfig.java:1419-1462, HuaweiSupportProvider.java:564-578), so
#     nothing is typed and nothing is read from this terminal for it. --pin opts in to the older hidden
#     prompt (read -s) for a watch that does not answer that request; the pin is then piped to the
#     driver on stdin and is not in argv, not in the environment and not in a file. Without --pin a
#     run never waits for anything but the AUTHENTICATE word.
#   * the derived key is NOT printed. It is kept only if you pass --save-derived, and then only in
#     $STATE_DIR/derived.key with mode 0600 — that is Phase 4 material.
#   * every line the driver produces is piped through a masker first, so even a Bluetooth address
#     that slipped into a message would leave as XX:XX:XX:XX:AA:BB.
#   * --bt-security asks the stack for a level before connect(), and --require-bond refuses to connect
#     unless bluetoothctl already reports the watch as paired. Both are off by default, so a run that
#     does not name them behaves exactly as it always did. What they do NOT promise: neither one
#     pairs a watch (pairing is done with bluetoothctl or your desktop's settings), neither one
#     reports back what the stack actually granted, and --require-bond cannot tell "pairing is
#     missing" from "bluetoothctl cannot say" — an unverifiable state is a refusal, not a pass.
#   * --phone-model changes the model string the watch is offered during security negotiation. It is
#     not an identity and it is not a secret; it is the one opening frame whose bytes differ from
#     Gadgetbridge's, and it stays the helper's own default unless you name another one.

umask 077
set -uo pipefail

say()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
die()  { warn "$*"; exit 2; }

usage() {
  sed -n '2,$p' "${BASH_SOURCE[0]}" | sed '/^[^#]/Q' | sed 's/^# \{0,1\}//'
}

HELPER_DIR="${BCS_HELPER_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CONFIG_DIR="${BCS_CONFIG_DIR:-$HOME/.config/aether-bcs}"
KEY_FILE="${BCS_AUTH_KEY_FILE:-$CONFIG_DIR/auth-key.txt}"
ACCOUNT_FILE="${BCS_AUTH_ACCOUNT_FILE:-$CONFIG_DIR/account.txt}"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/aether-bcs"
# One log and one report per run, named by the UTC stamp and the shell's pid. A run therefore cannot
# overwrite the run before it, which the first live bind needed: its report was a single file that the
# next attempt replaced, so the evidence of what it reached survived only by luck.
RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || true)"
[[ -n "$RUN_STAMP" ]] || RUN_STAMP="unknown-time"
RUN_STAMP="$RUN_STAMP-$$"
RUN_LOG="$STATE_DIR/auth-run-$RUN_STAMP.log"
REPORT="$STATE_DIR/auth-report-$RUN_STAMP.txt"
IDENTITY="$STATE_DIR/identity.json"
DRIVER="$HELPER_DIR/tools/bcs_auth.mjs"
SIDECAR="$HELPER_DIR/sidecar/rfcomm_sidecar.py"
MODE="bind"
EXPLICIT_KEY=0
CHANNEL="${BCS_CHANNEL:-18}"
SAVE_DERIVED=0
RUN_PLAN=0
SELF_TEST=0
SET_KEY=0
SET_ACCOUNT=0
WITH_ACCOUNT=0
SDP_ONLY=0
GENERATE=0
# --pin is the manual pin-code prompt, and it is off unless it is asked for. The auth-then-bind
# operation uses the pin code the watch sends back (PinCode reply 0x01/0x2C, decrypted with the static
# digest secret), which is what upstream does; typing it here is the fallback for a watch that does not
# answer that request.
PIN_PROMPT=0
# Phase 3G link options. None of these is on unless it is asked for, so a run that names none of them
# is exactly the run this script always was.
BT_SECURITY="${BCS_BT_SECURITY:-none}"
REQUIRE_BOND=0
PHONE_MODEL="${BCS_PHONE_MODEL:-}"
KEY_PROMPT_TTY_STATE=""

parse_args() {
  while (( $# )); do
    case "$1" in
      --self-test)    SELF_TEST=1 ;;
      --plan)         RUN_PLAN=1 ;;
      --set-key)      SET_KEY=1 ;;
      --set-account)  SET_ACCOUNT=1 ;;
      --with-account) WITH_ACCOUNT=1 ;;
      --sdp-only)     SDP_ONLY=1 ;;
      --generate)     GENERATE=1 ;;
      --pin)          PIN_PROMPT=1 ;;
      --require-bond) REQUIRE_BOND=1 ;;
      --bt-security)  shift; BT_SECURITY="${1:-}" ;;
      --phone-model)  shift; PHONE_MODEL="${1:-}" ;;
      --mode)         shift; MODE="${1:-}" ;;
      --channel)      shift; CHANNEL="${1:-}" ;;
      --key)          shift; KEY_FILE="${1:-$KEY_FILE}"; EXPLICIT_KEY=1 ;;
      --save-derived) SAVE_DERIVED=1 ;;
      --helper)       shift; HELPER_DIR="${1:-$HELPER_DIR}" ;;
      --help|-h)      usage; exit 0 ;;
      *)              warn "bcs_auth: unknown argument: $1"; warn "try: bash $0 --help"; exit 2 ;;
    esac
    shift || true
  done
  case "$MODE" in
    bind|auth-then-bind) ;;
    *) die "bcs_auth: --mode takes bind or auth-then-bind, not '$MODE'." ;;
  esac
  if [[ ! "$CHANNEL" =~ ^[0-9]{1,2}$ ]] || (( CHANNEL < 1 || CHANNEL > 30 )); then
    die "bcs_auth: --channel takes a number from 1 to 30 (RFCOMM has 30)."
  fi
  # A pin code belongs to the auth-then-bind operation and to nothing else: the bind operation keys the
  # handshake from the stored key, and every other flag here writes a file or resolves a channel. A pin
  # that could never be used is refused, not ignored, so it can never look like it had taken effect.
  if (( PIN_PROMPT )) && [[ "$MODE" != "auth-then-bind" ]]; then
    die "bcs_auth: --pin supplies the pin code that only --mode auth-then-bind uses; nothing was opened."
  fi
  # The two link options and the model string are validated before anything else happens, so a typo
  # cannot reach the sidecar and cannot become a different link.
  case "$BT_SECURITY" in
    none|low|medium|high) ;;
    *) die "bcs_auth: --bt-security takes none, low, medium or high, not '$BT_SECURITY'. Nothing was opened." ;;
  esac
  if [[ -n "$PHONE_MODEL" ]] && [[ ! "$PHONE_MODEL" =~ ^[[:print:]]{1,32}$ ]]; then
    die "bcs_auth: --phone-model takes 1-32 printable ASCII characters. Nothing was opened."
  fi
  if (( GENERATE )) && (( ! SET_KEY )); then
    die "bcs_auth: --generate belongs with --set-key; nothing was generated and nothing was opened."
  fi
  if (( SET_KEY )) && (( SET_ACCOUNT )); then
    die "bcs_auth: --set-key and --set-account write two different files; run them one at a time."
  fi
  # --sdp-only reads no key, writes no account file and derives nothing, so every flag that would do
  # one of those is refused here rather than quietly ignored: a lookup must never look like a run.
  if (( SDP_ONLY )); then
    if (( SET_KEY )); then
      die "bcs_auth: --set-key stores the auth key; --sdp-only never reads one. Run them separately."
    fi
    if (( SET_ACCOUNT )); then
      die "bcs_auth: --set-account stores the account ID; --sdp-only never reads one. Run them separately."
    fi
    if (( WITH_ACCOUNT )); then
      die "bcs_auth: --sdp-only resolves a channel and stops; --with-account sends an account frame. Pick one."
    fi
    if (( SAVE_DERIVED )); then
      die "bcs_auth: --sdp-only derives no key, so --save-derived has nothing to save."
    fi
    if (( SELF_TEST )); then
      die "bcs_auth: --self-test and --sdp-only are two different runs; pick one."
    fi
    if (( PIN_PROMPT )); then
      die "bcs_auth: --sdp-only resolves a channel and stops; --pin feeds an auth-then-bind run. Pick one."
    fi
    if (( REQUIRE_BOND )) || [[ "$BT_SECURITY" != "none" ]] || [[ -n "$PHONE_MODEL" ]]; then
      die "bcs_auth: --bt-security, --require-bond and --phone-model belong to a live run; --sdp-only opens no link and sends no frame. Run them separately."
    fi
  fi
  DRIVER="$HELPER_DIR/tools/bcs_auth.mjs"
  SIDECAR="$HELPER_DIR/sidecar/rfcomm_sidecar.py"
}

# ------------------------------------------------------------------------------- masking every line
# The driver already prints only states, byte counts and typed codes. This is the second line of
# defence: any address-shaped text leaves as XX:XX:XX:XX:AA:BB, keeping the last two octets.
stream_mask() {
  python3 -u -c '
import re, sys
mac = re.compile(r"(?i)\b[0-9a-f]{2}([:-])[0-9a-f]{2}\1[0-9a-f]{2}\1[0-9a-f]{2}\1[0-9a-f]{2}\1[0-9a-f]{2}\b")
def masked(m):
    digits = re.sub(r"[^0-9a-fA-F]", "", m.group(0))[-4:].upper()
    return "XX:XX:XX:XX:" + digits[:2] + ":" + digits[2:]
for line in sys.stdin:
    sys.stdout.write(mac.sub(masked, line))
    sys.stdout.flush()
'
}

# ------------------------------------------------------------------------------------- preflight
preflight() {
  [[ -f "$DRIVER" ]] || die "bcs_auth: the driver is missing at $DRIVER"
  command -v node >/dev/null 2>&1 || die "bcs_auth: node is not on PATH (Node >= 22.6 is required)"
  local version
  version="$(node -p 'process.versions.node')" || die "bcs_auth: node did not answer"
  if ! node -p 'String(process.features && process.features.typescript)' 2>/dev/null | grep -qv '^false$'; then
    die "bcs_auth: Node $version does not strip TypeScript types; Node >= 22.6 is required."
  fi
  node --check "$DRIVER" || die "bcs_auth: the driver does not parse; the repository copy is broken."
  [[ -f "$SIDECAR" ]] || die "bcs_auth: the sidecar is missing at $SIDECAR"
  command -v python3 >/dev/null 2>&1 || die "bcs_auth: python3 is not on PATH; the sidecar needs it"
}

check_key_file() {
  [[ -f "$KEY_FILE" ]] || die "bcs_auth: no auth key at $KEY_FILE. Store the key your watch and
          Gadgetbridge agree on, as even-length hexadecimal text:
          bash $0 --set-key
Both write that path with mode 0600. --set-key --generate can make a random 16-byte key here, but a
          generated key cannot complete a HiChain bind — the watch issues that key — so it is only
          useful for the HiChainLite/normal mode this helper refuses. A 17-19 digit Huawei account ID
          is not this value: that one goes in $ACCOUNT_FILE, with: bash $0 --set-account"
  local mode
  mode="$(stat -c '%a' "$KEY_FILE" 2>/dev/null || stat -f '%Lp' "$KEY_FILE" 2>/dev/null || echo '')"
  if [[ -n "$mode" && "$mode" != "600" ]]; then
    warn "bcs_auth: $KEY_FILE is mode $mode, not 600. Fix it before a live run:"
    warn "          chmod 600 $KEY_FILE"
    return 2
  fi
  return 0
}

restore_key_prompt_terminal() {
  if [[ -n "$KEY_PROMPT_TTY_STATE" ]]; then
    stty "$KEY_PROMPT_TTY_STATE" <&0 2>/dev/null || true
    KEY_PROMPT_TTY_STATE=""
  fi
}

check_account_file() {
  [[ -f "$ACCOUNT_FILE" ]] || die "bcs_auth: --with-account needs an account ID at $ACCOUNT_FILE.
          Store the 17-19 digit Huawei account ID first (it is not the auth key):
                    bash $0 --set-account
          That writes the path with mode 0600 and never displays the value."
  local mode
  mode="$(stat -c '%a' "$ACCOUNT_FILE" 2>/dev/null || stat -f '%Lp' "$ACCOUNT_FILE" 2>/dev/null || echo '')"
  if [[ -n "$mode" && "$mode" != "600" ]]; then
    warn "bcs_auth: $ACCOUNT_FILE is mode $mode, not 600. Fix it before a live run:"
    warn "          chmod 600 $ACCOUNT_FILE"
    return 2
  fi
  return 0
}

# ------------------------------------------------------------------------------- generating a key
# 16 bytes from the operating system's CSPRNG, as 32 lowercase hex characters — exactly the form
# Gadgetbridge stores and this helper reads. The value goes to stdout only so the caller can write it
# to the key file; nothing here prints or logs it, and no argument ever carries it.
generate_key_hex() {
  node -e 'process.stdout.write(require("node:crypto").randomBytes(16).toString("hex"))'
}

set_key() {
  if [[ ! -t 0 || ! -t 1 ]]; then
    die "bcs_auth: --set-key requires an interactive terminal."
  fi
  local key_dir answer key_first key_second
  key_dir="$(dirname "$KEY_FILE")"
  if [[ -L "$KEY_FILE" ]]; then
    die "bcs_auth: refusing to write through a symbolic link at $KEY_FILE"
  fi
  if [[ -e "$KEY_FILE" ]]; then
    printf 'auth key already exists at %s. Type OVERWRITE to replace it: ' "$KEY_FILE"
    read -r answer || answer=""
    if [[ "$answer" != "OVERWRITE" ]]; then
      say "not overwritten: the existing key was left unchanged."
      return 2
    fi
  fi
  mkdir -p -m 700 "$key_dir" || die "bcs_auth: cannot create $key_dir"
  chmod 700 "$key_dir" || die "bcs_auth: cannot secure $key_dir"
  if (( GENERATE )); then
    command -v node >/dev/null 2>&1 ||
      die "bcs_auth: --generate takes its entropy from node:crypto, and node is not on PATH."
    key_first="$(generate_key_hex)" || key_first=""
    if [[ ! "$key_first" =~ ^([0-9a-f]{2}){16}$ ]]; then
      key_first=""
      die "bcs_auth: key generation did not produce 16 random bytes; nothing was written."
    fi
    key_second="$key_first"
  else
    command -v stty >/dev/null 2>&1 || die "bcs_auth: stty is required for a hidden key prompt"
    KEY_PROMPT_TTY_STATE="$(stty -g <&0)" || die "bcs_auth: could not read terminal settings"
    trap 'restore_key_prompt_terminal' EXIT INT TERM HUP
    stty -echo <&0 || die "bcs_auth: could not disable terminal echo"
    printf 'auth key in hexadecimal (hidden): '
    IFS= read -rs key_first || key_first=""
    printf '\nrepeat auth key (hidden): '
    IFS= read -rs key_second || key_second=""
    printf '\n'
    restore_key_prompt_terminal
    trap - EXIT INT TERM HUP
    if [[ "$key_first" != "$key_second" ]]; then
      key_first="" key_second=""
      warn "bcs_auth: the entries did not match; no key was written."
      return 2
    fi
    if [[ ! "$key_first" =~ ^([0-9a-fA-F]{2})+$ ]]; then
      key_first="" key_second=""
      warn "bcs_auth: that is not an auth key. The key is even-length hexadecimal text —"
      warn "          32 hex characters for a 16-byte key, which is what --generate writes. Note that a"
      warn "          generated key cannot complete a HiChain bind: the watch issues that key, and only"
      warn "          HiChainLite/normal mode takes a local one, which this helper refuses."
      warn "          A 17-19 digit Huawei account ID is a different value and is not used here."
      warn "          No key was written."
      return 2
    fi
  fi
  if [[ -e "$KEY_FILE" ]]; then
    chmod 600 "$KEY_FILE" || {
      key_first="" key_second=""
      die "bcs_auth: cannot secure existing $KEY_FILE before replacing it"
    }
  fi
  printf '%s\n' "$key_first" >"$KEY_FILE" || {
    key_first="" key_second=""
    die "bcs_auth: could not write $KEY_FILE"
  }
  chmod 600 "$KEY_FILE" || {
    key_first="" key_second=""
    die "bcs_auth: could not secure $KEY_FILE"
  }
  key_first="" key_second=""
  if (( GENERATE )); then
    say "key generated and saved: $KEY_FILE (mode 0600). The 32 hex characters were not displayed."
    warn "note: a generated key cannot complete a HiChain bind — the watch issues that key. It is only"
    warn "      meaningful for HiChainLite/normal mode, which this helper refuses. To authenticate, store"
    warn "      the key your watch and Gadgetbridge agree on with: bash $0 --set-key"
  else
    say "auth key saved at $KEY_FILE (mode 0600). The value was not displayed."
  fi
  return 0
}

# -------------------------------------------------------------------------- storing the account ID
# The Huawei account ID (17-19 digits) that Gadgetbridge's own settings describe as "Huawei account
# used in pairing process. Setting it allows to pair without factory reset" (strings.xml:3366-3367).
# It is not a key and not a secret in the cryptographic sense, but it is personal data, so it gets the
# same treatment as the key: its own file, mode 0600, a hidden prompt, never echoed, never in a log,
# never in a report, and never in an argument.
set_account() {
  if [[ ! -t 0 || ! -t 1 ]]; then
    die "bcs_auth: --set-account requires an interactive terminal."
  fi
  local account_dir answer account_first account_second
  account_dir="$(dirname "$ACCOUNT_FILE")"
  if [[ -L "$ACCOUNT_FILE" ]]; then
    die "bcs_auth: refusing to write through a symbolic link at $ACCOUNT_FILE"
  fi
  if [[ -e "$ACCOUNT_FILE" ]]; then
    printf 'an account ID already exists at %s. Type OVERWRITE to replace it: ' "$ACCOUNT_FILE"
    read -r answer || answer=""
    if [[ "$answer" != "OVERWRITE" ]]; then
      say "not overwritten: the existing account file was left unchanged."
      return 2
    fi
  fi
  mkdir -p -m 700 "$account_dir" || die "bcs_auth: cannot create $account_dir"
  chmod 700 "$account_dir" || die "bcs_auth: cannot secure $account_dir"
  command -v stty >/dev/null 2>&1 || die "bcs_auth: stty is required for a hidden account prompt"
  KEY_PROMPT_TTY_STATE="$(stty -g <&0)" || die "bcs_auth: could not read terminal settings"
  trap 'restore_key_prompt_terminal' EXIT INT TERM HUP
  stty -echo <&0 || die "bcs_auth: could not disable terminal echo"
  printf 'Huawei account ID, 17-19 digits (hidden): '
  IFS= read -rs account_first || account_first=""
  printf '\nrepeat the account ID (hidden): '
  IFS= read -rs account_second || account_second=""
  printf '\n'
  restore_key_prompt_terminal
  trap - EXIT INT TERM HUP
  if [[ "$account_first" != "$account_second" ]]; then
    account_first="" account_second=""
    warn "bcs_auth: the entries did not match; no account was written."
    return 2
  fi
  # Every refusal below names the shape of the problem and the length, never the value itself.
  if [[ ! "$account_first" =~ ^[0-9]+$ ]]; then
    local length=${#account_first}
    account_first="" account_second=""
    warn "bcs_auth: a Huawei account ID is digits only; that was $length characters with at least"
    warn "          one non-digit. No account was written."
    return 2
  fi
  if (( ${#account_first} < 17 || ${#account_first} > 19 )); then
    local length=${#account_first}
    account_first="" account_second=""
    warn "bcs_auth: a Huawei account ID is 17 to 19 digits; that one was $length. No account was"
    warn "          written. This is the account, not the auth key: the key is 32 hex characters and"
    warn "          belongs in $KEY_FILE."
    return 2
  fi
  if [[ -e "$ACCOUNT_FILE" ]]; then
    chmod 600 "$ACCOUNT_FILE" || {
      account_first="" account_second=""
      die "bcs_auth: cannot secure existing $ACCOUNT_FILE before replacing it"
    }
  fi
  printf '%s\n' "$account_first" >"$ACCOUNT_FILE" || {
    account_first="" account_second=""
    die "bcs_auth: could not write $ACCOUNT_FILE"
  }
  chmod 600 "$ACCOUNT_FILE" || {
    account_first="" account_second=""
    die "bcs_auth: could not secure $ACCOUNT_FILE"
  }
  account_first="" account_second=""
  say "account ID saved at $ACCOUNT_FILE (mode 0600). The value was not displayed."
  say "it is read only by --with-account, which today stops before the radio (see --help)."
  return 0
}

sidecar_ready() {
  local response
  # A capability-only ping carries no received data, so it does not need --emit-hex. The driver
  # uses Node's AF_UNIX socketpair for payload delivery; a shell FIFO is deliberately not eligible.
  response="$(printf '%s\n' '{"id":1,"cmd":"ping"}' | python3 "$SIDECAR" \
    --config /nonexistent/aether-bcs-capability-probe 2>/dev/null)" || return 1
  # The capabilities this mode needs are the ones passed in: a live run needs "write" for the
  # allowlisted auth frames and "resolve" for the SDP channel, while --sdp-only needs "resolve"
  # alone, because it never writes. Either way a sidecar that cannot name a channel is no use: this
  # helper never connects to, or reports, a channel that came from a probe.
  python3 -c 'import json, sys
try:
    response = json.loads(sys.stdin.read())
except (json.JSONDecodeError, TypeError):
    raise SystemExit(1)
needed = set(sys.argv[1:])
capabilities = response.get("capabilities", []) if isinstance(response, dict) else []
raise SystemExit(0 if needed and needed.issubset(set(capabilities)) else 1)
' "$@" <<<"$response"
}

# ---------------------------------------------------------------------------------------- self-test
# Offline by construction: it runs the Phase 3 suites, which never open a socket, and it says what
# the live path would do. No key is read, nothing is decrypted, no radio is touched.
self_test() {
  local failures=0
  say "self-test: the Phase 3 suites (offline: no Bluetooth, no key, no watch)"
  if ( cd "$HELPER_DIR" && node --test \
        test/huaweiCrypto.test.ts test/huaweiAuthPackets.test.ts \
        test/huaweiAuthMachine.test.ts test/authKeyLeak.test.ts ) | stream_mask | tail -8; then
    :
  else
    warn "self-test: FAILED — a Phase 3 suite is red; fix that before thinking about a live run"
    failures=$((failures + 1))
  fi
  say ""
  node --check "$DRIVER" >/dev/null 2>&1 && say "self-test: the driver parses" || {
    warn "self-test: the driver does not parse"; failures=$((failures + 1));
  }
  if ! command -v node >/dev/null 2>&1; then
    warn "self-test: node is not on PATH"; failures=$((failures + 1))
  fi
  # The shell's own ping below travels down a FIFO, which is not the shape the driver's child gets:
  # Node hands it one end of a socketpair. That difference made the first real run fail while this
  # self-test passed, so the check now runs the driver's own path: spawnSidecar with --emit-hex.
  if ! command -v python3 >/dev/null 2>&1; then
    warn "self-test: python3 is not on PATH; the sidecar needs it"; failures=$((failures + 1))
  elif ( cd "$HELPER_DIR" && node --test test/sidecarProcess.test.ts ) | stream_mask | tail -6; then
    say "self-test: the driver can start the real sidecar and read its live ping"
  else
    warn "self-test: the driver could not start the real sidecar; a live run would stop with exit 2"
    failures=$((failures + 1))
  fi
  if sidecar_ready write resolve; then
    say "self-test: live ping advertises allowlisted writes and SDP channel resolution"
  else
    say "self-test: live ping lacks allowlisted writes or SDP resolution; a live run stops with exit 3"
  fi
  if (( failures )); then
    warn "self-test: FAILED, $failures check(s)"
    return 1
  fi
  say "self-test: every check passed. No Bluetooth was touched and no key was read."
  return 0
}

# --------------------------------------------------------------------------------------------- plan
# What a --sdp-only run would do. It has to be as literal as the live plan: this text is how someone
# decides whether to type SDPLOOKUP at all, so every claim here is something the driver really does.
plan_sdp_only() {
  say "an SDP-only run of bcs_auth would do exactly this, and nothing else:"
  say ""
  say "  1. require SDPLOOKUP on /dev/tty before anything starts (not AUTHENTICATE: this run does not"
  say "     authenticate, and the two words are different on purpose)"
  say "  2. NOT read the auth key at $KEY_FILE, and NOT touch the watch identity at $IDENTITY"
  say "  3. ask the sidecar's live ping for its capabilities and require SDP channel resolution"
  say "     (no write capability is needed, because this run never sends a frame)"
  say "  4. resolve the RFCOMM channel through SDP for 82ff3820-8411-400c-b85a-55bdb32cf060; refuse to"
  say "     report a channel if SDP cannot be read, cannot name the serial channel, or names a record"
  say "     carrying neither the Huawei UUID nor a serial-port profile. A channel found by probe-channel"
  say "     is never used instead"
  say "  5. print the masked watch address, the service UUID, the channel, the method that named it, the"
  say "     evidence behind it, and whether it matches the saved channel $CHANNEL (a disagreement is"
  say "     sdp-disagreement, the same code a live run refuses with)"
  say "  6. write those lines and the stage trail to this run's report, then exit"
  say ""
  say "it stops before opening any RFCOMM connection, before reading the auth key, before writing the"
  say "run identity, and before a single frame is sent: the SDP query is the whole run."
  say ""
  say "link options are not accepted here: --bt-security, --require-bond, --phone-model and --pin all"
  say "belong to a run that opens something, and this one opens nothing."
  say ""
  say "it would touch: $RUN_LOG (masked) and $REPORT (states, codes and counts only). Both names carry"
  say "                this run's UTC stamp and pid, so a run never overwrites the one before it."
  say "it would NOT touch: the watch, your health data, the key file, the identity file, or any file"
  say "                   outside those two log and report files."
  say ""
  if sidecar_ready resolve; then
    say "status: ready — the live ping advertises SDP channel resolution."
  else
    say "status: BLOCKED — the live ping does not advertise SDP channel resolution, so this run stops"
    say "        with exit 3 before asking anything."
  fi
  if command -v sdptool >/dev/null 2>&1; then
    say "sdp: sdptool is on PATH, so the channel can be resolved without probing."
  else
    say "sdp: sdptool is NOT on PATH. The lookup will stop with sdp-unavailable rather than report a"
    say "     probed channel. Install bluez-deprecated-tools for sdptool."
  fi
  return 0
}

# --------------------------------------------------------------------------------------------- plan
plan() {
  if (( SDP_ONLY )); then
    plan_sdp_only
    return 0
  fi
  say "a live run of bcs_auth would do exactly this, and nothing else:"
  say ""
  if [[ "$MODE" == "bind" ]] || (( EXPLICIT_KEY )); then
    say "  1. read the auth key from $KEY_FILE (mode 0600, checked first; never in an argument)"
  else
    say "  1. read no auth key file: default auth-then-bind derives operation 1 from the watch PIN"
  fi
  if (( WITH_ACCOUNT )); then
    say "     and, because --with-account was given, the account ID from $ACCOUNT_FILE (mode 0600,"
    say "     digits only, 17-19 of them; never in an argument)"
  fi
  say "  2. reuse the watch identity in $IDENTITY, creating a 32-character id once if it is absent"
  say "  3. ask the sidecar's live ping for its capabilities and require allowlisted writes and SDP"
  say "     channel resolution"
  say "  4. resolve the RFCOMM channel through SDP for 82ff3820-8411-400c-b85a-55bdb32cf060; refuse to"
  say "     start if SDP cannot be read, cannot name the serial channel, or names a channel other than"
  say "     $CHANNEL. A channel found by probe-channel is never used instead, and the sidecar refuses"
  say "     to connect to any channel it did not resolve itself"
  say "  5. open that channel through the sidecar, exactly as Phase 1 does"
  if [[ "$BT_SECURITY" == "none" ]] && (( ! REQUIRE_BOND )); then
    say "     link options: bt-security none, require-bond off — the behaviour of every run before"
    say "     these options existed: no security level is requested and the pairing state is not checked"
  else
    say "     link options: bt-security $BT_SECURITY (a request to the stack before connect(), never a"
    say "     report of what the stack granted)"
    if (( REQUIRE_BOND )); then
      say "     require-bond on: the run refuses unless bluetoothctl already reports the watch as paired"
    else
      say "     require-bond off: the pairing state is not checked"
    fi
  fi
  if [[ -n "$PHONE_MODEL" ]]; then
    say "     phone model in security negotiation: $PHONE_MODEL (1-32 printable ASCII; the helper's own"
    say "     default is used when this is not given)"
  fi
  say "  6. run the $MODE operation: link params, device status, security negotiation,"
  if [[ "$MODE" == "auth-then-bind" ]]; then
    if (( PIN_PROMPT )); then
      say "     the pin code read here at a hidden prompt (--pin) and piped to the driver on stdin,"
      say "     HiChain auth steps 1-4, then a fresh bind of 1-4"
    else
      say "     the pin code asked for from the watch itself (PinCode 0x01/0x2C, a 10-byte frame) and"
      say "     decrypted in memory with the static digest secret, HiChain auth steps 1-4, then a fresh"
      say "     bind of 1-4"
    fi
  else
    say "     then HiChain bind steps 1, 2 and 4 (the bind operation never sends step 3)"
  fi
  say "  7. wait per step, following upstream's own numbers: 2000 ms for the link-params reply"
  say "     (HuaweiSupportProvider.java:203, the init queue's initTimeout), 30 000 ms for the first"
  say "     HiChain step and the pin-code step (GetHiChainRequest.java:57, \"the user needs to confirm"
  say "     the pairing request on the device itself\"), and 5000 ms for every later step"
  say "     (GetHiChainRequest.java:58); plus a ${BCS_DEADLINE_MS:-120000} ms ceiling on the whole run"
  say "  8. report each state with a byte count, and record the stage reached together with how many"
  say "     bytes and frames actually arrived: never a frame, a token, a MAC or a key"
  say "  9. on success keep the derived key in memory only, unless --save-derived was given, in"
  say "     which case it goes to $STATE_DIR/derived.key with mode 0600"
  say " 10. close the link, wipe the key, exit"
  if [[ "$MODE" == "auth-then-bind" ]]; then
    say ""
    if (( PIN_PROMPT )); then
      say "the pin code comes from this terminal because --pin was given: it is read with echo off, sent"
      say "to the driver on stdin only, and never written to the log, the report or an argument."
    else
      say "no pin code is typed anywhere: the watch is asked for it over the link (PinCode 0x01/0x2C) and"
      say "its reply is decrypted with the static digest secret. A manual pin is opt-in with --pin, for a"
      say "watch that does not answer that request."
    fi
  fi
  say ""
  say "it would touch: $RUN_LOG (masked) and $REPORT (states, codes and counts only). Both names carry"
  say "                this run's UTC stamp and pid, so a run never overwrites the one before it."
  say "it would NOT touch: the watch's settings, your health data, or any file outside those two."
  say ""
  if sidecar_ready write resolve; then
    say "status: unblocked — the live ping advertises allowlisted writes and SDP resolution."
    if command -v sdptool >/dev/null 2>&1; then
      say "sdp: sdptool is on PATH, so the channel can be resolved without probing."
    else
      say "sdp: sdptool is NOT on PATH. A live run will refuse to start (sdp-unavailable) rather than"
      say "     connect to a probed channel. Install bluez-deprecated-tools for sdptool."
    fi
  else
    say "status: BLOCKED — the live ping lacks allowlisted writes or SDP resolution, so the live path"
    say "        exits 3."
  fi
  if (( WITH_ACCOUNT )); then
    say "account step: BLOCKED — the account frame needs the transaction cipher (0x7C/0x7D/0x7E),"
    say "               which this phase does not implement, so a --with-account run exits 3 before"
    say "               the radio opens. The offline half (file, validation, frame bytes) is complete."
  fi
  if (( REQUIRE_BOND )) && ! command -v bluetoothctl >/dev/null 2>&1; then
    say "bond check: BLOCKED — --require-bond is on and bluetoothctl is not on PATH, so the pairing"
    say "            state cannot be verified. The run refuses (not-bonded) before opening anything:"
    say "            an unverifiable precondition is a refusal, never a pass."
  fi
  return 0
}

# ------------------------------------------------------------------------------ driving the driver
# One place that starts the driver: masked, into this run's own log, with this run's stamp and report
# path. $1 is the pin code (empty when the mode needs none). Returns the driver's own exit status, so
# every caller reports the same codes whether the run was a handshake or a lookup.
drive_driver() {
  local pin="${1:-}" status=0
  : >"$RUN_LOG"
  chmod 600 "$RUN_LOG" || die "bcs_auth: cannot secure $RUN_LOG"
  local env_args=(
    "BCS_CHANNEL=$CHANNEL"
    "BCS_AUTH_MODE=$MODE"
    "BCS_AUTH_KEY_FILE=$KEY_FILE"
    "BCS_AUTH_KEY_EXPLICIT=$EXPLICIT_KEY"
    "BCS_STATE_DIR=$STATE_DIR"
    "BCS_SAVE_DERIVED=$SAVE_DERIVED"
    "BCS_DEADLINE_MS=${BCS_DEADLINE_MS:-120000}"
    "BCS_WITH_ACCOUNT=$WITH_ACCOUNT"
    "BCS_AUTH_ACCOUNT_FILE=$ACCOUNT_FILE"
    "BCS_SDP_ONLY=$SDP_ONLY"
    "BCS_BT_SECURITY=$BT_SECURITY"
    "BCS_REQUIRE_BOND=$REQUIRE_BOND"
    "BCS_PHONE_MODEL=$PHONE_MODEL"
    "BCS_PIN_PROMPT=$PIN_PROMPT"
    # The driver writes the report to this run's own file, the same name this shell reports at the end.
    "BCS_REPORT_FILE=$REPORT"
    "BCS_RUN_STAMP=$RUN_STAMP"
  )
  if [[ -n "$pin" ]]; then
    printf '%s\n' "$pin" | env "${env_args[@]}" node "$DRIVER" 2>&1 | stream_mask | tee -a "$RUN_LOG"
    status=${PIPESTATUS[1]}
  else
    env "${env_args[@]}" node "$DRIVER" 2>&1 | stream_mask | tee -a "$RUN_LOG"
    status=${PIPESTATUS[0]}
  fi
  return "$status"
}

show_report() {
  [[ -f "$REPORT" ]] || return 0
  say ""
  say "report: $REPORT"
  tail -10 "$REPORT" | sed 's/^/  /'
}

# -------------------------------------------------------------------------------------- SDP lookup
# --sdp-only. The same SDP resolution a live run does, and nothing else: no key is read, the identity
# file is not touched, no RFCOMM connection is opened and no frame is sent. The terminal gate is the
# same one, with SDPLOOKUP instead of AUTHENTICATE, so this can never be mistaken for a handshake.
sdp_lookup() {
  if [[ ! -t 0 || ! -t 1 ]]; then
    warn "bcs_auth: run this in your own terminal: it asks you to confirm by hand."
    return 2
  fi
  preflight || return 2
  mkdir -p -m 700 "$STATE_DIR" || die "bcs_auth: cannot write to $STATE_DIR"
  chmod 700 "$STATE_DIR" || die "bcs_auth: cannot secure $STATE_DIR"

  say "about to ask SDP which RFCOMM channel serves the Huawei service on your watch, once."
  say "no RFCOMM connection is opened, no auth key is read, the run identity is not touched and no"
  say "frame is sent: the SDP query is the whole run."
  say ""
  say "the driver will require SDPLOOKUP on /dev/tty before it starts the sidecar."
  say ""
  local status=0
  drive_driver "" || status=$?

  say ""
  case "$status" in
    0) say "resolved: SDP named the channel, and it is the saved channel $CHANNEL." ;;
    1) warn "the lookup stopped: the typed code above says where. Nothing was retried." ;;
    2) warn "no channel proven: the typed code above says why. Nothing was connected, and no key was read." ;;
    3) warn "blocked: the sidecar ping did not advertise SDP channel resolution. Nothing was asked." ;;
    *) warn "the lookup ended with status $status" ;;
  esac
  show_report
  return "$status"
}

# ---------------------------------------------------------------------------------------- live run
# The gate. Two things must be true before a byte goes to the watch: a person is at the keyboard, and
# that person typed the word. A live handshake must never be startable by anything unattended.
live() {
  if [[ ! -t 0 || ! -t 1 ]]; then
    warn "bcs_auth: run this in your own terminal: it asks you to confirm by hand."
    return 2
  fi
  preflight || return 2
  if [[ "$MODE" == "bind" ]] || (( EXPLICIT_KEY )); then
    if ! check_key_file; then
      return 2
    fi
  fi
  # The account step is asked for by --with-account. Both of its obstacles are checked before
  # anything is opened: the file has to exist at mode 0600, and — until the transaction cipher is
  # implemented — the frame itself cannot be sent. Refusing here means the radio is never touched.
  if (( WITH_ACCOUNT )); then
    if ! check_account_file; then
      return 2
    fi
    warn "blocked: --with-account was asked for, and this helper cannot send the account frame yet."
    warn "          Upstream wraps it in the transaction envelope (tags 0x7C/0x7D/0x7E, AES with the"
    warn "          derived key), which this phase does not implement; an unencrypted account frame"
    warn "          would be rejected by the watch. Nothing was opened, read or sent."
    warn "          The offline path is complete: the account file, the validation and the frame bytes"
    warn "          are all tested. Run without --with-account to authenticate on its own."
    return 3
  fi
  mkdir -p -m 700 "$STATE_DIR" || die "bcs_auth: cannot write to $STATE_DIR"
  chmod 700 "$STATE_DIR" || die "bcs_auth: cannot secure $STATE_DIR"

  say ""
  if [[ "$MODE" == "bind" ]] || (( EXPLICIT_KEY )); then
    say "about to authenticate against your watch, once, with the key in $KEY_FILE. The RFCOMM channel"
  else
    say "about to authenticate against your watch, once, deriving operation 1 from the watch PIN."
    say "No auth key file is required. The RFCOMM channel"
  fi
  say "is resolved through SDP, and the run stops before connecting unless SDP names channel $CHANNEL."
  say "The watch may ask you to confirm on its own screen."
  if [[ "$MODE" == "auth-then-bind" ]]; then
    if (( PIN_PROMPT )); then
      say "--pin was given: the pin code is typed here at a hidden prompt and piped to the driver on"
      say "stdin. It is never in argv, never in the environment and never in a file."
    else
      say "the pin code is not typed here: the run asks the watch for it itself (PinCode 0x01/0x2C) and"
      say "decrypts the reply in memory with the static digest secret, exactly as Gadgetbridge does."
      say "the only thing read from this terminal is the word below."
    fi
  fi
  say ""
  if [[ "$MODE" == "bind" ]] || (( EXPLICIT_KEY )); then
    say "the driver will require AUTHENTICATE on /dev/tty before it reads the key or starts the sidecar."
  else
    say "the driver will require AUTHENTICATE on /dev/tty before it starts the sidecar; no key is read."
  fi
  say "the handshake runs once. If it fails it stops: no retry, no second attempt, nothing written"
  say "to the watch beyond the handshake frames. The derived key is never printed."
  say ""
  local pin=""
  if (( PIN_PROMPT )); then
    printf 'pin code for this auth-then-bind run (hidden, not stored): '
    read -rs pin || pin=""
    printf '\n'
    if [[ ! "$pin" =~ ^[0-9]{4,12}$ ]]; then
      warn "bcs_auth: that is not a 4-12 digit pin code; nothing was opened. Without --pin the run asks"
      warn "          the watch for its pin code instead, so try again without the flag first."
      return 2
    fi
  fi

  say ""
  local status=0
  drive_driver "$pin" || status=$?
  pin=""

  say ""
  case "$status" in
    0) say "authenticated: the handshake completed. The derived key was not printed." ;;
    1) warn "the flow stopped: the typed code above says where. Nothing was retried." ;;
    3) warn "blocked: the sidecar ping did not advertise allowlisted writes. Nothing was opened or sent." ;;
    4) warn "timed out: the watch did not answer in time. Nothing was changed." ;;
    5) warn "the link ended underneath the flow. Run it again when the watch is awake." ;;
    *) warn "the run ended with status $status" ;;
  esac
  show_report
  return "$status"
}

# ------------------------------------------------------------------------------------------- main
main() {
  parse_args "$@"
  if (( SET_KEY )); then set_key; return $?; fi
  if (( SET_ACCOUNT )); then set_account; return $?; fi
  if (( SELF_TEST )); then self_test; return $?; fi
  if (( RUN_PLAN )); then plan; return $?; fi
  if (( SDP_ONLY )); then sdp_lookup; return $?; fi
  live
}

main "$@"
exit $?