#!/bin/bash
# BCS helper — Phase 1 (link only): pair the watch once, then hand its channel to probe-channel.
# Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
# See NOTICE in the helper directory for attribution and privacy rules (../NOTICE from here).
#
# Phase 1 rule: this script never sends a single byte to the watch. Everything it does is Bluetooth
# control-plane work — discovery, one bond you explicitly approve, and one SDP/RFCOMM query handed
# to probe-channel. No auth code, no cookie and no account token is read, asked for or stored.
#
#   bash bcs/helper/tools/bcs_pair.sh              # the real thing, in your own terminal
#   bash bcs/helper/tools/bcs_pair.sh --dry-list   # list known devices, masked; radio stays quiet
#   bash bcs/helper/tools/bcs_pair.sh --self-test  # check the plumbing; no Bluetooth involved
#
# Exit codes: 0 = paired (or dry-list/self-test passed), 1 = it ran and failed (the reason is on
# screen and in the report), 2 = it could not even start (no bluetoothctl, no saved address, or no
# terminal to ask the passkey question in).
#
# Privacy: the watch's address is read from ~/.config/aether-bcs/watch.json, never from an
# argument, and is never printed in full. Every line this script produces — screen, log, report —
# goes through a stream masker first, so an address that arrives split across two reads still
# cannot leak.

set -uo pipefail

say()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
die()  { warn "$*"; exit 2; }

usage() {
  sed -n '2,$p' "${BASH_SOURCE[0]}" | sed '/^[^#]/Q' | sed 's/^# \{0,1\}//'
}

# Where things live. The helper is found relative to this script, so the repository copy and a copy
# kept somewhere else (with --helper or BCS_HELPER_DIR) both work. Output files are masked by
# construction, and they live under the state directory rather than /tmp: /tmp is a tmpfs here, so
# a reboot would take the evidence with it.
HELPER_DIR="${BCS_HELPER_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CONFIG_PATH="${BCS_CONFIG:-$HOME/.config/aether-bcs/watch.json}"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/aether-bcs"
LIVE="$STATE_DIR/pair-live.log"
REPORT="$STATE_DIR/pair-report.txt"
WORK=""
FIFO=""
SESSION_PID=""
WATCH_ADDRESS=""
WATCH_MASKED="XX:XX:XX:XX:XX:XX"
CHANNEL=18
DO_PROBE=1
SELF_TEST=0
DRY_LIST=0
SCAN_SECONDS=60
PAIR_SECONDS=60
GATE_SECONDS=90

parse_args() {
  while (( $# )); do
    case "$1" in
      --self-test) SELF_TEST=1 ;;
      --dry-list)  DRY_LIST=1 ;;
      --no-probe)  DO_PROBE=0 ;;
      --channel)   shift; CHANNEL="${1:-}" ;;
      --helper)    shift; HELPER_DIR="${1:-$HELPER_DIR}" ;;
      --timeout)   shift; SCAN_SECONDS="${1:-60}"; PAIR_SECONDS="$SCAN_SECONDS" ;;
      --help|-h)   usage; exit 0 ;;
      *)           warn "bcs_pair: unknown argument: $1"; warn "try: bash $0 --help"; exit 2 ;;
    esac
    shift || true
  done
  if [[ ! "$CHANNEL" =~ ^[0-9]{1,2}$ ]] || (( CHANNEL < 1 || CHANNEL > 30 )); then
    die "bcs_pair: --channel takes a number from 1 to 30 (RFCOMM has 30)."
  fi
}

# ---------------------------------------------------------------------------- masking and the log
# One filter for every stream. It masks addresses, and it also flushes a partial line that looks
# like a prompt: bluetoothctl writes "[agent] Confirm passkey 123456 (yes/no):" with no trailing
# newline, and a log that waited for one would never show the passkey question at all.
stream_mask() {
  python3 -u -c '
import os, re, sys

OCTET = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
PROMPT = re.compile(r"\((?:yes/no|y/n|number in [^)]*|pin(?:\s+code)?)\)\s*[:?]?\s*$", re.IGNORECASE)


def mask(text):
    def keep(match):
        address = match.group(0)
        return "XX:XX:XX:XX:" + address[12:14].upper() + ":" + address[15:17].upper()

    return OCTET.sub(keep, text)


buffer = ""
while True:
    chunk = os.read(0, 4096)
    if not chunk:
        break
    buffer += chunk.decode("utf-8", "replace")
    while "\n" in buffer:
        line, buffer = buffer.split("\n", 1)
        sys.stdout.write(mask(line) + "\n")
    # A prompt is written without a trailing newline, and the passkey question IS the gate, so a
    # recognisable question is flushed at once. Nothing else is flushed early: a read can land in
    # the middle of an address, and half an address printed on its own is still a leak.
    if PROMPT.search(buffer):
        sys.stdout.write(mask(buffer) + "\n")
        buffer = ""
    elif len(buffer) > 8192:
        sys.stdout.write(mask(buffer) + "\n")
        buffer = ""
    sys.stdout.flush()
if buffer:
    sys.stdout.write(mask(buffer) + "\n")
'
}

# Session helpers. bluetoothctl is kept on a FIFO so it can never read this script's stdin (your
# answers) and so one session — one agent, one discovery — spans discovery and pairing. That
# matters: an unpaired device leaves BlueZ's cache the moment discovery stops, and the watch must
# not vanish between "found it" and "pair it".
session_send() {
  local command="$1" shown="$1"
  case "$command" in
    yes|no) shown="[agent reply withheld]" ;;
    [0-9][0-9][0-9][0-9][0-9][0-9]) shown="[agent reply withheld]" ;;
  esac
  if [[ -n "$WATCH_ADDRESS" ]]; then
    shown="${shown//$WATCH_ADDRESS/$WATCH_MASKED}"
  fi
  printf '%s\n' "$command" >&9 2>/dev/null || { warn "bcs_pair: the bluetoothctl session is gone."; return 1; }
  # The arrow goes in the argument, never in the format: printf reads a format that starts with "-"
  # as an option ("printf: ->: invalid option") and then writes nothing at all.
  printf '%s\n' "-> $shown" >>"$LIVE" 2>/dev/null || true
}

session_start() {
  FIFO="$WORK/agent.in"
  mkfifo "$FIFO" || { warn "bcs_pair: could not create $FIFO"; return 1; }
  bluetoothctl <"$FIFO" > >(stream_mask >>"$LIVE") 2>&1 &
  SESSION_PID=$!
  exec 9>"$FIFO" || { warn "bcs_pair: could not open the bluetoothctl session"; return 1; }
  sleep 1
  if ! kill -0 "$SESSION_PID" 2>/dev/null; then
    warn "bcs_pair: bluetoothctl stopped immediately; is the Bluetooth service running?"
    return 1
  fi
  return 0
}

session_stop() {
  if [[ -n "$SESSION_PID" ]] && kill -0 "$SESSION_PID" 2>/dev/null; then
    printf 'scan off\nagent off\nquit\n' >&9 2>/dev/null || true
  fi
  # No 2>/dev/null here: exec is a special builtin, so a redirection on this line would silence the
  # rest of the run, warnings included.
  exec 9>&- || true
  sleep 1
  [[ -n "$SESSION_PID" ]] && kill "$SESSION_PID" 2>/dev/null
  SESSION_PID=""
}

# The line readers. Every one of them is case-insensitive on purpose: bluetoothctl shouts device
# names ("HUAWEI WATCH GT 5-121") while the things we look for are written in lower case, and a
# case-sensitive search reports a watch that is plainly in the log as missing. That was a real bug
# in the first version of this script; self_test() below fails if it ever comes back.
wait_for_line() {
  local needle="$1" limit="${2:-60}" waited=0
  while :; do
    if grep -aqiE -- "$needle" "$LIVE" 2>/dev/null; then
      return 0
    fi
    (( waited >= limit )) && return 1
    sleep 1
    waited=$((waited + 1))
  done
}

# The log this reads is already masked, so the watch is found by its masked address: a needle
# carrying the full address could never match a masked line. Matching the address rather than the
# device name also survives a watch being renamed in the phone's own app. The [NEW] line is the one
# that counts — later [CHG] lines repeat the same address with RSSI chatter, so taking the last
# match picked one of those and named the wrong line.
found_device() {
  local line
  line="$(grep -aiE -- "^\[NEW\] Device $WATCH_MASKED" "$LIVE" 2>/dev/null | tail -n 1)"
  if [[ -z "$line" ]]; then
    line="$(grep -aiE -- "device[[:space:]]+$WATCH_MASKED" "$LIVE" 2>/dev/null | tail -n 1)"
  fi
  printf '%s\n' "$line"
}
seen_devices() { grep -aE -- '^\[NEW\] Device ' "$LIVE" 2>/dev/null; }
prompt_lines() { grep -aiE -- '\[agent\]|passkey|confirmation' "$LIVE" 2>/dev/null | tail -n 5; }
result_lines() {
  grep -aiE -- 'pairing successful|failed to pair|authentication|already ?exists|not available' \
    "$LIVE" 2>/dev/null | tail -n 5
}

# ------------------------------------------------------------------------------------ pre-flight
# The address is read with python3 from the same file the rest of the helper uses, and it is never
# passed as an argument to this script, so it cannot land in a shell history or a process list.
load_address() {
  WATCH_ADDRESS="$(BCS_CONFIG="$CONFIG_PATH" python3 -c '
import json, os, re

path = os.environ.get("BCS_CONFIG") or os.path.expanduser("~/.config/aether-bcs/watch.json")
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, ValueError):
    raise SystemExit(0)
address = str(data.get("address") or "").strip() if isinstance(data, dict) else ""
if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", address):
    print(address)
' 2>/dev/null)"
  if [[ -z "$WATCH_ADDRESS" ]]; then
    warn "bcs_pair: no usable watch address saved in $CONFIG_PATH"
    warn "  list what this machine knows:  cd \"$HELPER_DIR\" && python3 tools/watch-address.py list"
    warn "  save the watch's address:      cd \"$HELPER_DIR\" && python3 tools/watch-address.py save"
    return 1
  fi
  WATCH_ADDRESS="${WATCH_ADDRESS^^}"
  WATCH_MASKED="XX:XX:XX:XX:${WATCH_ADDRESS:12:2}:${WATCH_ADDRESS:15:2}"
  return 0
}

preflight() {
  local tool missing=0 answer=""
  for tool in bluetoothctl python3; do
    command -v "$tool" >/dev/null 2>&1 || { warn "bcs_pair: $tool is not installed"; missing=1; }
  done
  (( missing )) && return 1
  if [[ ! -f "$HELPER_DIR/probe-channel" ]]; then
    warn "bcs_pair: probe-channel is not in $HELPER_DIR"
    warn "  run the repository copy of this script, or pass --helper <the bcs/helper directory>"
    return 1
  fi
  say "Two things have to be true before this starts:"
  say "  1. the phone's Bluetooth is off (or Huawei Health is disconnected): the watch accepts one"
  say "     classic link at a time, and it refuses or drops the newcomer while the phone holds it"
  say "  2. the watch is awake, its Bluetooth is on, and it is showing its Bluetooth/pairing screen"
  say ""
  say "Then: this script discovers the watch and asks BlueZ to pair, and it STOPS there. Nothing is"
  say "confirmed until you compare the code with your watch and answer below. No bytes go to the watch."
  say ""
  read -r -p "type yes to start (anything else cancels): " answer || return 1
  case "$answer" in
    yes|YES|Yes) return 0 ;;
    *) say "cancelled; nothing was changed."; return 1 ;;
  esac
}

# ----------------------------------------------------------------------------------- discovery
scan_for_watch() {
  say "scanning for up to ${SCAN_SECONDS}s, looking for $WATCH_MASKED ..."
  session_send "agent KeyboardDisplay" || return 1
  session_send "scan on" || return 1
  if wait_for_line "device[[:space:]]+$WATCH_MASKED" "$SCAN_SECONDS"; then
    say "found: $(found_device)"
    return 0
  fi
  return 1
}

# What a genuine miss looks like. The first version of this script ended with a tail of unrelated
# lines and left the user guessing whether the watch had been seen at all, so every device BlueZ
# reported is listed here (masked, and already masked in the log it is read from).
seen_devices_report() {
  local list
  list="$(seen_devices | head -n 20)"
  if [[ -z "$list" ]]; then
    say "  (BlueZ reported no device at all during this scan)"
    return 0
  fi
  say "devices BlueZ reported during this scan (masked, first 20):"
  printf '%s\n' "$list" | sed 's/^/  /'
  say "the script matches the address saved in $CONFIG_PATH, not the name, so a watch in that list"
  say "would have matched: compare the addresses above with $WATCH_MASKED."
}

# -------------------------------------------------------------------------------------- pairing
# The human gate. This is Numeric Comparison: BlueZ prints a passkey, and the answer is yes/no.
# The typed answer is sent to BlueZ; it is not the watch's six-digit code and never claims to be.
confirm_passkey() {
  local prompt digits answer
  prompt="$(prompt_lines | tail -n 1)"
  if [[ -z "$prompt" ]]; then
    warn "bcs_pair: the pairing agent said nothing to confirm, so nothing was confirmed."
    return 1
  fi
  say ""
  say "bluetoothctl's agent says:"
  say "  $prompt"
  digits="$(printf '%s' "$prompt" | grep -aoE '[0-9]{6}' | tail -n 1)"
  say ""
  if [[ -n "$digits" ]]; then
    say "BlueZ is asking whether passkey $digits matches the code shown on the watch."
    say "Answer yes only when those two numbers match. Do not type the six digits as the answer."
  else
    say "answer yes only if you approve the exact request shown above; otherwise answer no."
  fi
  say "the watch's pairing window is short: answer within ${GATE_SECONDS}s."
  say ""
  read -r -t "$GATE_SECONDS" -p "compare the codes, then type yes to confirm: " answer || {
    warn "bcs_pair: no answer within ${GATE_SECONDS}s; nothing was confirmed."
    return 1
  }
  case "$answer" in
    yes|YES|Yes)                    session_send "yes" ;;
    [0-9][0-9][0-9][0-9][0-9][0-9])
      say "not confirmed: this is a yes/no comparison, not a prompt to enter the passkey."
      session_send "no"
      return 1 ;;
    *) say "not confirmed; turning the request down..."
       session_send "no"
       return 1 ;;
  esac
  return 0
}

pair_watch() {
  say ""
  say "asking BlueZ to pair. For Numeric Comparison, confirm only when BlueZ's passkey and the"
  say "watch's code match; the answer below is yes/no, not the six-digit code itself."
  session_send "pair $WATCH_ADDRESS" || return 1
  if ! wait_for_line '\[agent\]|pairing successful|failed to pair|authentication' "$PAIR_SECONDS"; then
    warn "bcs_pair: the watch did not react within ${PAIR_SECONDS}s, so no bond was made."
    warn "  Check that it is awake, on its Bluetooth screen, close by, and free of the phone."
    return 1
  fi
  if grep -aqiE -- 'pairing successful|already ?exists' "$LIVE" 2>/dev/null; then
    say "BlueZ says it is already bonded, so there is no code to confirm."
  else
    # wait_for_line returned as soon as the agent question appeared. Print that exact question now,
    # before asking the human; do not wait for a later pairing result to reveal it.
    result_lines | tr '\r' '\n' | grep -aEi 'Confirm passkey [0-9]+' | tail -n1 | say
    confirm_passkey || return 1
    if ! wait_for_line 'pairing successful|already ?exists|failed to pair|authentication (failed|rejected|timeout)' "$PAIR_SECONDS"; then
      warn "bcs_pair: no pairing result came back within ${PAIR_SECONDS}s."
      return 1
    fi
  fi
  say ""
  say "what BlueZ said:"
  result_lines | sed 's/^/  /'
  if ! grep -aqiE -- 'pairing successful|already ?exists' "$LIVE" 2>/dev/null; then
    warn "bcs_pair: that is not a success, so the bond was not made."
    warn "  If it says authentication failed, an older key may still be in the way: remove the watch"
    warn "  from this machine, and on the watch remove this PC from its own Bluetooth list."
    return 1
  fi
  say "bonded."
  session_send "trust $WATCH_ADDRESS" || true
  sleep 1
  session_send "info $WATCH_ADDRESS" || true
  sleep 1
  say "BlueZ's own view of the device (masked):"
  grep -aiE -- '^[[:space:]]+(Trusted|Paired|Bonded|Name|Alias):' "$LIVE" 2>/dev/null | tail -n 6 | sed 's/^/  /'
  return 0
}

# ----------------------------------------------------------------------------------------- probe
run_probe() {
  if (( ! DO_PROBE )); then
    say "channel probe skipped (--no-probe). Run it yourself with:"
    say "  cd \"$HELPER_DIR\" && python3 probe-channel --channels $CHANNEL --no-sdp --verbose"
    return 0
  fi
  say ""
  say "handing channel $CHANNEL to probe-channel: it connects, takes SDP, and writes nothing."
  local status
  ( cd "$HELPER_DIR" && python3 probe-channel --channels "$CHANNEL" --no-sdp --verbose ) 2>&1 \
    | stream_mask | tee -a "$LIVE"
  status="${PIPESTATUS[0]}"
  if (( status == 0 )); then
    say "the channel accepted: the link half of Phase 1 is done, and nothing was sent to the watch."
  else
    say "probe-channel exited $status, so no channel accepted. The bond itself worked, which points"
    say "at the watch side (awake, not held by the phone) rather than at the pairing."
  fi
  return "$status"
}

# ----------------------------------------------------------------------------------- bookkeeping
# The report is the evidence of the run. It is built from the already-masked live log, so no full
# address can reach it, and it is written under the state directory rather than /tmp, which a
# reboot empties.
write_report() {
  local status="$1"
  mkdir -p "$STATE_DIR" 2>/dev/null || true
  {
    printf '# bcs_pair report\n'
    printf '# %s\n' "$(date -Is 2>/dev/null || date)"
    printf '# masked_address: %s\n' "$WATCH_MASKED"
    printf '# channel tried: %s\n' "$CHANNEL"
    printf '# exit: %s\n' "$status"
    printf '# every line below is masked; a full address never reaches this file\n'
    cat "$LIVE" 2>/dev/null
  } >>"$REPORT" 2>/dev/null || warn "bcs_pair: could not write $REPORT"
  chmod 600 "$REPORT" 2>/dev/null || true
  say "report (masked, kept for the record): $REPORT"
}

print_undo() {
  say ""
  say "undo, if you ever want it — the bond is the only thing this script changed:"
  say "  bluetoothctl disconnect <the address>     # or: bluetoothctl remove <the address>"
  say "  bluetoothctl untrust <the address>"
  say "  rm $CONFIG_PATH"
  say "  and on the watch: Bluetooth > this PC > unpair"
  say "note: Huawei Health may then need the watch added again. Phase 1 asks for no key, no account"
  say "token and no cookie, so none of that is read, and nothing of yours is stored on this machine."
}

# -------------------------------------------------------------------------------------- self-test
# Nothing here touches Bluetooth: the masker, the needle matching and the line readers are pure
# string work. The log is seeded the way a real run leaves it — through the masker — so these tests
# read exactly what the script reads live.
#
# The regression: the first version searched its own log for a lower-case device name while
# bluetoothctl writes "HUAWEI WATCH GT 5-121", so a run could report "the watch was not found" with
# the watch sitting in its own log two seconds in. The guard below fails if that case bug could no
# longer be caught, so this test cannot quietly stop testing anything.
self_test() {
  local failures=0 out found sample="AA:BB:CC:DD:EE:FF"
  WATCH_ADDRESS="$sample"
  WATCH_MASKED="XX:XX:XX:XX:EE:FF"
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/bcs_selftest.XXXXXX")"
  LIVE="$WORK/live.log"

  out="$(printf 'Device %s HUAWEI WATCH GT 5-121\n' "$sample" | stream_mask)"
  case "$out" in
    *"XX:XX:XX:XX:EE:FF"*) : ;;
    *) warn "FAIL the masker did not keep the last two octets: $out"; failures=$((failures + 1)) ;;
  esac
  case "$out" in
    *"$sample"*) warn "FAIL the masker let the whole address through: $out"; failures=$((failures + 1)) ;;
  esac
  case "$out" in
    *"HUAWEI WATCH GT 5-121"*) : ;;
    *) warn "FAIL the masker damaged the device name: $out"; failures=$((failures + 1)) ;;
  esac

  out="$(printf 'again %s\n' "XX:XX:XX:XX:EE:FF" | stream_mask)"
  case "$out" in
    *"XX:XX:XX:XX:EE:FF"*) : ;;
    *) warn "FAIL masking was not idempotent: $out"; failures=$((failures + 1)) ;;
  esac

  # An address can arrive in two reads; the masker must not leak the half it saw first.
  out="$( { printf '[NEW] Device AA:BB:CC:DD:'; sleep 0.3; printf 'EE:FF HUAWEI WATCH GT 5-121\n'; } | stream_mask )"
  case "$out" in
    *"AA:BB:CC:DD"*) warn "FAIL an address split across two reads leaked: $out"; failures=$((failures + 1)) ;;
  esac
  case "$out" in
    *"XX:XX:XX:XX:EE:FF"*) : ;;
    *) warn "FAIL a split address was not masked: $out"; failures=$((failures + 1)) ;;
  esac

  # bluetoothctl writes the passkey question with no newline; holding it back would hide the gate.
  out="$(printf '[agent] Confirm passkey 123456 (yes/no): ' | stream_mask)"
  case "$out" in
    *123456*) : ;;
    *) warn "FAIL a prompt with no newline was held back: $out"; failures=$((failures + 1)) ;;
  esac

  # A live log as a real run leaves it: masked, with the watch in it and unrelated chatter around it.
  {
    printf '[CHG] Device 11:22:33:44:55:66 RSSI: -70\n'
    printf '[NEW] Device %s HUAWEI WATCH GT 5-121\n' "$sample"
    printf '[CHG] Device %s ManufacturerData Key: 0x00ff\n' "$sample"
    printf '[Bluetooth]# pair the watch\n'
  } | stream_mask >"$LIVE"

  if grep -aq "$sample" "$LIVE"; then
    warn "FAIL the seeded log is not masked, so it does not mirror a real run"
    failures=$((failures + 1))
  fi
  if grep -aqE -- 'huawei watch gt 5' "$LIVE"; then
    warn "FAIL the seeded log no longer reproduces the old case bug, so the guard below proves nothing"
    failures=$((failures + 1))
  fi
  if ! wait_for_line 'huawei watch gt 5' 1; then
    warn "FAIL wait_for_line missed an upper-case device name (case-sensitive matching is back)"
    failures=$((failures + 1))
  fi
  if ! wait_for_line "device[[:space:]]+$WATCH_MASKED" 1; then
    warn "FAIL wait_for_line missed the watch by its masked address"
    failures=$((failures + 1))
  fi
  if wait_for_line 'there is no such device in this log' 1; then
    warn "FAIL wait_for_line found something that was never logged"
    failures=$((failures + 1))
  fi

  found="$(found_device)"
  case "$found" in
    *"XX:XX:XX:XX:EE:FF"*"HUAWEI WATCH GT 5-121"*) : ;;
    *) warn "FAIL found_device did not pick the watch out of the log: $found"; failures=$((failures + 1)) ;;
  esac
  if [[ "$(seen_devices | wc -l)" != "1" ]]; then
    warn "FAIL seen_devices counted the wrong number of new devices"; failures=$((failures + 1))
  fi
  if seen_devices_report | grep -aq 'AA:BB:CC:DD'; then
    warn "FAIL the miss report leaked an unmasked address"; failures=$((failures + 1))
  fi

  # session_send writes the real command to the session and only a masked copy to the log.
  exec 9>"$WORK/fd9.log"
  session_send "pair $sample" >/dev/null || true
  exec 9>&- || true   # no redirection on this line: exec would keep it for the whole run
  if ! grep -aq -- 'pair XX:XX:XX:XX:EE:FF' "$LIVE"; then
    warn "FAIL session_send did not log a masked command"
    warn "     log tail: $(tail -n 3 "$LIVE" 2>/dev/null | tr '\n' '|')"
    failures=$((failures + 1))
  fi
  if ! grep -aq -- "$sample" "$WORK/fd9.log" 2>/dev/null; then
    warn "FAIL the pair command never reached the session channel"
    failures=$((failures + 1))
  fi
  if grep -aq "$sample" "$LIVE"; then
    warn "FAIL a full address reached the log"; failures=$((failures + 1))
  fi

  printf '[agent] confirm passkey 123456 (yes/no):\n' >>"$LIVE"
  if ! prompt_lines | grep -aqi -- 'confirm passkey'; then
    warn "FAIL prompt_lines did not read the agent's question"; failures=$((failures + 1))
  fi
  printf '[Bluetooth]# Failed to pair: org.bluez.Error.AuthenticationFailed\n' >>"$LIVE"
  if ! result_lines | grep -aqi -- 'authenticationfailed'; then
    warn "FAIL result_lines did not read the pairing result"; failures=$((failures + 1))
  fi

  rm -rf "$WORK"
  if (( failures )); then
    warn "self-test: FAILED, $failures check(s)"
    return 1
  fi
  say "self-test: every check passed — masking, idempotence, split reads, newline-less prompts,"
  say "           masked-address matching, case-insensitive names, an absent needle, the device"
  say "           list, agent questions and pairing results. No Bluetooth was touched."
  return 0
}

# --------------------------------------------------------------------------------------- dry-list
# Lists what BlueZ already knows and says whether the saved watch is in there. No scan, no session,
# no pairing: the radio is left exactly as it was.
dry_list() {
  local out
  load_address || true
  say "devices this machine knows (BlueZ cache only; no scan, radio untouched):"
  out="$(bluetoothctl devices 2>&1 | stream_mask)"
  if printf '%s\n' "$out" | grep -aqE '^Device '; then
    printf '%s\n' "$out" | grep -aE '^Device ' | sed 's/^/  /'
  else
    say "  (nothing in the cache)"
  fi
  say ""
  if [[ -z "$WATCH_ADDRESS" ]]; then
    return 0
  fi
  if printf '%s\n' "$out" | grep -aqiE "Device[[:space:]]+$WATCH_MASKED"; then
    say "the saved watch ($WATCH_MASKED) is in that list."
  else
    say "the saved watch ($WATCH_MASKED) is NOT in that list — normal before pairing: an unpaired"
    say "device leaves the cache when discovery stops, which is why the real run keeps one session"
    say "open from discovery through pairing."
  fi
  return 0
}

# ------------------------------------------------------------------------------------------ main
main() {
  parse_args "$@"
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/bcs_pair.XXXXXX")" || die "bcs_pair: could not create a work directory"
  trap 'session_stop >/dev/null 2>&1; rm -rf "$WORK"' EXIT

  if (( SELF_TEST )); then self_test; return $?; fi
  if (( DRY_LIST )); then dry_list; return $?; fi

  # The start confirmation and the passkey gate have to be answered by a person at a keyboard, so
  # this refuses to run with its input or output redirected.
  if [[ ! -t 0 || ! -t 1 ]]; then
    warn "bcs_pair: run this in your own terminal: it asks you questions and waits for your answers."
    return 2
  fi
  mkdir -p "$STATE_DIR" || die "bcs_pair: cannot write to $STATE_DIR"
  preflight || return 2
  load_address || return 2

  # One live log per run; the previous one is already in the report.
  : >"$LIVE"
  say ""
  say "watch: $WATCH_MASKED    channel to try after pairing: $CHANNEL"
  say "the full address stays in this process and in $CONFIG_PATH; the screen, the log and the"
  say "report only ever see masked lines."
  say ""

  if ! session_start; then
    write_report 1
    return 2
  fi
  if ! scan_for_watch; then
    warn ""
    warn "bcs_pair: the watch ($WATCH_MASKED) was not seen in ${SCAN_SECONDS}s. Nothing was paired."
    seen_devices_report
    warn ""
    warn "check: the watch is awake with its Bluetooth on and showing its pairing screen, the phone's"
    warn "Bluetooth is off, and the watch is within a metre or two. Then run this again."
    write_report 1
    return 1
  fi
  if ! pair_watch; then
    write_report 1
    return 1
  fi

  run_probe
  local status=$?
  write_report "$status"
  print_undo
  return "$status"
}

main "$@"
exit $?
