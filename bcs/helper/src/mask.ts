// BCS helper: address masking, so no log line or test output can carry a full Bluetooth address.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// The address is not a secret, but it must not be committed or printed in full. Masking keeps
// the last two octets (XX:XX:XX:XX:AA:BB) so two runs can be compared without revealing the
// device. maskMacText() is the safety net for arbitrary text: every logger in this helper
// sends its message through it, so a mistake elsewhere still cannot leak an address.

/** What a masked address looks like. Six octets, first four hidden. */
export const MASKED_ADDRESS = "XX:XX:XX:XX:XX:XX";

const HEX_OCTET = /^[0-9A-Fa-f]{2}$/;
const MAC_IN_TEXT = /(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])/g;

/** True when the value parses as a six-octet colon-separated Bluetooth address. */
export function isAddress(value: unknown): value is string {
  const parts = String(value ?? "").trim().split(":");
  return parts.length === 6 && parts.every((part) => HEX_OCTET.test(part));
}

/**
 * Mask an address, keeping only its last two octets. Anything that is not a valid address
 * becomes the fully masked placeholder rather than being echoed back.
 */
export function maskAddress(address: unknown): string {
  if (!isAddress(address)) return MASKED_ADDRESS;
  const parts = String(address).trim().split(":");
  return `XX:XX:XX:XX:${parts[4].toUpperCase()}:${parts[5].toUpperCase()}`;
}

/**
 * Mask every Bluetooth address inside a longer string. Idempotent: an already masked address
 * contains `XX`, which is not a hex octet, so it is left exactly as it is.
 */
export function maskMacText(text: unknown): string {
  return String(text ?? "").replace(MAC_IN_TEXT, (match) => maskAddress(match));
}