// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Helpers for the TLS & certificates page (T-023).

/** The create-profile request body from the form ("" = not set). */
export function profileBody(f: { name: string; description: string; min_version: string; ciphers: string; truststore_id: string; keystore_id: string }) {
  return {
    name: f.name.trim(),
    description: f.description,
    min_version: f.min_version,
    ciphers: f.ciphers.trim() || null,
    truststore_id: f.truststore_id ? Number(f.truststore_id) : null,
    keystore_id: f.keystore_id ? Number(f.keystore_id) : null,
  };
}

/** CSS class for a certificate status badge. */
export function statusClass(status: "valid" | "expiring" | "expired" | "not_yet_valid"): string {
  return status === "valid" ? "published" : status === "expiring" ? "deprecated" : "retired";
}

