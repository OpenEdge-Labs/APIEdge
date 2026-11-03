// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { profileBody, statusClass } from "../src/tls";

test("profile form values become the API body; empty selections are null", () => {
  const f = { name: " backend ", description: "", min_version: "1.3", ciphers: " ", truststore_id: "4", keystore_id: "" };
  assert.deepEqual(profileBody(f), {
    name: "backend", description: "", min_version: "1.3", ciphers: null, truststore_id: 4, keystore_id: null,
  });
});

test("certificate status badges", () => {
  assert.equal(statusClass("valid"), "published");
  assert.equal(statusClass("expiring"), "deprecated");
  assert.equal(statusClass("expired"), "retired");
});
