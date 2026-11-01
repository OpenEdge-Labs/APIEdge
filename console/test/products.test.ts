// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { TRANSITIONS, deletable, parseOwners } from "../src/products";

test("lifecycle moves match the server: retired is final", () => {
  assert.deepEqual(TRANSITIONS.draft, ["published", "retired"]);
  assert.deepEqual(TRANSITIONS.published, ["deprecated"]);
  assert.deepEqual(TRANSITIONS.retired, []);
  assert.equal(TRANSITIONS.published.includes("draft"), false);
});

test("only draft and retired products can be deleted", () => {
  assert.deepEqual(
    (["draft", "published", "deprecated", "retired"] as const).filter(deletable),
    ["draft", "retired"],
  );
});

test("owners are parsed into unique usernames", () => {
  assert.deepEqual(parseOwners(" alice, bob  alice,,carol "), ["alice", "bob", "carol"]);
  assert.deepEqual(parseOwners("   "), []);
});
