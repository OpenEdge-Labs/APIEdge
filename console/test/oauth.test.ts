// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { clientBody, clientProblems, splitList, type ClientForm } from "../src/oauth";

const form: ClientForm = {
  name: " web ",
  description: "",
  client_type: "confidential",
  grant_types: ["authorization_code", "refresh_token"],
  redirect_uris: "https://a.example.com/cb\nhttps://a.example.com/cb",
  scopes: "openid, profile orders.read",
  audiences: "",
  access_token_ttl: "",
  refresh_token_ttl: "3600",
};

test("lists are split on whitespace and commas without duplicates", () => {
  assert.deepEqual(splitList(" a, b\nc  a "), ["a", "b", "c"]);
  assert.deepEqual(splitList(""), []);
});

test("client form values become the API body", () => {
  assert.deepEqual(clientBody(form), {
    name: "web",
    description: "",
    client_type: "confidential",
    grant_types: ["authorization_code", "refresh_token"],
    redirect_uris: ["https://a.example.com/cb"],
    scopes: ["openid", "profile", "orders.read"],
    audiences: [],
    access_token_ttl: 600,
    refresh_token_ttl: 3600,
  });
});

test("grant combinations the server refuses are flagged", () => {
  assert.deepEqual(clientProblems(form), []);
  assert.equal(clientProblems({ ...form, grant_types: [] }).length, 1);
  assert.equal(clientProblems({ ...form, redirect_uris: "" }).length, 1);
  assert.equal(clientProblems({ ...form, grant_types: ["refresh_token"], redirect_uris: "" }).length, 1);
  assert.equal(clientProblems({ ...form, client_type: "public", grant_types: ["client_credentials"] }).length, 1);
});
