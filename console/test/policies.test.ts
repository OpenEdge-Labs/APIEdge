// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { POLICY_TYPES, chainBody, formFromSpec, move, newPolicy, specFromForm, type PolicySpec } from "../src/policies";

test("every policy type has a usable default form", () => {
  for (const t of POLICY_TYPES) {
    const form = newPolicy(t.type);
    assert.equal(form.type, t.type);
    for (const f of t.fields) assert.ok(f.key in form.values, `${t.type}.${f.key}`);
  }
  // Defaults that need user input are reported, not sent.
  assert.ok(specFromForm(newPolicy("cors"), 0).errors.some((e) => e.includes("origin")));
  assert.ok(specFromForm(newPolicy("ip-filter"), 0).errors.length > 0);
  assert.ok(specFromForm(newPolicy("jwt"), 0).errors.some((e) => e.includes("public key")));
  assert.deepEqual(specFromForm(newPolicy("api-key"), 0).errors, []);
});

test("forms round-trip the API's JSON, including nested transform fields", () => {
  const spec: PolicySpec = {
    id: "abc123",
    type: "transform",
    name: "tidy",
    enabled: false,
    routes: ["/orders"],
    config: {
      request: {
        set_headers: { "x-consumer": "{consumer}" },
        remove_headers: ["x-debug"],
        set_json: { "meta.source": "gateway", n: 2 },
        remove_json: [],
        set_query: { v: "2" },
        remove_query: [],
      },
      response: { set_headers: {}, remove_headers: ["server"], set_json: {}, remove_json: ["secret"], max_body_bytes: 2048 },
    },
  };
  const form = formFromSpec(spec);
  assert.equal(form.values["request.set_headers"], "x-consumer: {consumer}");
  assert.equal(form.values["request.set_json"], 'meta.source = "gateway"\nn = 2');
  const back = specFromForm(form, 0);
  assert.deepEqual(back.errors, []);
  assert.equal(back.spec?.id, "abc123");
  assert.equal(back.spec?.enabled, false);
  assert.deepEqual(back.spec?.routes, ["/orders"]);
  const req = back.spec?.config.request as Record<string, unknown>;
  assert.deepEqual(req.set_headers, { "x-consumer": "{consumer}" });
  assert.deepEqual(req.set_json, { "meta.source": "gateway", n: 2 });
  assert.deepEqual(req.set_query, { v: "2" });
  const resp = back.spec?.config.response as Record<string, unknown>;
  assert.deepEqual(resp.remove_json, ["secret"]);
  assert.equal(resp.max_body_bytes, 2048);
});

test("invalid input is reported per policy", () => {
  const tf = newPolicy("transform");
  tf.values["request.set_headers"] = "missing-separator";
  tf.values["request.set_json"] = "a = not json";
  const rl = newPolicy("rate-limit");
  rl.values.limit = "ten";
  const cors = newPolicy("cors");
  cors.values.allow_origins = "*";
  cors.values.allow_credentials = true;
  const jwt = newPolicy("jwt");
  jwt.values.algorithms = ["HS256", "RS256"];
  jwt.values.secret = "short";
  const { body, errors } = chainBody([tf, rl, cors, jwt]);
  assert.equal(body, undefined);
  assert.ok(errors.some((e) => e.startsWith("Policy 1") && e.includes("name: value")));
  assert.ok(errors.some((e) => e.startsWith("Policy 1") && e.includes("JSON")));
  assert.ok(errors.some((e) => e.startsWith("Policy 2") && e.includes("whole number")));
  assert.ok(errors.some((e) => e.startsWith("Policy 3") && e.includes("credentials")));
  assert.ok(errors.some((e) => e.startsWith("Policy 4") && e.includes("mix")));
  assert.ok(errors.some((e) => e.startsWith("Policy 4") && e.includes("32 bytes")));
});

test("an empty secret means keep the stored one", () => {
  const jwt = newPolicy("jwt");
  jwt.values.algorithms = ["HS256"];
  const r = specFromForm(jwt, 0);
  assert.deepEqual(r.errors, []);
  assert.equal(r.spec?.config.secret, null);
  // The server never returns secrets, so the form starts empty.
  assert.equal(formFromSpec({ ...r.spec!, config: { ...r.spec!.config, secret: "x".repeat(40) } }).values.secret, "");
});

test("policies can be reordered", () => {
  assert.deepEqual(move([1, 2, 3], 0, 1), [2, 1, 3]);
  assert.deepEqual(move([1, 2, 3], 2, 1), [1, 3, 2]);
  assert.deepEqual(move([1, 2, 3], 0, -1), [1, 2, 3]);
});

test("the basic-ldap policy needs a directory and round-trips", () => {
  assert.ok(specFromForm(newPolicy("basic-ldap"), 0).errors.some((e) => e.includes("directory")));
  const spec: PolicySpec = {
    id: "l1",
    type: "basic-ldap",
    name: "",
    enabled: true,
    routes: [],
    config: { directory_id: 4, realm: "Orders", cache_seconds: 0, hide_credentials: false },
  };
  const out = specFromForm(formFromSpec(spec), 0);
  assert.deepEqual(out.errors, []);
  assert.equal(out.spec?.config.directory_id, 4);
  assert.equal(out.spec?.config.cache_seconds, 0);
  assert.equal(out.spec?.config.hide_credentials, false);
});

test("the mtls policy needs a truststore and round-trips its allow-lists", () => {
  assert.ok(specFromForm(newPolicy("mtls"), 0).errors.some((e) => e.includes("truststore")));
  const spec: PolicySpec = {
    id: "m1",
    type: "mtls",
    name: "",
    enabled: true,
    routes: [],
    config: { truststore_id: 3, allowed_subjects: ["billing-svc"], allowed_fingerprints: [], consumer_from: "subject" },
  };
  const out = specFromForm(formFromSpec(spec), 0);
  assert.deepEqual(out.errors, []);
  assert.equal(out.spec?.config.truststore_id, 3);
  assert.deepEqual(out.spec?.config.allowed_subjects, ["billing-svc"]);
  assert.equal(out.spec?.config.consumer_from, "subject");
});
