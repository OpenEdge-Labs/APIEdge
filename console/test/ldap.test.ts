// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { createBody, directoryProblems, emptyDirectoryForm, formFromDirectory, updateBody, type Directory } from "../src/ldap";

const stored: Directory = {
  id: 7,
  name: "corp",
  description: "",
  host: "ldap.example.com",
  port: 636,
  security: "ldaps",
  truststore_id: 3,
  timeout_seconds: 5,
  bind_dn: "cn=svc,dc=x",
  bind_password_set: true,
  user_base_dn: "dc=x",
  user_filter: "(uid={username})",
  user_dn_template: "",
  username_attribute: "uid",
  email_attribute: "mail",
  name_attribute: "cn",
  apis: [],
};

test("a new directory needs a search base or a template", () => {
  assert.ok(directoryProblems(emptyDirectoryForm, null).some((p) => p.includes("base DN")));
  const ok = { ...emptyDirectoryForm, user_base_dn: "dc=x" };
  assert.deepEqual(directoryProblems(ok, null), []);
  assert.deepEqual(directoryProblems({ ...emptyDirectoryForm, user_dn_template: "uid={username},dc=x" }, null), []);
  assert.ok(directoryProblems({ ...emptyDirectoryForm, user_dn_template: "uid=fixed" }, null).some((p) => p.includes("template")));
});

test("the filter must contain the user name and the port must be valid", () => {
  const f = { ...emptyDirectoryForm, user_base_dn: "dc=x" };
  assert.ok(directoryProblems({ ...f, user_filter: "(uid=fixed)" }, null).some((p) => p.includes("{username}")));
  assert.ok(directoryProblems({ ...f, port: "70000" }, null).some((p) => p.includes("port")));
});

test("the service account needs both a DN and a password", () => {
  const f = { ...emptyDirectoryForm, user_base_dn: "dc=x" };
  assert.ok(directoryProblems({ ...f, bind_dn: "cn=a" }, null).some((p) => p.includes("password")));
  assert.ok(directoryProblems({ ...f, bind_password: "p" }, null).some((p) => p.includes("bind DN")));
});

test("an edit keeps the stored password unless the server changes", () => {
  const f = formFromDirectory(stored);
  assert.equal(f.bind_password, "");
  assert.deepEqual(directoryProblems(f, stored), []);
  assert.deepEqual(directoryProblems({ ...f, user_base_dn: "dc=y" }, stored), []);
  for (const moved of [{ host: "evil.example.com" }, { port: "1636" }, { security: "plain" as const }, { truststore_id: "" }]) {
    assert.ok(directoryProblems({ ...f, ...moved }, stored).some((p) => p.includes("again")), JSON.stringify(moved));
    assert.deepEqual(directoryProblems({ ...f, ...moved, bind_password: "new" }, stored), []);
  }
});

test("request bodies", () => {
  const f = { ...formFromDirectory(stored), host: " h.example.com " };
  assert.equal(createBody(f).host, "h.example.com");
  assert.equal(createBody(f).name, "corp");
  assert.equal("bind_password" in updateBody(f), false);
  assert.equal("name" in updateBody(f), false);
  assert.equal(updateBody({ ...f, bind_password: "p" }).bind_password, "p");
  assert.equal(updateBody({ ...f, truststore_id: "" }).truststore_id, null);
});
