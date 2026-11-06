// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Helpers for the LDAP directories page (T-023).

export type LdapSecurity = "ldaps" | "starttls" | "plain";

export interface Directory {
  id: number;
  name: string;
  description: string;
  host: string;
  port: number;
  security: LdapSecurity;
  truststore_id: number | null;
  timeout_seconds: number;
  bind_dn: string;
  bind_password_set: boolean;
  user_base_dn: string;
  user_filter: string;
  user_dn_template: string;
  username_attribute: string;
  email_attribute: string;
  name_attribute: string;
  apis: string[];
}

export interface DirectoryForm {
  name: string;
  description: string;
  host: string;
  port: string;
  security: LdapSecurity;
  truststore_id: string;
  timeout_seconds: string;
  bind_dn: string;
  bind_password: string;
  user_base_dn: string;
  user_filter: string;
  user_dn_template: string;
  username_attribute: string;
  email_attribute: string;
  name_attribute: string;
}

export const emptyDirectoryForm: DirectoryForm = {
  name: "",
  description: "",
  host: "",
  port: "636",
  security: "ldaps",
  truststore_id: "",
  timeout_seconds: "5",
  bind_dn: "",
  bind_password: "",
  user_base_dn: "",
  user_filter: "(uid={username})",
  user_dn_template: "",
  username_attribute: "uid",
  email_attribute: "mail",
  name_attribute: "cn",
};

/** The form for editing a directory; the stored password is never sent to the browser. */
export function formFromDirectory(d: Directory): DirectoryForm {
  return {
    name: d.name,
    description: d.description,
    host: d.host,
    port: String(d.port),
    security: d.security,
    truststore_id: d.truststore_id === null ? "" : String(d.truststore_id),
    timeout_seconds: String(d.timeout_seconds),
    bind_dn: d.bind_dn,
    bind_password: "",
    user_base_dn: d.user_base_dn,
    user_filter: d.user_filter,
    user_dn_template: d.user_dn_template,
    username_attribute: d.username_attribute,
    email_attribute: d.email_attribute,
    name_attribute: d.name_attribute,
  };
}

function fields(f: DirectoryForm) {
  return {
    description: f.description,
    host: f.host.trim(),
    port: Number(f.port),
    security: f.security,
    truststore_id: f.truststore_id ? Number(f.truststore_id) : null,
    timeout_seconds: Number(f.timeout_seconds),
    bind_dn: f.bind_dn.trim(),
    user_base_dn: f.user_base_dn.trim(),
    user_filter: f.user_filter.trim(),
    user_dn_template: f.user_dn_template.trim(),
    username_attribute: f.username_attribute.trim(),
    email_attribute: f.email_attribute.trim(),
    name_attribute: f.name_attribute.trim(),
  };
}

export function createBody(f: DirectoryForm) {
  return { name: f.name.trim(), ...fields(f), bind_password: f.bind_password };
}

/** A left-empty password keeps the stored one, so it is only sent when one was typed. */
export function updateBody(f: DirectoryForm) {
  return { ...fields(f), ...(f.bind_password ? { bind_password: f.bind_password } : {}) };
}

/** Problems the server would reject, shown before submitting (the server checks again). */
export function directoryProblems(f: DirectoryForm, editing: Directory | null): string[] {
  const out: string[] = [];
  const port = Number(f.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) out.push("The port must be between 1 and 65535.");
  if (!f.user_dn_template.trim() && !f.user_base_dn.trim()) out.push("Set a user base DN (to search for users) or a user DN template.");
  if (!f.user_filter.includes("{username}")) out.push("The user filter must contain {username}.");
  if (f.user_dn_template.trim() && !f.user_dn_template.includes("{username}")) out.push("The user DN template must contain {username}.");
  const hasPassword = Boolean(f.bind_password) || Boolean(editing?.bind_password_set);
  if (f.bind_dn.trim() && !hasPassword) out.push("A service account needs a password.");
  if (!f.bind_dn.trim() && f.bind_password) out.push("A password needs a service account bind DN.");
  if (editing?.bind_password_set && f.bind_dn.trim() && !f.bind_password) {
    const moved =
      f.host.trim() !== editing.host ||
      port !== editing.port ||
      f.security !== editing.security ||
      (f.truststore_id ? Number(f.truststore_id) : null) !== editing.truststore_id;
    if (moved) out.push("Enter the service account's password again: the host, port, security or truststore changed.");
  }
  return out;
}
