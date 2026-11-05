// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Helpers for the OAuth & OIDC page (T-023).

export type GrantType = "client_credentials" | "authorization_code" | "refresh_token";

export interface ClientForm {
  name: string;
  description: string;
  client_type: "confidential" | "public";
  grant_types: GrantType[];
  redirect_uris: string;
  scopes: string;
  audiences: string;
  access_token_ttl: string;
  refresh_token_ttl: string;
}

/** Split a whitespace- or comma-separated list, dropping empty entries and duplicates. */
export function splitList(text: string): string[] {
  return Array.from(new Set(text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)));
}

/** The create-client request body from the form. */
export function clientBody(f: ClientForm) {
  return {
    name: f.name.trim(),
    description: f.description,
    client_type: f.client_type,
    grant_types: f.grant_types,
    redirect_uris: splitList(f.redirect_uris),
    scopes: splitList(f.scopes),
    audiences: splitList(f.audiences),
    access_token_ttl: Number(f.access_token_ttl) || 600,
    refresh_token_ttl: Number(f.refresh_token_ttl) || 86400,
  };
}

/** Problems the server would reject, shown before submitting (the server checks again). */
export function clientProblems(f: ClientForm): string[] {
  const out: string[] = [];
  const grants = new Set(f.grant_types);
  if (grants.size === 0) out.push("Choose at least one grant type.");
  if (f.client_type === "public" && grants.has("client_credentials")) out.push("Public clients cannot use client credentials.");
  if (grants.has("refresh_token") && !grants.has("authorization_code")) out.push("Refresh tokens need the authorization code grant.");
  if (grants.has("authorization_code") && splitList(f.redirect_uris).length === 0) out.push("The authorization code grant needs a redirect URI.");
  return out;
}
