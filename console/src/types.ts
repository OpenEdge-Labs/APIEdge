// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Shapes returned by the admin API (see docs/admin-guide/access-control.md).

export interface Me {
  id: number;
  username: string;
  email: string | null;
  tenant_id: number | null;
  is_superadmin: boolean;
  must_change_password: boolean;
  mfa_enabled: boolean;
  permissions: string[];
  product_permissions: { product_id: number; permissions: string[] }[];
}

export interface Tenant {
  id: number;
  slug: string;
  name: string;
  is_active: boolean;
  created_at: string;
}

export interface User {
  id: number;
  tenant_id: number | null;
  username: string;
  email: string | null;
  is_active: boolean;
  is_locked: boolean;
  mfa_enabled: boolean;
  must_change_password: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface Permission {
  name: string;
  description: string;
  platform_only: boolean;
}

export interface Role {
  id: number;
  tenant_id: number | null;
  name: string;
  description: string;
  is_builtin: boolean;
  permissions: string[];
}

export interface Assignment {
  id: number;
  tenant_id: number;
  user_id: number;
  role_id: number;
  role_name: string;
  product_id: number | null;
  created_at: string;
}

export type Lifecycle = "draft" | "published" | "deprecated" | "retired";

export interface Product {
  id: number;
  tenant_id: number;
  name: string;
  description: string;
  lifecycle: Lifecycle;
  owners: { user_id: number; username: string }[];
  created_at: string;
  updated_at: string;
}

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

export interface Upstream {
  url: string;
  weight: number;
}

export interface Route {
  methods: HttpMethod[];
  path: string;
  description: string;
}

export interface Api {
  id: number;
  tenant_id: number;
  product_id: number;
  name: string;
  version: string;
  base_path: string;
  gateway_path: string;
  description: string;
  timeout_ms: number;
  lifecycle: Lifecycle;
  upstreams: Upstream[];
  routes: Route[];
  created_at: string;
  updated_at: string;
}

export interface AuditEvent {
  id: number;
  tenant_id: number | null;
  actor_user_id: number | null;
  actor_username: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  outcome: string;
  client_ip: string | null;
  request_id: string | null;
  details: string | null;
  created_at: string;
}

export interface Setting {
  name: string;
  value: string;
  group: string;
}

export interface MfaSetup {
  secret: string;
  otpauth_uri: string;
}

// Analytics (T-013)
export interface AnalyticsStats {
  requests: number;
  errors: number;
  error_rate: number;
  latency_p50_ms: number | null;
  latency_p95_ms: number | null;
  latency_p99_ms: number | null;
}

export interface AnalyticsTotals extends AnalyticsStats {
  client_errors: number;
  server_errors: number;
  latency_avg_ms: number | null;
  latency_max_ms: number | null;
  bytes_in: number;
  bytes_out: number;
}

export interface AnalyticsPoint extends AnalyticsStats {
  t: number;
}

export interface AnalyticsSummary {
  start: string;
  end: string;
  step_seconds: number;
  totals: AnalyticsTotals;
  series: AnalyticsPoint[];
  status_codes: { status: number; requests: number }[];
  top_apis: (AnalyticsStats & { api_id: number; product_id: number; name: string | null })[];
  top_consumers: (AnalyticsStats & { consumer: string })[];
}
