# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""ORM models.

Tenancy (T-003): every tenant-owned row carries ``tenant_id`` and uses :class:`TenantOwned`
(or :class:`TenantOrGlobal` for rows that may also be platform-wide, such as built-in roles).
Sessions bound to a tenant (``apiedge.db.tenancy``) filter those models automatically.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apiedge.db.base import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class TenantOwned:
    """Mixin marker: tenant-bound sessions see only rows with their ``tenant_id``.

    Rows with ``tenant_id`` NULL (platform users, platform audit events) are invisible to them.
    """


class TenantOrGlobal:
    """Mixin marker: tenant-bound sessions see their tenant's rows plus global rows
    (``tenant_id`` NULL, e.g. built-in roles), and may only write their own tenant's rows.
    """


class Tenant(Base):
    """An organization: the hard isolation boundary."""

    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(63), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class User(TenantOwned, Base):
    """A console user. ``tenant_id`` NULL means a platform user (only SuperAdmins)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=True
    )
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_superadmin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    # T-003: lockout, session invalidation and MFA.
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Bumped on password, role or status change: invalidates every access token issued before.
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # TOTP secret, encrypted with the secrets box (AAD binds it to the user id).
    mfa_secret_enc: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mfa_last_step: Mapped[int | None] = mapped_column(Integer, nullable=True)  # replay guard

    assignments: Mapped[list[RoleAssignment]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )


class Permission(Base):
    """Catalog of ``resource:action`` permissions (seeded by migrations)."""

    __tablename__ = "permissions"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(String(255), nullable=False, default="")


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission: Mapped[str] = mapped_column(
        ForeignKey("permissions.name", ondelete="CASCADE"), primary_key=True
    )


class Role(TenantOrGlobal, Base):
    """A named bundle of permissions. Built-in roles are global (``tenant_id`` NULL), read-only."""

    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_id_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    permission_rows: Mapped[list[RolePermission]] = relationship(
        cascade="all, delete-orphan", passive_deletes=True, lazy="selectin"
    )

    @property
    def permissions(self) -> list[str]:
        return sorted(p.permission for p in self.permission_rows)


class RoleAssignment(TenantOwned, Base):
    """Grants a role to a user in a tenant, or only for one product in it (``product_id``)."""

    __tablename__ = "role_assignments"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "role_id", "tenant_id", "product_id", name="uq_role_assignments_scope"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    # Product scope (T-005): deleting the product removes its product-scoped grants.
    product_id: Mapped[int | None] = mapped_column(
        ForeignKey("products.id", ondelete="CASCADE"), index=True, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    user: Mapped[User] = relationship(back_populates="assignments")
    role: Mapped[Role] = relationship(lazy="joined")


PRODUCT_LIFECYCLE = ("draft", "published", "deprecated", "retired")


class Product(TenantOwned, Base):
    """A bundle of APIs with owners and a lifecycle (T-005)."""

    __tablename__ = "products"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_products_tenant_id_name"),
        CheckConstraint(
            "lifecycle IN ('draft', 'published', 'deprecated', 'retired')", name="lifecycle"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    lifecycle: Mapped[str] = mapped_column(String(16), nullable=False, default="draft")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    owner_rows: Mapped[list[ProductOwnerLink]] = relationship(
        cascade="all, delete-orphan", passive_deletes=True, lazy="selectin"
    )


class ProductOwnerLink(TenantOwned, Base):
    """A user of the product's tenant who owns the product (informational, not a grant)."""

    __tablename__ = "product_owners"

    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True
    )

    user: Mapped[User] = relationship(lazy="joined")


class Api(TenantOwned, Base):
    """An API inside a product: base path, version, upstreams, routes and a lifecycle (T-006)."""

    __tablename__ = "apis"
    __table_args__ = (
        UniqueConstraint("tenant_id", "base_path", name="uq_apis_tenant_id_base_path"),
        UniqueConstraint("product_id", "name", "version", name="uq_apis_product_id_name_version"),
        CheckConstraint(
            "lifecycle IN ('draft', 'published', 'deprecated', 'retired')", name="lifecycle"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    # CASCADE only serves tenant deletion: the admin API refuses to delete a product with APIs.
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    base_path: Mapped[str] = mapped_column(String(255), nullable=False)
    timeout_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=30000)
    lifecycle: Mapped[str] = mapped_column(String(16), nullable=False, default="draft")
    # Ordered policy chain (T-008): JSON list of apiedge.policies.config.PolicySpec documents,
    # secret fields encrypted with the secrets box.
    policies: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    # TLS profile for HTTPS upstream connections (T-023); None: the gateway's default.
    tls_profile_id: Mapped[int | None] = mapped_column(
        ForeignKey("tls_profiles.id"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    upstreams: Mapped[list[ApiUpstream]] = relationship(
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        order_by="ApiUpstream.position",
    )
    routes: Mapped[list[ApiRoute]] = relationship(
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        order_by="ApiRoute.position",
    )


class ApiUpstream(TenantOwned, Base):
    """A backend target of an API. The URL passed the SSRF guard when it was saved."""

    __tablename__ = "api_upstreams"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    api_id: Mapped[int] = mapped_column(
        ForeignKey("apis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    weight: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class ApiRoute(TenantOwned, Base):
    """An operation of an API: HTTP methods plus a path relative to the API's base path."""

    __tablename__ = "api_routes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    api_id: Mapped[int] = mapped_column(
        ForeignKey("apis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    methods: Mapped[str] = mapped_column(String(64), nullable=False)  # "GET,POST"
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class ApiKey(TenantOwned, Base):
    """An API key for the APIs of one product (T-008). Only the SHA-256 of the key is stored.

    Keys are shown once when created and can be revoked; T-014 attaches them to consumers.
    """

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)  # shown to identify a key
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)  # user id (no FK)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RefreshToken(Base):
    """Opaque rotating refresh token (only its SHA-256 is stored). One family per login."""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    family_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AuditEvent(TenantOwned, Base):
    """Append-only audit log of privileged actions and authentication events."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # No foreign keys: audit entries outlive the tenants and users they mention.
    tenant_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    actor_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(150), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="success")
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)  # masked JSON
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False, default=utcnow
    )


class AnalyticsBucket(TenantOwned, Base):
    """Aggregated gateway traffic for one minute and one dimension combination (T-013).

    Rows are insert-only: every flush of a gateway process adds its own rows and queries sum
    them. ``product_id`` / ``api_id`` have no foreign keys so history outlives deleted APIs;
    the tenant foreign key removes a deleted tenant's analytics. ``h0``-``h12`` count requests
    per latency bucket (bounds in ``apiedge.analytics.metrics.LATENCY_BOUNDS_MS``).
    """

    __tablename__ = "analytics_buckets"
    __table_args__ = (Index("ix_analytics_buckets_tenant_time", "tenant_id", "bucket_start"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    bucket_start: Mapped[int] = mapped_column(BigInteger, index=True, nullable=False)  # epoch s
    product_id: Mapped[int] = mapped_column(Integer, nullable=False)
    api_id: Mapped[int] = mapped_column(Integer, nullable=False)
    route: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    consumer: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    requests: Mapped[int] = mapped_column(Integer, nullable=False)
    latency_sum_ms: Mapped[float] = mapped_column(Float, nullable=False)
    latency_max_ms: Mapped[float] = mapped_column(Float, nullable=False)
    bytes_in: Mapped[int] = mapped_column(BigInteger, nullable=False)
    bytes_out: Mapped[int] = mapped_column(BigInteger, nullable=False)
    h0: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h1: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h2: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h3: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h4: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h5: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h6: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h7: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h8: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h9: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h10: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h11: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    h12: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class CaptureSession(TenantOwned, Base):
    """An opt-in, time-boxed packet capture for one API (T-012, ADR 0010).

    ``route`` / ``consumer`` narrow it to one route path or one consumer label. The gateway keeps
    at most ``max_exchanges`` exchanges per session (oldest dropped first) and deletes them once
    the retention period after the session's end has passed.
    """

    __tablename__ = "capture_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id", ondelete="CASCADE"), index=True, nullable=False
    )
    api_id: Mapped[int] = mapped_column(
        ForeignKey("apis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    route: Mapped[str | None] = mapped_column(String(500), nullable=True)
    consumer: Mapped[str | None] = mapped_column(String(128), nullable=True)
    max_exchanges: Mapped[int] = mapped_column(Integer, nullable=False)
    max_body_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    mask_fields: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON list
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_name: Mapped[str | None] = mapped_column(String(150), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    captured: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class CapturedExchange(TenantOwned, Base):
    """One captured request/response (T-012).

    ``data`` is the full exchange as JSON, encrypted with the secrets box (the associated data
    binds it to its tenant and session). The other columns are the filterable summary; they
    hold no headers, query strings or bodies.
    """

    __tablename__ = "captured_exchanges"
    __table_args__ = (Index("ix_captured_exchanges_tenant_session", "tenant_id", "session_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    session_id: Mapped[int] = mapped_column(
        ForeignKey("capture_sessions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    product_id: Mapped[int] = mapped_column(Integer, nullable=False)
    api_id: Mapped[int] = mapped_column(Integer, nullable=False)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    route: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    status: Mapped[int] = mapped_column(Integer, nullable=False)
    consumer: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    duration_ms: Mapped[float] = mapped_column(Float, nullable=False)
    upstream: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    data: Mapped[str] = mapped_column(Text, nullable=False)


class Truststore(TenantOwned, Base):
    """A tenant's bundle of trusted CA certificates (T-023, ADR 0013).

    Used by the ``mtls`` policy to check client certificates. Certificates are public data and
    stored as normalised PEM.
    """

    __tablename__ = "truststores"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_truststores_tenant_id_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    certificates: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class Keystore(TenantOwned, Base):
    """A tenant's certificate chain and private key (T-023, ADR 0013).

    The private key is stored only encrypted with the secrets box (AES-256-GCM, bound to the
    tenant and keystore) and is never returned by the admin API.
    """

    __tablename__ = "keystores"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_keystores_tenant_id_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    certificate_chain: Mapped[str] = mapped_column(Text, nullable=False)
    private_key: Mapped[str] = mapped_column(Text, nullable=False)  # secrets-box token
    key_type: Mapped[str] = mapped_column(String(32), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class TlsProfile(TenantOwned, Base):
    """How the gateway connects to an API's HTTPS upstreams (T-023, ADR 0013).

    Lowest TLS version, optional TLS 1.2 cipher list, the truststore that verifies the upstream's
    certificate (default: the gateway's CA bundle) and an optional keystore presented as the
    client certificate (upstream mTLS). Certificate and host name verification are always on.
    """

    __tablename__ = "tls_profiles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_tls_profiles_tenant_id_name"),
        CheckConstraint("min_version IN ('1.2', '1.3')", name="min_version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    min_version: Mapped[str] = mapped_column(String(8), nullable=False, default="1.2")
    ciphers: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    truststore_id: Mapped[int | None] = mapped_column(ForeignKey("truststores.id"), nullable=True)
    keystore_id: Mapped[int | None] = mapped_column(ForeignKey("keystores.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


# --------------------------------------------------------------------------- LDAP


class LdapDirectory(TenantOwned, Base):
    """A tenant's LDAP or Active Directory server (T-023, ADR 0016).

    The service account's password is stored only encrypted with the secrets box and is never
    returned. ``truststore_id`` selects the CAs that verify the server (default: system store).
    """

    __tablename__ = "ldap_directories"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_ldap_directories_tenant_id_name"),
        CheckConstraint("security IN ('ldaps', 'starttls', 'plain')", name="security"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=636)
    security: Mapped[str] = mapped_column(String(16), nullable=False, default="ldaps")
    truststore_id: Mapped[int | None] = mapped_column(ForeignKey("truststores.id"), nullable=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    bind_dn: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    bind_password: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_base_dn: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    user_filter: Mapped[str] = mapped_column(
        String(1024), nullable=False, default="(uid={username})"
    )
    user_dn_template: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    username_attribute: Mapped[str] = mapped_column(String(128), nullable=False, default="uid")
    email_attribute: Mapped[str] = mapped_column(String(128), nullable=False, default="mail")
    name_attribute: Mapped[str] = mapped_column(String(128), nullable=False, default="cn")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


# --------------------------------------------------------------------------- OAuth 2.0 / OIDC


class OAuthSigningKey(TenantOwned, Base):
    """A tenant's token signing key (T-023, ADR 0015). The private key is stored only encrypted
    with the secrets box; retired keys stay in the JWKS until deleted, so tokens they signed
    keep validating until they expire."""

    __tablename__ = "oauth_signing_keys"
    __table_args__ = (CheckConstraint("status IN ('active', 'retired')", name="status"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    kid: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="RS256")
    private_key: Mapped[str] = mapped_column(Text, nullable=False)  # secrets-box token
    public_jwk: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OAuthClient(TenantOwned, Base):
    """An OAuth 2.0 client registered with a tenant's authorization server. Only the SHA-256
    of the client secret is stored (public clients have none and must use PKCE)."""

    __tablename__ = "oauth_clients"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_oauth_clients_tenant_id_name"),
        CheckConstraint("client_type IN ('confidential', 'public')", name="client_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    client_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    client_type: Mapped[str] = mapped_column(String(16), nullable=False)
    secret_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    secret_prefix: Mapped[str | None] = mapped_column(String(16), nullable=True)
    redirect_uris: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON
    grant_types: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON
    audiences: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON
    access_token_ttl: Mapped[int] = mapped_column(Integer, nullable=False, default=600)
    refresh_token_ttl: Mapped[int] = mapped_column(Integer, nullable=False, default=86400)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class OAuthCode(TenantOwned, Base):
    """A one-time authorization code (hash only), bound to client, redirect URI and PKCE."""

    __tablename__ = "oauth_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    client_pk: Mapped[int] = mapped_column(
        ForeignKey("oauth_clients.id", ondelete="CASCADE"), index=True, nullable=False
    )
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False, default="")
    code_challenge: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str | None] = mapped_column(String(255), nullable=True)
    family_id: Mapped[str] = mapped_column(String(32), nullable=False)
    auth_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OAuthRefreshToken(TenantOwned, Base):
    """A rotating refresh token (hash only). Presenting a used token revokes its family."""

    __tablename__ = "oauth_refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    client_pk: Mapped[int] = mapped_column(
        ForeignKey("oauth_clients.id", ondelete="CASCADE"), index=True, nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    family_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False, default="")
    auth_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class OAuthRevokedToken(TenantOwned, Base):
    """A revoked access token's ``jti``, kept until the token would have expired."""

    __tablename__ = "oauth_revoked_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    jti: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
