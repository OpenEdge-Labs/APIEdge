# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""``/api/v1/auth``: login, token refresh, logout, profile, password change and TOTP MFA.

Permission: none beyond being authenticated - these routes act on the caller's own account.
"""

from __future__ import annotations

from datetime import timedelta
from functools import cache
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select

from apiedge.admin.deps import (
    DB,
    REFRESH_COOKIE,
    SESSION_COOKIE,
    Caller,
    authenticated,
    client_ip,
    get_settings_dep,
    unauthorized,
)
from apiedge.admin.schemas import (
    ChangePasswordIn,
    LoginIn,
    MeOut,
    MfaCodeIn,
    MfaDisableIn,
    MfaSetupOut,
    ProductPermissions,
    TokenOut,
)
from apiedge.config import Settings
from apiedge.db.models import Tenant, User, utcnow
from apiedge.security import auth
from apiedge.security.audit import audit
from apiedge.security.crypto import CryptoError, SecretBox
from apiedge.security.passwords import hash_password, password_problems, verify_password
from apiedge.security.rbac import PERMISSIONS

router = APIRouter(prefix="/auth", tags=["auth"])
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
CallerDep = Annotated[Caller, Depends(authenticated)]


@cache
def _dummy_hash() -> str:
    """Verified against when the user does not exist, so timing does not reveal usernames."""
    return hash_password("apiedge-timing-equaliser")


def _secure(request: Request, settings: Settings) -> bool:
    return settings.cookie_secure or request.url.scheme == "https"


def _set_session_cookies(
    response: Response, request: Request, settings: Settings, access: str, refresh: str | None
) -> None:
    secure = _secure(request, settings)
    response.set_cookie(
        SESSION_COOKIE,
        access,
        max_age=settings.access_token_ttl_seconds,
        path="/api",
        httponly=True,
        secure=secure,
        samesite="strict",
    )
    if refresh is not None:
        response.set_cookie(
            REFRESH_COOKIE,
            refresh,
            max_age=settings.refresh_token_ttl_hours * 3600,
            path="/api/v1/auth",
            httponly=True,
            secure=secure,
            samesite="strict",
        )


def _clear_session_cookies(response: Response, request: Request, settings: Settings) -> None:
    secure = _secure(request, settings)
    response.delete_cookie(SESSION_COOKIE, path="/api", httponly=True, secure=secure)
    response.delete_cookie(REFRESH_COOKIE, path="/api/v1/auth", httponly=True, secure=secure)


def _token_out(request: Request, user: User) -> TokenOut:
    signer: auth.TokenSigner = request.app.state.token_signer
    return TokenOut(
        access_token=signer.issue(user),
        expires_in=signer.ttl_seconds,
        must_change_password=user.must_change_password,
    )


def _secret_box(request: Request) -> SecretBox:
    box: SecretBox | None = request.app.state.secret_box
    if box is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MFA needs the secrets master key (see APIEDGE_SECRET_KEY)",
        )
    return box


def _mfa_aad(user: User) -> str:
    return f"user:{user.id}:mfa"


def _check_login_totp(request: Request, user: User, code: str) -> int | None:
    """The matched TOTP step, or None (also when the stored secret cannot be decrypted)."""
    if not user.mfa_secret_enc:
        return None
    try:
        secret = _secret_box(request).decrypt_str(user.mfa_secret_enc, _mfa_aad(user))
    except CryptoError:
        return None
    return auth.verify_totp(secret, code, user.mfa_last_step)


@router.post("/login", response_model=TokenOut, summary="Sign in (password and TOTP code)")
def login(
    body: LoginIn, request: Request, response: Response, session: DB, settings: SettingsDep
) -> TokenOut:
    ip = client_ip(request)
    throttle: auth.LoginThrottle = request.app.state.login_throttle
    if not throttle.hit(ip or "unknown"):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too_many_attempts",
            headers={"Retry-After": "60"},
        )

    user = session.scalar(select(User).where(User.username == body.username))

    def fail(code: str, reason: str, tenant_id: int | None = None) -> HTTPException:
        audit(
            session,
            "auth.login",
            tenant_id=tenant_id,
            actor_id=user.id if user else None,
            actor_username=body.username[:150],
            outcome="failure",
            client_ip=ip,
            details={"reason": reason},
        )
        session.commit()
        return unauthorized(code)

    if user is None:
        verify_password(_dummy_hash(), body.password)
        raise fail("invalid_credentials", "unknown_user")
    password_ok = verify_password(user.password_hash, body.password)
    if auth.is_locked(user):
        raise fail("account_locked" if password_ok else "invalid_credentials", "locked")
    if not password_ok:
        locked = auth.record_failure(
            user, settings.login_max_failures, settings.login_lockout_minutes
        )
        if locked:
            audit(
                session,
                "auth.lockout",
                tenant_id=user.tenant_id,
                actor_id=user.id,
                actor_username=user.username,
                resource_type="user",
                resource_id=user.id,
                client_ip=ip,
            )
        raise fail("invalid_credentials", "bad_password", user.tenant_id)
    tenant = session.get(Tenant, user.tenant_id) if user.tenant_id is not None else None
    if (
        not user.is_active
        or (user.tenant_id is not None and (tenant is None or not tenant.is_active))
        or (user.tenant_id is None and not user.is_superadmin)
    ):
        raise fail("invalid_credentials", "inactive", user.tenant_id)
    if user.mfa_enabled:
        if body.totp_code is None:
            raise unauthorized("mfa_required")  # password was right; no failure counted
        step = _check_login_totp(request, user, body.totp_code)
        if step is None:
            auth.record_failure(user, settings.login_max_failures, settings.login_lockout_minutes)
            raise fail("invalid_mfa_code", "bad_mfa_code", user.tenant_id)
        user.mfa_last_step = step

    auth.record_success(user)
    refresh = auth.issue_refresh(
        session, user, expires_at=utcnow() + timedelta(hours=settings.refresh_token_ttl_hours)
    )
    audit(
        session,
        "auth.login",
        tenant_id=user.tenant_id,
        actor_id=user.id,
        actor_username=user.username,
        client_ip=ip,
    )
    session.commit()
    out = _token_out(request, user)
    _set_session_cookies(response, request, settings, out.access_token, refresh)
    return out


@router.post("/refresh", response_model=TokenOut, summary="Rotate the refresh cookie")
def refresh(request: Request, response: Response, session: DB, settings: SettingsDep) -> TokenOut:
    raw = request.cookies.get(REFRESH_COOKIE)
    if not raw:
        raise unauthorized()
    try:
        user, new_raw = auth.rotate_refresh(session, raw)
    except auth.AuthError as exc:
        if exc.code == "token_reused":
            audit(
                session,
                "auth.refresh_reuse",
                tenant_id=None,
                outcome="failure",
                client_ip=client_ip(request),
            )
        session.commit()  # keep the family revocation
        raise unauthorized("invalid_token") from exc
    if user.tenant_id is not None:
        tenant = session.get(Tenant, user.tenant_id)
        if tenant is None or not tenant.is_active:
            session.rollback()
            raise unauthorized("invalid_token")
    session.commit()
    out = _token_out(request, user)
    _set_session_cookies(response, request, settings, out.access_token, new_raw)
    return out


@router.post("/logout", status_code=204, summary="Sign out (revokes the refresh token family)")
def logout(request: Request, session: DB, settings: SettingsDep) -> Response:
    raw = request.cookies.get(REFRESH_COOKIE)
    if raw:
        auth.revoke_refresh(session, raw)
        session.commit()
    response = Response(status_code=204)
    _clear_session_cookies(response, request, settings)
    return response


@router.get("/me", response_model=MeOut, summary="The signed-in user and their permissions")
def me(caller: CallerDep) -> MeOut:
    user, p = caller.user, caller.principal
    perms = p.tenant_permissions(user.tenant_id) if user.tenant_id is not None else None
    if p.is_superadmin:
        perms = frozenset(PERMISSIONS)
    by_product: dict[int, set[str]] = {}
    for g in p.grants:
        if g.product_id is not None:
            by_product.setdefault(g.product_id, set()).update(g.permissions)
    return MeOut(
        id=user.id,
        username=user.username,
        email=user.email,
        tenant_id=user.tenant_id,
        is_superadmin=user.is_superadmin,
        must_change_password=user.must_change_password,
        mfa_enabled=user.mfa_enabled,
        permissions=sorted(perms or ()),
        product_permissions=[
            ProductPermissions(product_id=k, permissions=sorted(v))
            for k, v in sorted(by_product.items())
        ],
    )


@router.post("/change-password", response_model=TokenOut, summary="Change own password")
def change_password(
    body: ChangePasswordIn,
    request: Request,
    response: Response,
    caller: CallerDep,
    settings: SettingsDep,
) -> TokenOut:
    user, session = caller.user, caller.session
    if not verify_password(user.password_hash, body.current_password):
        audit(
            session,
            "user.password_change",
            tenant_id=user.tenant_id,
            actor_id=user.id,
            actor_username=user.username,
            outcome="failure",
            client_ip=caller.ip,
        )
        session.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="current password is incorrect")
    problems = password_problems(body.new_password, user.username)
    if body.new_password == body.current_password:
        problems.append("must differ from the current password")
    if problems:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"password": problems})
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.password_changed_at = utcnow()
    auth.invalidate_sessions(session, user)  # every other session ends
    refresh_raw = auth.issue_refresh(
        session, user, expires_at=utcnow() + timedelta(hours=settings.refresh_token_ttl_hours)
    )
    audit(
        session,
        "user.password_change",
        tenant_id=user.tenant_id,
        actor_id=user.id,
        actor_username=user.username,
        resource_type="user",
        resource_id=user.id,
        client_ip=caller.ip,
    )
    session.commit()
    out = _token_out(request, user)
    _set_session_cookies(response, request, settings, out.access_token, refresh_raw)
    return out


def _require_no_pending_change(caller: Caller) -> None:
    if caller.principal.must_change_password:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="password_change_required")


@router.post("/mfa/setup", response_model=MfaSetupOut, summary="Start TOTP enrolment")
def mfa_setup(request: Request, caller: CallerDep) -> MfaSetupOut:
    _require_no_pending_change(caller)
    user = caller.user
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="MFA is already enabled")
    secret = auth.new_totp_secret()
    user.mfa_secret_enc = _secret_box(request).encrypt(secret, _mfa_aad(user))
    caller.session.commit()
    return MfaSetupOut(secret=secret, otpauth_uri=auth.totp_uri(secret, user.username))


@router.post("/mfa/enable", status_code=204, summary="Confirm TOTP enrolment with a code")
def mfa_enable(body: MfaCodeIn, request: Request, caller: CallerDep) -> Response:
    _require_no_pending_change(caller)
    user, session = caller.user, caller.session
    if user.mfa_enabled or not user.mfa_secret_enc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="start MFA setup first")
    secret = _secret_box(request).decrypt_str(user.mfa_secret_enc, _mfa_aad(user))
    step = auth.verify_totp(secret, body.code, user.mfa_last_step)
    if step is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid_mfa_code")
    user.mfa_enabled = True
    user.mfa_last_step = step
    audit(
        session,
        "user.mfa_enable",
        tenant_id=user.tenant_id,
        actor_id=user.id,
        actor_username=user.username,
        resource_type="user",
        resource_id=user.id,
        client_ip=caller.ip,
    )
    session.commit()
    return Response(status_code=204)


@router.post("/mfa/disable", status_code=204, summary="Turn TOTP off (password and code)")
def mfa_disable(body: MfaDisableIn, request: Request, caller: CallerDep) -> Response:
    _require_no_pending_change(caller)
    user, session = caller.user, caller.session
    if not user.mfa_enabled or not user.mfa_secret_enc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="MFA is not enabled")
    secret = _secret_box(request).decrypt_str(user.mfa_secret_enc, _mfa_aad(user))
    if not verify_password(user.password_hash, body.password) or (
        auth.verify_totp(secret, body.code, user.mfa_last_step) is None
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid password or code")
    user.mfa_enabled = False
    user.mfa_secret_enc = None
    user.mfa_last_step = None
    audit(
        session,
        "user.mfa_disable",
        tenant_id=user.tenant_id,
        actor_id=user.id,
        actor_username=user.username,
        resource_type="user",
        resource_id=user.id,
        client_ip=caller.ip,
    )
    session.commit()
    return Response(status_code=204)
