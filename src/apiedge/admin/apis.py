# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""APIs inside products: ``/api/v1/tenants/{tenant_id}/products/{product_id}/apis`` (T-006).

| Route | Permission (tenant-wide or scoped to the product) |
|---|---|
| ``GET .../apis`` | ``api:read`` |
| ``POST .../apis`` | ``api:create`` |
| ``GET .../apis/{api_id}`` | ``api:read`` |
| ``PATCH .../apis/{api_id}`` | ``api:update`` |
| ``POST .../apis/{api_id}/lifecycle`` | ``api:publish`` |
| ``DELETE .../apis/{api_id}`` | ``api:delete`` |

A product the caller cannot read APIs of answers 404 (no existence disclosure), and so does an
API id that does not belong to the product in the path. Every query runs on a tenant-bound
session (``apiedge.db.tenancy``).

An API carries its upstreams and routes; the form editor sends them whole and ``PATCH``
replaces the lists. Every upstream URL must pass the SSRF guard (``apiedge.security.ssrf``)
under the configured policy. Lifecycle as for products; publishing needs at least one upstream
and one route. Retired APIs, and every API of a retired product, are read-only. Only draft and
retired APIs can be deleted. The APIs of a retired product can still be deprecated and retired, so
that the product can be emptied and deleted.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from apiedge.admin.deps import TenantCaller, deny, not_found, require_any
from apiedge.admin.products import DELETABLE, TRANSITIONS
from apiedge.admin.schemas import (
    ApiIn,
    ApiOut,
    ApiPatch,
    LifecycleIn,
    RouteIn,
    RouteOut,
    UpstreamIn,
    UpstreamOut,
)
from apiedge.config import Settings
from apiedge.db.models import Api, ApiRoute, ApiUpstream, Product
from apiedge.security.audit import audit
from apiedge.security.ssrf import SsrfError, check_url

router = APIRouter(prefix="/tenants/{tenant_id}/products/{product_id}/apis", tags=["apis"])

SSRF_HINT = (
    "the URL is not allowed: use http or https without credentials, and a host that resolves "
    "to a public address (private, loopback, link-local and cloud metadata addresses are blocked "
    "unless an administrator allows them)"
)


def _out(a: Api, tenant_slug: str) -> ApiOut:
    return ApiOut(
        id=a.id,
        tenant_id=a.tenant_id,
        product_id=a.product_id,
        name=a.name,
        version=a.version,
        base_path=a.base_path,
        gateway_path=f"/{tenant_slug}{a.base_path}",
        description=a.description,
        timeout_ms=a.timeout_ms,
        lifecycle=a.lifecycle,
        upstreams=[UpstreamOut(url=u.url, weight=u.weight) for u in a.upstreams],
        routes=[
            RouteOut(methods=r.methods.split(","), path=r.path, description=r.description)
            for r in a.routes
        ],
        created_at=a.created_at,
        updated_at=a.updated_at,
    )


def _product(caller: TenantCaller, product_id: int, permission: str) -> Product:
    """Load a product of the caller's tenant and check ``permission`` for its APIs."""
    product = caller.session.get(Product, product_id)
    tid = caller.tenant_id
    if (
        product is None
        or product.tenant_id != tid
        or not caller.principal.has("api:read", tid, product.id)
    ):
        raise not_found("Product not found")
    if not caller.principal.has(permission, tid, product.id):
        raise deny(caller, permission, tid)
    return product


def _api(caller: TenantCaller, product: Product, api_id: int) -> Api:
    api = caller.session.get(Api, api_id)
    if api is None or api.tenant_id != caller.tenant_id or api.product_id != product.id:
        raise not_found("API not found")
    return api


def _writable(product: Product, api: Api | None = None) -> None:
    if product.lifecycle == "retired":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="the product is retired (read-only)")
    if api is not None and api.lifecycle == "retired":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="retired APIs are read-only")


def _upstreams(
    request: Request, caller: TenantCaller, items: list[UpstreamIn]
) -> list[ApiUpstream]:
    settings: Settings = request.app.state.settings
    policy = settings.ssrf_policy()
    errors: list[str] = []
    for i, item in enumerate(items, start=1):
        try:
            check_url(item.url, policy)
        except SsrfError:
            errors.append(f"upstream {i}: {SSRF_HINT}")
    if errors:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"upstreams": errors})
    return [
        ApiUpstream(tenant_id=caller.tenant_id, position=i, url=item.url, weight=item.weight)
        for i, item in enumerate(items)
    ]


def _routes(caller: TenantCaller, items: list[RouteIn]) -> list[ApiRoute]:
    return [
        ApiRoute(
            tenant_id=caller.tenant_id,
            position=i,
            methods=",".join(item.methods),
            path=item.path,
            description=item.description,
        )
        for i, item in enumerate(items)
    ]


def _check_unique(caller: TenantCaller, api: Api) -> None:
    """Friendly 409s before the unique constraints would fire."""
    same_path = select(Api.id).where(
        Api.tenant_id == caller.tenant_id, Api.base_path == api.base_path
    )
    same_name = select(Api.id).where(
        Api.product_id == api.product_id, Api.name == api.name, Api.version == api.version
    )
    if api.id is not None:
        same_path = same_path.where(Api.id != api.id)
        same_name = same_name.where(Api.id != api.id)
    # The base path is unique in the whole tenant, including products the caller cannot see;
    # the message names no other API.
    with caller.session.no_autoflush:
        path_taken = caller.session.scalar(same_path.limit(1)) is not None
        name_taken = caller.session.scalar(same_name.limit(1)) is not None
    if path_taken:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="base path already in use")
    if name_taken:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="an API with this name and version already exists"
        )


def _flush(caller: TenantCaller) -> None:
    try:
        caller.session.flush()
    except IntegrityError as exc:
        caller.session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="base path or name and version already in use"
        ) from exc


def _audit(caller: TenantCaller, action: str, api: Api, **details: object) -> None:
    audit(
        caller.session,
        action,
        tenant_id=caller.tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="api",
        resource_id=api.id,
        client_ip=caller.ip,
        details={
            "product_id": api.product_id,
            "name": api.name,
            "version": api.version,
            "base_path": api.base_path,
            **details,
        },
    )


@router.get("", response_model=list[ApiOut], summary="List the APIs of a product")
def list_apis(
    product_id: int, caller: Annotated[TenantCaller, Depends(require_any("api:read"))]
) -> list[ApiOut]:
    product = _product(caller, product_id, "api:read")
    stmt = (
        select(Api)
        .where(Api.tenant_id == caller.tenant_id, Api.product_id == product.id)
        .order_by(Api.name, Api.version)
    )
    return [_out(a, caller.tenant.slug) for a in caller.session.scalars(stmt)]


@router.post("", response_model=ApiOut, status_code=201, summary="Create an API in a product")
def create_api(
    product_id: int,
    body: ApiIn,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require_any("api:create"))],
) -> ApiOut:
    product = _product(caller, product_id, "api:create")
    _writable(product)
    api = Api(
        tenant_id=caller.tenant_id,
        product_id=product.id,
        name=body.name,
        version=body.version,
        base_path=body.base_path,
        description=body.description,
        timeout_ms=body.timeout_ms,
        lifecycle="draft",
    )
    _check_unique(caller, api)
    api.upstreams = _upstreams(request, caller, body.upstreams)
    api.routes = _routes(caller, body.routes)
    caller.session.add(api)
    _flush(caller)
    _audit(caller, "api.create", api, upstreams=len(body.upstreams), routes=len(body.routes))
    caller.session.commit()
    caller.session.refresh(api)
    return _out(api, caller.tenant.slug)


@router.get("/{api_id}", response_model=ApiOut, summary="Get an API")
def get_api(
    product_id: int,
    api_id: int,
    caller: Annotated[TenantCaller, Depends(require_any("api:read"))],
) -> ApiOut:
    api = _api(caller, _product(caller, product_id, "api:read"), api_id)
    return _out(api, caller.tenant.slug)


@router.patch("/{api_id}", response_model=ApiOut, summary="Update an API, its upstreams and routes")
def update_api(
    product_id: int,
    api_id: int,
    body: ApiPatch,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require_any("api:update"))],
) -> ApiOut:
    product = _product(caller, product_id, "api:update")
    api = _api(caller, product, api_id)
    _writable(product, api)
    if api.lifecycle != "draft" and body.base_path not in (None, api.base_path):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="the base path can only change while the API is a draft",
        )
    for field in ("name", "version", "base_path", "description", "timeout_ms"):
        value = getattr(body, field)
        if value is not None:
            setattr(api, field, value)
    _check_unique(caller, api)
    if body.upstreams is not None:
        if not body.upstreams and api.lifecycle != "draft":
            raise HTTPException(
                status.HTTP_409_CONFLICT, detail="a published API needs at least one upstream"
            )
        api.upstreams = _upstreams(request, caller, body.upstreams)
    if body.routes is not None:
        if not body.routes and api.lifecycle != "draft":
            raise HTTPException(
                status.HTTP_409_CONFLICT, detail="a published API needs at least one route"
            )
        api.routes = _routes(caller, body.routes)
    _flush(caller)
    changed = sorted(body.model_dump(exclude_unset=True, exclude_none=True))
    _audit(caller, "api.update", api, changed=changed)
    caller.session.commit()
    caller.session.refresh(api)
    return _out(api, caller.tenant.slug)


@router.post("/{api_id}/lifecycle", response_model=ApiOut, summary="Change an API's lifecycle")
def change_api_lifecycle(
    product_id: int,
    api_id: int,
    body: LifecycleIn,
    caller: Annotated[TenantCaller, Depends(require_any("api:publish"))],
) -> ApiOut:
    product = _product(caller, product_id, "api:publish")
    api = _api(caller, product, api_id)
    if product.lifecycle == "retired" and body.lifecycle not in ("deprecated", "retired"):
        # A retired product is read-only, but its APIs can still be wound down.
        raise HTTPException(status.HTTP_409_CONFLICT, detail="the product is retired (read-only)")
    before = api.lifecycle
    if body.lifecycle not in TRANSITIONS[before]:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"cannot change lifecycle from {before} to {body.lifecycle}",
        )
    if body.lifecycle == "published" and (not api.upstreams or not api.routes):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="an API needs at least one upstream and one route to be published",
        )
    api.lifecycle = body.lifecycle
    _audit(caller, "api.lifecycle", api, before=before, after=body.lifecycle)
    caller.session.commit()
    caller.session.refresh(api)
    return _out(api, caller.tenant.slug)


@router.delete("/{api_id}", status_code=204, summary="Delete a draft or retired API")
def delete_api(
    product_id: int,
    api_id: int,
    caller: Annotated[TenantCaller, Depends(require_any("api:delete"))],
) -> Response:
    product = _product(caller, product_id, "api:delete")
    api = _api(caller, product, api_id)
    if api.lifecycle not in DELETABLE:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="only draft or retired APIs can be deleted"
        )
    _audit(caller, "api.delete", api)
    caller.session.delete(api)
    caller.session.commit()
    return Response(status_code=204)
