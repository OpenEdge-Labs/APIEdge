# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Products: ``/api/v1/tenants/{tenant_id}/products`` (T-005).

| Route | Permission |
|---|---|
| ``GET /tenants/{tenant_id}/products`` | ``product:read`` (lists the products it covers) |
| ``POST /tenants/{tenant_id}/products`` | ``product:create`` (tenant-wide) |
| ``GET /tenants/{tenant_id}/products/{product_id}`` | ``product:read`` for the product |
| ``PATCH /tenants/{tenant_id}/products/{product_id}`` | ``product:update`` for the product |
| ``POST /tenants/{tenant_id}/products/{product_id}/lifecycle`` | ``product:publish`` for it |
| ``DELETE /tenants/{tenant_id}/products/{product_id}`` | ``product:delete`` for the product |

Permissions may come from a tenant-wide grant or from a grant scoped to the product. A product
the caller cannot read answers 404 (no existence disclosure); one they can read but not change
answers 403. Every query runs on a tenant-bound session (``apiedge.db.tenancy``).

Lifecycle: ``draft -> published -> deprecated -> retired`` (a deprecated product may be
published again, a draft may be retired directly, retired is final). Retired products are
read-only. Only draft and retired products without APIs can be deleted.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from apiedge.admin.deps import TenantCaller, deny, not_found, require, require_any
from apiedge.admin.schemas import (
    LifecycleIn,
    OwnerOut,
    ProductIn,
    ProductLifecycle,
    ProductOut,
    ProductPatch,
)
from apiedge.db.models import Api, Product, ProductOwnerLink, RoleAssignment, User
from apiedge.security.audit import audit

router = APIRouter(prefix="/tenants/{tenant_id}/products", tags=["products"])

TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"published", "retired"}),
    "published": frozenset({"deprecated"}),
    "deprecated": frozenset({"published", "retired"}),
    "retired": frozenset(),
}
DELETABLE = frozenset({"draft", "retired"})


def _out(p: Product) -> ProductOut:
    return ProductOut(
        id=p.id,
        tenant_id=p.tenant_id,
        name=p.name,
        description=p.description,
        lifecycle=p.lifecycle,
        owners=sorted(
            (OwnerOut(user_id=o.user_id, username=o.user.username) for o in p.owner_rows),
            key=lambda o: o.username,
        ),
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


def _get(caller: TenantCaller, product_id: int, permission: str) -> Product:
    """Load a product of the caller's tenant and check ``permission`` on it."""
    product = caller.session.get(Product, product_id)
    tid = caller.tenant_id
    if (
        product is None
        or product.tenant_id != tid
        or not caller.principal.has("product:read", tid, product.id)
    ):
        raise not_found("Product not found")
    if not caller.principal.has(permission, tid, product.id):
        raise deny(caller, permission, tid)
    return product


def _owner_rows(caller: TenantCaller, usernames: list[str]) -> list[ProductOwnerLink]:
    if not usernames:
        return []
    users = list(
        caller.session.scalars(
            select(User).where(User.username.in_(usernames), User.tenant_id == caller.tenant_id)
        )
    )
    missing = sorted(set(usernames) - {u.username for u in users})
    if missing:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail={"owners": [f"unknown user: {m}" for m in missing]}
        )
    return [ProductOwnerLink(tenant_id=caller.tenant_id, user_id=u.id) for u in users]


def _audit(caller: TenantCaller, action: str, product: Product, **details: object) -> None:
    audit(
        caller.session,
        action,
        tenant_id=caller.tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="product",
        resource_id=product.id,
        client_ip=caller.ip,
        details={"name": product.name, **details},
    )


def _flush(caller: TenantCaller) -> None:
    try:
        caller.session.flush()
    except IntegrityError as exc:
        caller.session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="product name already in use") from exc


@router.get("", response_model=list[ProductOut], summary="List products")
def list_products(
    caller: Annotated[TenantCaller, Depends(require_any("product:read"))],
    lifecycle: Annotated[ProductLifecycle | None, Query()] = None,
) -> list[ProductOut]:
    stmt = select(Product).where(Product.tenant_id == caller.tenant_id).order_by(Product.name)
    visible = caller.principal.product_ids_with("product:read", caller.tenant_id)
    if visible is not None:
        stmt = stmt.where(Product.id.in_(visible))
    if lifecycle is not None:
        stmt = stmt.where(Product.lifecycle == lifecycle)
    return [_out(p) for p in caller.session.scalars(stmt)]


@router.post("", response_model=ProductOut, status_code=201, summary="Create a product")
def create_product(
    body: ProductIn, caller: Annotated[TenantCaller, Depends(require("product:create"))]
) -> ProductOut:
    owners = body.owners
    if owners is None:
        owners = [caller.username] if caller.user.tenant_id == caller.tenant_id else []
    product = Product(
        tenant_id=caller.tenant_id,
        name=body.name,
        description=body.description,
        lifecycle="draft",
        owner_rows=_owner_rows(caller, owners),
    )
    caller.session.add(product)
    _flush(caller)
    _audit(caller, "product.create", product, owners=owners)
    caller.session.commit()
    caller.session.refresh(product)
    return _out(product)


@router.get("/{product_id}", response_model=ProductOut, summary="Get a product")
def get_product(
    product_id: int, caller: Annotated[TenantCaller, Depends(require_any("product:read"))]
) -> ProductOut:
    return _out(_get(caller, product_id, "product:read"))


@router.patch("/{product_id}", response_model=ProductOut, summary="Update a product")
def update_product(
    product_id: int,
    body: ProductPatch,
    caller: Annotated[TenantCaller, Depends(require_any("product:update"))],
) -> ProductOut:
    product = _get(caller, product_id, "product:update")
    if product.lifecycle == "retired":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="retired products are read-only")
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    if body.name is not None:
        product.name = body.name
    if body.description is not None:
        product.description = body.description
    if body.owners is not None:
        product.owner_rows = [
            ProductOwnerLink(tenant_id=r.tenant_id, product_id=product.id, user_id=r.user_id)
            for r in _owner_rows(caller, body.owners)
        ]
    _flush(caller)
    _audit(caller, "product.update", product, **changes)
    caller.session.commit()
    caller.session.refresh(product)
    return _out(product)


@router.post(
    "/{product_id}/lifecycle", response_model=ProductOut, summary="Change a product's lifecycle"
)
def change_lifecycle(
    product_id: int,
    body: LifecycleIn,
    caller: Annotated[TenantCaller, Depends(require_any("product:publish"))],
) -> ProductOut:
    product = _get(caller, product_id, "product:publish")
    before = product.lifecycle
    if body.lifecycle not in TRANSITIONS[before]:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"cannot change lifecycle from {before} to {body.lifecycle}",
        )
    product.lifecycle = body.lifecycle
    _audit(caller, "product.lifecycle", product, before=before, after=body.lifecycle)
    caller.session.commit()
    caller.session.refresh(product)
    return _out(product)


@router.delete("/{product_id}", status_code=204, summary="Delete a draft or retired product")
def delete_product(
    product_id: int, caller: Annotated[TenantCaller, Depends(require_any("product:delete"))]
) -> Response:
    product = _get(caller, product_id, "product:delete")
    if product.lifecycle not in DELETABLE:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="only draft or retired products can be deleted"
        )
    has_apis = caller.session.scalar(select(Api.id).where(Api.product_id == product.id).limit(1))
    if has_apis is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="the product still contains APIs; delete them first"
        )
    grants = list(
        caller.session.scalars(
            select(RoleAssignment).where(RoleAssignment.product_id == product.id)
        )
    )
    for g in grants:  # also removed by the foreign key; explicit so the audit can count them
        caller.session.delete(g)
    _audit(caller, "product.delete", product, revoked_grants=len(grants))
    caller.session.delete(product)
    caller.session.commit()
    return Response(status_code=204)
