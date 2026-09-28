"""FastAPI application: redaction endpoint and versioned policy library."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Annotated, Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Path, status
from fastapi.responses import JSONResponse

from . import config, policy_store
from . import impact as impact_preview
from .redaction import redact
from .schemas import (
    NAME_PATTERN,
    ImpactRequest,
    ImpactResponse,
    PolicySnapshot,
    PolicyUpsert,
    RedactRequest,
    RedactResponse,
    RuleSpec,
    compile_specs,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure the volume-backed directory and schema exist before first request.
    path = config.get_policy_db_path()
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    policy_store.configure(path)
    yield


app = FastAPI(
    title="JSON Redaction API",
    version="2.0.0",
    description=(
        "Redact arbitrary JSON using JSON Pointer rules with * / ** globs. "
        "Rule sets can be supplied inline or referenced from an immutable, "
        "versioned policy library."
    ),
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _parse_if_match(header: Optional[str]) -> Optional[object]:
    """Translate an RFC 9110 If-Match header into a store precondition.

    ``None`` / missing -> create-only; ``*`` -> policy must exist; otherwise
    the (single) quoted entity-tag must equal the current version's ETag.
    """
    if header is None:
        return None
    value = header.strip()
    if value == "*":
        return policy_store.ANY
    # Tolerate one or a comma-separated list of entity tags; the request is
    # satisfied if the current ETag appears anywhere in the list.
    tags = {part.strip() for part in value.split(",") if part.strip()}
    if not tags:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="malformed If-Match header"
        )
    return tags


def _check_precondition(current_etag: str, if_match: Optional[object]) -> None:
    if if_match is None or if_match is policy_store.ANY:
        return
    if current_etag not in if_match:  # type: ignore[operator]
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail={
                "error": "etag_mismatch",
                "message": "If-Match ETag does not match the current version",
                "current_etag": current_etag,
            },
        )


def _snapshot_response(snapshot: Dict[str, Any], status_code: int) -> JSONResponse:
    """Serialize a policy snapshot, echoing its ETag as a header."""
    body = PolicySnapshot.model_validate(snapshot).model_dump(exclude_none=True)
    return JSONResponse(
        status_code=status_code, content=body, headers={"ETag": snapshot["etag"]}
    )


# --------------------------------------------------------------------------- #
# Ops
# --------------------------------------------------------------------------- #


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok"}


# --------------------------------------------------------------------------- #
# Policy library
# --------------------------------------------------------------------------- #

PolicyName = Annotated[str, Path(pattern=NAME_PATTERN)]
PolicyVersion = Annotated[int, Path(ge=1)]


@app.put(
    "/policies/{name}",
    tags=["policies"],
    response_model=PolicySnapshot,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "New immutable version appended to an existing policy."},
        201: {"description": "Policy created (version 1)."},
        412: {"description": "Missing or stale If-Match ETag."},
    },
)
def put_policy(
    body: PolicyUpsert,
    name: PolicyName,
    if_match: Annotated[
        Optional[str],
        Header(
            description=(
                "Current ETag required for updates. Omit entirely to create a "
                "new policy; use '*' to require existence without a specific ETag."
            )
        ),
    ] = None,
) -> JSONResponse:
    precondition = _parse_if_match(if_match)
    rules_payload = [spec.model_dump(exclude_none=True) for spec in body.rules]
    try:
        snapshot, created = policy_store.put_policy(name, rules_payload, precondition)
    except policy_store.PreconditionFailed as exc:
        # Look up the current state to tell the caller *why* it failed and
        # hand back the ETag to retry with.
        try:
            current = policy_store.get_current(name)
        except policy_store.PolicyNotFound:
            # Precondition (ETag / '*') against a policy that does not exist.
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail={"error": "policy_not_found", "message": str(exc)},
            )
        if precondition is not None and precondition is not policy_store.ANY:
            # A specific ETag was supplied but is stale.
            _check_precondition(current["etag"], precondition)
        # No ETag supplied on an existing policy.
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail={
                "error": "etag_required",
                "message": str(exc),
                "current_etag": current["etag"],
                "current_version": current["version"],
            },
        )
    return _snapshot_response(snapshot, status.HTTP_201_CREATED if created else status.HTTP_200_OK)


@app.get(
    "/policies/{name}",
    tags=["policies"],
    response_model=PolicySnapshot,
    summary="Fetch the current (latest) version of a policy.",
)
def get_current_policy(name: PolicyName) -> JSONResponse:
    try:
        snapshot = policy_store.get_current(name)
    except policy_store.PolicyNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy not found")
    return _snapshot_response(snapshot, status.HTTP_200_OK)


@app.get(
    "/policies/{name}/versions/{version}",
    tags=["policies"],
    response_model=PolicySnapshot,
    summary="Fetch an immutable historical snapshot of a policy.",
)
def get_policy_version(name: PolicyName, version: PolicyVersion) -> JSONResponse:
    try:
        snapshot = policy_store.get_version(name, version)
    except policy_store.PolicyNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"policy {name!r} version {version} not found",
        )
    return _snapshot_response(snapshot, status.HTTP_200_OK)


@app.post(
    "/policies/{name}/impact",
    tags=["policies"],
    response_model=ImpactResponse,
    summary="Preview the impact of a candidate rule change without creating a version.",
    responses={
        404: {"description": "No policy with this name exists."},
        422: {"description": "Invalid candidate rules, or samples outside the 1..20 range."},
    },
)
def policy_impact(name: PolicyName, body: ImpactRequest) -> JSONResponse:
    # One atomic read of the newest committed version; this endpoint is purely
    # a read and never writes a new version.
    try:
        snapshot = policy_store.get_current(name)
    except policy_store.PolicyNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "policy_not_found", "name": name},
        )

    current_specs = [RuleSpec.model_validate(item) for item in snapshot["rules"]]
    current_rules = compile_specs(current_specs)
    candidate_rules = compile_specs(body.rules)

    report = impact_preview.preview_impact(
        body.samples, current_rules, candidate_rules, salt=config.get_salt()
    )
    results = []
    for index, result in enumerate(report["samples"]):
        results.append(
            {
                "index": index,
                "diff": result["diff"],
                "counts": result["counts"],
                "has_changes": result["has_changes"],
            }
        )

    return JSONResponse(
        {
            "baseline": {
                "name": snapshot["name"],
                "version": snapshot["version"],
                "etag": snapshot["etag"],
            },
            "samples": results,
            "summary": report["summary"],
        }
    )


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


@app.post(
    "/redact",
    response_model=RedactResponse,
    tags=["redact"],
    responses={
        404: {"description": "Referenced policy or pinned version does not exist."},
        422: {"description": "Invalid rules, or both/neither rule source misconfigured."},
    },
)
def redact_endpoint(request: RedactRequest) -> JSONResponse:
    policy_ref: Optional[Dict[str, Any]] = None

    if request.policy is not None:
        selector = request.policy
        # Unspecified version -> one atomic read of the newest committed
        # version; pinned version -> the immutable historical snapshot.
        try:
            if selector.version is None:
                snapshot = policy_store.get_current(selector.name)
            else:
                snapshot = policy_store.get_version(selector.name, selector.version)
        except policy_store.PolicyNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "policy_not_found",
                    "name": selector.name,
                    "version": selector.version,
                },
            )
        rule_specs = [RuleSpec.model_validate(item) for item in snapshot["rules"]]
        policy_ref = {"name": snapshot["name"], "version": snapshot["version"]}
    else:
        rule_specs = request.inline_rules

    # Compile specs inside the handler so an invalid pointer produces a clean
    # 422 (Pydantic ValidationError -> FastAPI) rather than a 500.
    rules = compile_specs(rule_specs)
    redacted, audit = redact(request.data, rules, salt=config.get_salt())

    # Stamp every audit record with the concrete policy actually applied;
    # historical pins stay reproducible because the snapshot never changes.
    if policy_ref is not None:
        for entry in audit:
            entry["policy"] = policy_ref

    return JSONResponse(
        {"redacted": redacted, "audit": audit, "policy": policy_ref}
    )
