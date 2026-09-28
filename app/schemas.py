"""Pydantic models for the redaction API."""

from __future__ import annotations

from typing import Any, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .redaction import compile_rule, parse_pointer

Action = Literal["mask", "remove", "sha256"]

# Policy names are URL path segments composed of conservative characters.
NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"


class RuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pointer: str = Field(
        ...,
        description="JSON Pointer (RFC 6901); '*' matches one segment, '**' matches any number.",
        examples=["/users/*/email"],
    )
    action: Action = Field(..., description="Action to apply to every matched node.")
    name: Optional[str] = Field(
        default=None, description="Optional human-readable name echoed into the audit trail."
    )

    @field_validator("pointer")
    @classmethod
    def _valid_pointer(cls, value: str) -> str:
        # Raises ValueError -> Pydantic ValidationError -> HTTP 422.
        parse_pointer(value)
        return value


class PolicySelector(BaseModel):
    """Reference to a persisted policy, optionally pinned to a version."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        ...,
        pattern=NAME_PATTERN,
        description="Name of a policy previously stored via PUT /policies/{name}.",
    )
    version: Optional[int] = Field(
        default=None,
        ge=1,
        description=(
            "Immutable version to redact against. When omitted, the request "
            "atomically reads the latest version at handling time."
        ),
    )


class RedactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: Any = Field(..., description="Arbitrary JSON document to redact.")
    rules: Optional[List[RuleSpec]] = Field(
        default=None,
        description="Inline redaction rules. Mutually exclusive with 'policy'.",
    )
    policy: Optional[PolicySelector] = Field(
        default=None,
        description="Named policy reference. Mutually exclusive with inline 'rules'.",
    )

    @model_validator(mode="after")
    def _exactly_one_rule_source(self) -> "RedactRequest":
        if self.rules is not None and self.policy is not None:
            raise ValueError("'rules' and 'policy' are mutually exclusive; choose one")
        return self

    @property
    def inline_rules(self) -> List[RuleSpec]:
        """Inline rules, defaulting to an empty list for backwards compatibility."""
        return self.rules if self.rules is not None else []


class PolicyUpsert(BaseModel):
    """Body of PUT /policies/{name}: a full replacement rule list."""

    model_config = ConfigDict(extra="forbid")

    rules: List[RuleSpec] = Field(
        ..., description="Complete rule set for the new immutable version."
    )


class RuleRef(BaseModel):
    index: int = Field(..., description="Zero-based declaration index within the effective rules.")
    pointer: str
    action: Action
    name: Optional[str] = None


class PolicyRef(BaseModel):
    name: str = Field(..., description="Name of the policy actually applied.")
    version: int = Field(
        ..., description="Concrete version actually applied (resolved when unspecified)."
    )


class AuditEntry(BaseModel):
    pointer: str = Field(..., description="JSON Pointer of the node on the ORIGINAL document.")
    action: Action
    rule: RuleRef
    policy: Optional[PolicyRef] = Field(
        default=None,
        description="Set when the rules came from a policy; absent for inline rules.",
    )


class RedactResponse(BaseModel):
    redacted: Any
    audit: List[AuditEntry]
    policy: Optional[PolicyRef] = Field(
        default=None,
        description=(
            "Name and concrete version of the policy applied; "
            "absent when inline rules were supplied."
        ),
    )


class PolicySnapshot(BaseModel):
    """An immutable versioned policy snapshot."""

    name: str
    version: int
    rules: List[RuleSpec]
    etag: str = Field(..., description="Opaque, version-specific validator (also an ETag).")
    created_at: str = Field(..., description="UTC ISO-8601 creation timestamp.")


# --------------------------------------------------------------------------- #
# Policy change impact preview
# --------------------------------------------------------------------------- #

MAX_IMPACT_SAMPLES = 20


class ImpactRequest(BaseModel):
    """Body of POST /policies/{name}/impact: candidate rules + sample docs."""

    model_config = ConfigDict(extra="forbid")

    rules: List[RuleSpec] = Field(
        ...,
        description=(
            "Candidate rule set to preview. It is NEVER persisted or used to "
            "create a new version; the stored policy stays untouched."
        ),
    )
    samples: List[Any] = Field(
        ...,
        min_length=1,
        max_length=MAX_IMPACT_SAMPLES,
        description=(
            f"1..{MAX_IMPACT_SAMPLES} representative JSON documents; each is "
            "processed once by the current rules and once by the candidate rules."
        ),
    )


class ImpactEffect(BaseModel):
    """One side of an effective-action comparison."""

    action: Action
    rule: RuleRef


class ImpactAdded(BaseModel):
    pointer: str = Field(..., description="Original-document JSON Pointer newly acted on.")
    action: Action
    rule: RuleRef


class ImpactRemoved(BaseModel):
    pointer: str = Field(..., description="Original-document JSON Pointer no longer acted on.")
    action: Action
    rule: RuleRef


class ImpactChanged(BaseModel):
    pointer: str = Field(
        ..., description="Original-document JSON Pointer whose effective action changes."
    )
    before: ImpactEffect
    after: ImpactEffect


class ImpactDiff(BaseModel):
    added: List[ImpactAdded] = Field(default_factory=list)
    removed: List[ImpactRemoved] = Field(default_factory=list)
    changed: List[ImpactChanged] = Field(default_factory=list)


class ImpactCounts(BaseModel):
    added: int
    removed: int
    changed: int


class SampleImpact(BaseModel):
    index: int = Field(..., description="Zero-based position of the sample in the request.")
    diff: ImpactDiff
    counts: ImpactCounts
    has_changes: bool


class ImpactSummary(ImpactCounts):
    samples: int = Field(..., description="Number of samples compared.")


class ImpactBaseline(BaseModel):
    name: str
    version: int = Field(
        ..., description="Concrete current version atomically read for this preview."
    )
    etag: str = Field(..., description="ETag of the baseline (current) version.")


class ImpactResponse(BaseModel):
    baseline: ImpactBaseline
    samples: List[SampleImpact]
    summary: ImpactSummary


def compile_specs(rules: List[RuleSpec]):
    """Turn validated request specs into engine rules."""
    return [
        compile_rule(index=i, pointer=spec.pointer, action=spec.action, name=spec.name)
        for i, spec in enumerate(rules)
    ]
