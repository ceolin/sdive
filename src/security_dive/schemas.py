"""Result schemas: what an analysis subagent must write for `sdive record`."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Location(_Strict):
    path: str = Field(description="Repo-relative path in the snapshot")
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    symbol: str | None = Field(default=None, description="Enclosing function, if any")


class UnitStatus(_Strict):
    key: str = Field(description="Unit key exactly as given in the brief")
    status: Literal["clean", "hypotheses", "partial"] = Field(
        description="clean: examined, nothing found; hypotheses: examined, raised "
        "at least one; partial: not examined thoroughly enough to count as covered"
    )
    note: str = ""


class Hypothesis(_Strict):
    title: str = Field(max_length=120)
    claim: str = Field(
        description="What is wrong, where attacker-influenced data enters, and how it "
        "reaches the defect. This is all the blind verifier sees besides locations."
    )
    locations: list[Location] = Field(min_length=1)
    property: str | None = Field(default=None, description="Threat-model property, e.g. P1")
    attacker: str | None = Field(default=None, description="Attacker class, e.g. A2")
    cwe: str | None = Field(default=None, description="e.g. CWE-787")
    confidence: Literal["low", "medium", "high"]
    auditor_notes: str = Field(default="", description="Not shown to the verifier")
    slug: str | None = Field(default=None, description="Optional short kebab-case id")


class UpstreamNote(_Strict):
    """A suspected defect inside an external (reference) component, e.g. a
    crypto library. Kept for later triage and filing with that project; never
    an MCUboot/Zephyr finding."""

    component: str = Field(description="Reference tree path as given in the brief")
    title: str = Field(max_length=120)
    description: str = Field(
        description="The suspected defect in the external code, and how this project "
        "is or could be affected"
    )
    locations: list[Location] = []


class DossierNote(_Strict):
    area: str
    text: str = Field(
        description="Markdown: trust boundaries, invariants (with where they are "
        "enforced), and cleared patterns with the reason they are safe"
    )


class AuditResult(_Strict):
    """Output of a sweep or dive run."""

    run_id: int
    model: str = Field(description="Model ID the agent is running as")
    summary: str
    units: list[UnitStatus]
    hypotheses: list[Hypothesis] = Field(
        default=[],
        description="Defects in this project's code: each needs at least one location "
        "in an indexed unit. Locations in reference trees may be added as evidence.",
    )
    dossier: list[DossierNote] = []
    upstream_notes: list[UpstreamNote] = []


class VerifyResult(_Strict):
    """Output of a verify run: an independent verdict on one hypothesis."""

    run_id: int
    model: str
    verdict: Literal["verified", "rejected", "duplicate", "inconclusive"]
    reasoning: str = Field(description="The code-grounded argument for the verdict")
    property: str | None = None
    attacker: str | None = None
    cwe: str | None = None
    severity: str | None = Field(default=None, description="CVSS vector, if verified")
    duplicate_of: str | None = Field(
        default=None, description="Finding slug, GHSA id, or disclosure id"
    )
    revised_title: str | None = None
    revised_claim: str | None = None
    dossier: list[DossierNote] = []
    upstream_notes: list[UpstreamNote] = []

    @model_validator(mode="after")
    def _check(self) -> VerifyResult:
        if self.verdict == "verified" and not (self.property and self.attacker):
            raise ValueError("a verified finding must name property and attacker")
        if self.verdict == "duplicate" and not self.duplicate_of:
            raise ValueError("a duplicate verdict must give duplicate_of")
        return self


class WriteupResult(_Strict):
    """Output of a write-up: the advisory draft for one cluster. The fields up to
    `rationale` are zepsec's MCUboot verdict (`result.json`) fields, so zepsec's
    filing tools read the export directly; the rest are sdive's additions."""

    cluster: str = Field(description="Cluster slug exactly as given in the brief")
    model: str = Field(description="Model ID the agent is running as")
    is_vulnerability: Literal["yes", "no", "unclear"]
    property_violated: Literal["P1", "P2", "P3", "P4", "P5", "P6"] | None
    attacker_class: Literal["A1", "A2", "A3"] | None
    vuln_class: Literal["memory-safety", "bounds", "integer-overflow", "use-after-free",
                        "info-leak", "auth", "crypto", "dos", "race", "logic",
                        "input-validation", "other"] | None
    cwe: str | None = Field(pattern=r"^CWE-\d+$")
    severity: Literal["none", "low", "moderate", "high", "critical"]
    cvss_vector: str | None = Field(description="CVSS 3.1 base vector; sdive scores it")
    attacker_reachable: Literal["yes", "maybe", "no", "unknown"]
    reachable_surface: list[str] = []
    affected_components: list[str] = Field(description="Repo-relative paths in the snapshot")
    affected_functions: list[str] = []
    introduced_by: str | None
    affected_versions: str | None
    reportable: bool
    reportable_reason: str | None
    advisory_summary: str | None = Field(max_length=150)
    advisory_description: str | None
    confidence: Literal["low", "medium", "high"]
    evidence: list[str] = Field(min_length=1)
    rationale: str
    # sdive additions
    affected_configurations: list[str] = Field(
        default=[], description="Build options (MCUBOOT_*/CONFIG_*) and ports it needs")
    recommended_fix: str = Field(description="The one fix that closes every member")
    open_questions: list[str] = Field(
        default=[], description="What the write-up could not settle from source")

    @model_validator(mode="after")
    def _check(self) -> WriteupResult:
        if self.is_vulnerability == "yes":
            missing = [k for k in ("property_violated", "attacker_class", "cwe", "cvss_vector",
                                   "advisory_summary", "advisory_description")
                       if not getattr(self, k)]
            if missing:
                raise ValueError(f"a vulnerability needs {', '.join(missing)}")
        if not self.reportable and not (self.reportable_reason or "").strip():
            raise ValueError("reportable false needs reportable_reason")
        return self


SCHEMAS: dict[str, type[BaseModel]] = {
    "audit": AuditResult, "verify": VerifyResult, "writeup": WriteupResult}
