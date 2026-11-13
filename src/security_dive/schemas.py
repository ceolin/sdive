"""Result schemas: what an analysis subagent must write for `sdive record`."""

from __future__ import annotations

import re
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


class Verdict(_Strict):
    """An advisory verdict for one cluster. The fields up to `rationale` are
    zepsec's MCUboot verdict (`result.json`) fields, so zepsec's filing tools
    read an export directly; the rest are sdive's additions."""

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
    def _check_verdict(self) -> Verdict:
        if self.is_vulnerability == "yes":
            missing = [k for k in ("property_violated", "attacker_class", "cwe", "cvss_vector",
                                   "advisory_summary", "advisory_description")
                       if not getattr(self, k)]
            if missing:
                raise ValueError(f"a vulnerability needs {', '.join(missing)}")
        if not self.reportable and not (self.reportable_reason or "").strip():
            raise ValueError("reportable false needs reportable_reason")
        return self


class WriteupResult(Verdict):
    """Output of a write-up (the sdive-writer agent): the verdict for one cluster."""

    cluster: str = Field(description="Cluster slug exactly as given in the brief")
    model: str = Field(description="Model ID the agent is running as")


# --- the hand-off to zepsec ------------------------------------------------
# Both documents are a contract with zepsec's client-side intake: change them
# only by bumping the schema string, and regenerate schemas/ (`sdive schema
# --write`).

HEX40 = r"^[0-9a-f]{40}$"


class ExportVerification(_Strict):
    run_id: int
    model: str | None
    verdict: str | None


class ExportMemberScope(_Strict):
    verdict: Literal["released", "post-release", "mixed", "unknown"] | None = None
    latest_release: str | None = None
    as_is_since: str | None = None


class ExportMember(_Strict):
    slug: str
    title: str
    claim: str
    property: str | None
    attacker: str | None
    cwe: str | None
    cvss_vector: str | None = Field(description="The verifier's vector (provenance)")
    confidence: str | None
    locations: list[Location]
    carried_from: str | None = Field(
        description="'<ledger>:<slug>' when carried in from a benchmark round")
    verification: list[ExportVerification]
    scope: ExportMemberScope


class ExportSnapshot(_Strict):
    sha: str = Field(pattern=HEX40)
    ref: str | None


class ExportProvenance(_Strict):
    ledger: str
    snapshot: ExportSnapshot
    writeup_version: int = Field(ge=1)
    written_by: str | None = Field(description="The writer's model (not credited)")
    written_at: str
    approved_at: str
    approval_note: str | None
    origin_runs: list[int]
    analysis_models: list[str] = Field(
        description="Models that found and verified the members: the ones to credit")
    sdive_commit: str | None
    exported_at: str


class ExportDocument(Verdict):
    """`cluster.json`: an approved write-up exported for zepsec."""

    schema_: Literal["sdive-export/1"] = Field(alias="schema")
    source: Literal["security-dive"]
    project: str = Field(description="sdive project name; selects zepsec's filing profile")
    cluster: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    title: str
    track: Literal["advisory", "plain-fix"]
    track_note: str | None
    sha: str = Field(pattern=HEX40, description="Commit analysed: not a fix SHA")
    cvss_score: float | None = Field(ge=0, le=10)
    members: list[ExportMember] = Field(min_length=1)
    scope: Literal["released", "post-release", "mixed", "unknown"] | None
    provenance: ExportProvenance

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class StatusDedup(_Strict):
    match: Literal["duplicate", "annotate", "distinct", "none"]
    advisory: str | None = Field(default=None, pattern=r"^GHSA(-[0-9a-z]{4}){3}$")
    note: str | None = None


class StatusBackport(_Strict):
    line: str
    pr: str | None = None
    sha: str | None = Field(default=None, pattern=HEX40)


ZEPSEC_STATES = ("received", "duplicate", "drafted", "fix-open", "fix-merged", "published",
                 "declined")


class ZepsecStatus(_Strict):
    """`status.json`: zepsec's report on one export, written beside it.

    Rules beyond the field types (checked by `sdive sync-status`): state
    `duplicate` needs dedup.match `duplicate` and dedup.advisory; `drafted`
    and `published` need ghsa_id; `fix-open` needs fix_prs; `fix-merged` needs
    fix_shas (40-hex). export_hash must be the hash of a cluster.json sdive
    wrote. sdive moves the members to `fixed` on `fix-merged`, or on
    `published` with fix_shas, and to `duplicate` on `duplicate`."""

    schema_: Literal["zepsec-status/1"] = Field(alias="schema")
    project: str
    cluster: str
    export_hash: str = Field(pattern=r"^[0-9a-f]{32}$",
                             description="First 32 hex chars of sha256(cluster.json) as read")
    writeup_version: int = Field(ge=1)
    unit: str | None = None
    state: Literal["received", "duplicate", "drafted", "fix-open", "fix-merged", "published",
                   "declined"]
    dedup: StatusDedup | None = None
    ghsa_id: str | None = Field(default=None, pattern=r"^GHSA(-[0-9a-z]{4}){3}$")
    cve_id: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")
    fix_prs: list[str] = []
    fix_shas: list[str] = Field(default=[], description="40-hex commit SHAs")
    backports: list[StatusBackport] = []
    notes: str | None = None
    updated_at: str

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @model_validator(mode="after")
    def _check_state(self) -> ZepsecStatus:
        bad = [s for s in self.fix_shas if not re.fullmatch(HEX40, s)]
        if bad:
            raise ValueError(f"fix_shas must be 40-hex commit SHAs: {bad}")
        if self.state == "duplicate" and not (self.dedup and self.dedup.match == "duplicate"
                                              and self.dedup.advisory):
            raise ValueError("state duplicate needs dedup.match duplicate and dedup.advisory")
        if self.state in ("drafted", "published") and not self.ghsa_id:
            raise ValueError(f"state {self.state} needs ghsa_id")
        if self.state == "fix-open" and not self.fix_prs:
            raise ValueError("state fix-open needs fix_prs")
        if self.state == "fix-merged" and not self.fix_shas:
            raise ValueError("state fix-merged needs fix_shas")
        return self


SCHEMAS: dict[str, type[BaseModel]] = {
    "audit": AuditResult, "verify": VerifyResult, "writeup": WriteupResult,
    "export": ExportDocument, "status": ZepsecStatus}

# Contract files committed under schemas/ for zepsec to validate against.
CONTRACT_FILES = {"export": "sdive-export-1.schema.json", "status": "zepsec-status-1.schema.json"}


def contract_schema(kind: str) -> dict:
    """The JSON Schema of a hand-off document, as committed under schemas/."""
    schema = SCHEMAS[kind].model_json_schema(by_alias=True)
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = CONTRACT_FILES[kind]
    return schema
