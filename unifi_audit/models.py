from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    detail: str
    rationale: str = ""
    recommendation: str = ""
    confidence: str = "medium"
    cis_controls: list[str] = field(default_factory=list)
    nist_controls: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleResult:
    rule_id: str
    title: str
    category: str
    severity: str
    status: str  # pass | fail | unknown
    rationale: str
    recommendation: str
    confidence: str  # high | medium | low
    cis_controls: list[str] = field(default_factory=list)
    nist_controls: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditReport:
    backup_path: str
    profile: str
    score: int
    grade: str
    rules: list[RuleResult]
    findings: list[Finding]
    stats: dict[str, Any]
