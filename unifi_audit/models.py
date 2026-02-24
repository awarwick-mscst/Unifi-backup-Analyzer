from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    detail: str
    recommendation: str = ""
    cis_controls: list[str] = field(default_factory=list)
    nist_controls: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditReport:
    backup_path: str
    profile: str
    score: int
    grade: str
    findings: list[Finding]
    stats: dict[str, Any]
