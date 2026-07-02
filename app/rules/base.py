"""Rule contract + Finding model shared by all checks."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Iterable

from app.hcl_normalize import Resource


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    """A single rule violation against a specific resource."""

    rule_id: str
    title: str
    severity: Severity
    resource: str      # terraform address, e.g. azurerm_sql_firewall_rule.allow_all
    file: str
    detail: str        # what specifically tripped the rule
    remediation: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


class Rule:
    """Base class. Subclasses set metadata and implement `evaluate`."""

    id: str = "BASE"
    title: str = "Base rule"
    severity: Severity = Severity.MEDIUM
    # Resource types this rule cares about; empty means "all".
    applies_to: tuple[str, ...] = ()

    def matches_type(self, resource: Resource) -> bool:
        return not self.applies_to or resource.type in self.applies_to

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Yield Finding objects for violations. Override in subclasses."""
        raise NotImplementedError

    def finding(self, resource: Resource, detail: str, remediation: str) -> Finding:
        """Helper to build a Finding carrying this rule's metadata."""
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            resource=resource.address,
            file=resource.file,
            detail=detail,
            remediation=remediation,
        )
