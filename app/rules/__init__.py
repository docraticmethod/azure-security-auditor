"""Pluggable security-rule engine.

Each rule is a subclass of `Rule` that inspects a normalized `Resource` and
yields zero or more `Finding` objects. Rules self-register via `ALL_RULES` so the
scanner stays agnostic to which checks exist.
"""

from __future__ import annotations

from .base import Finding, Rule, Severity
from .network import OpenSshRdpRule
from .storage import PublicBlobAccessRule
from .database import SqlFirewallAllowAllRule

# The registry the scanner iterates. Add new rules here.
ALL_RULES: list[Rule] = [
    OpenSshRdpRule(),
    PublicBlobAccessRule(),
    SqlFirewallAllowAllRule(),
]

__all__ = [
    "Finding",
    "Rule",
    "Severity",
    "ALL_RULES",
]
