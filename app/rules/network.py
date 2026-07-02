"""Network exposure rules for azurerm_network_security_rule."""

from __future__ import annotations

from typing import Iterable

from app.hcl_normalize import Resource
from .base import Finding, Rule, Severity

# Source values that mean "anywhere on the internet".
_PUBLIC_SOURCES = {"*", "0.0.0.0/0", "0.0.0.0", "internet", "any", ""}

# Ports we consider management planes that must never face the internet.
_SENSITIVE_PORTS = {22: "SSH", 3389: "RDP"}


def _source_is_public(prefix: str | None) -> bool:
    if prefix is None:
        return False
    return prefix.strip().lower() in _PUBLIC_SOURCES


def _port_covered(port_range: str | None, target: int) -> bool:
    """True if `target` falls within an NSG destination_port_range value.

    Handles single ports ("22"), ranges ("20-30"), and wildcard ("*").
    Azure also allows comma lists ("22,3389").
    """
    if port_range is None:
        return False
    spec = port_range.strip()
    if spec == "*":
        return True
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                if int(lo) <= target <= int(hi):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(part) == target:
                    return True
            except ValueError:
                continue
    return False


class OpenSshRdpRule(Rule):
    id = "AZ-NET-001"
    title = "Management port open to the internet"
    severity = Severity.CRITICAL
    applies_to = ("azurerm_network_security_rule",)

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        if resource.attr("direction", "").lower() != "inbound":
            return
        if resource.attr("access", "").lower() != "allow":
            return
        if not _source_is_public(resource.attr("source_address_prefix")):
            return

        port_range = resource.attr("destination_port_range")
        for port, label in _SENSITIVE_PORTS.items():
            if _port_covered(port_range, port):
                src = resource.attr("source_address_prefix")
                yield self.finding(
                    resource,
                    detail=(
                        f"Inbound Allow rule exposes {label} (port {port}) to "
                        f"source '{src}' via destination_port_range='{port_range}'."
                    ),
                    remediation=(
                        f"Restrict source_address_prefix to a trusted CIDR/bastion, "
                        f"or remove public {label} access. Never allow {label} from "
                        f"'*', '0.0.0.0/0', or the Internet service tag."
                    ),
                )
