"""SQL firewall rules for azurerm_sql_firewall_rule / mssql variants."""

from __future__ import annotations

from typing import Iterable

from app.hcl_normalize import Resource
from .base import Finding, Rule, Severity


def _ip_to_int(ip: str) -> int | None:
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return None
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]


class SqlFirewallAllowAllRule(Rule):
    id = "AZ-SQL-001"
    title = "SQL firewall rule exposes the server to the internet"
    severity = Severity.CRITICAL
    applies_to = ("azurerm_sql_firewall_rule", "azurerm_mssql_firewall_rule")

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        start = resource.attr("start_ip_address")
        end = resource.attr("end_ip_address")
        if start is None or end is None:
            return

        start_i = _ip_to_int(start)
        end_i = _ip_to_int(end)

        # The Azure-documented "allow all Azure services" sentinel.
        azure_services = start == "0.0.0.0" and end == "0.0.0.0"
        # A range that begins at 0.0.0.0 spanning any real breadth is world-open.
        wide_open = (
            start_i is not None
            and end_i is not None
            and start_i == 0
            and end_i >= _ip_to_int("255.255.255.255")
        )

        if azure_services:
            yield self.finding(
                resource,
                detail="start/end = 0.0.0.0 is the 'Allow all Azure services' rule, open to any Azure tenant.",
                remediation=(
                    "Remove the 0.0.0.0-0.0.0.0 rule. Use private endpoints or scope "
                    "firewall rules to specific trusted IPs."
                ),
            )
        elif wide_open:
            yield self.finding(
                resource,
                detail=f"Firewall range {start} - {end} covers the entire public IPv4 space.",
                remediation=(
                    "Scope start_ip_address/end_ip_address to specific trusted IPs; "
                    "never span 0.0.0.0 - 255.255.255.255."
                ),
            )
