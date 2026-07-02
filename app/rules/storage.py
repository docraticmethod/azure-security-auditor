"""Storage exposure rules for azurerm_storage_account."""

from __future__ import annotations

from typing import Iterable

from app.hcl_normalize import Resource
from .base import Finding, Rule, Severity

_TRUE = {"true", "1", "yes"}


def _is_true(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _TRUE


class PublicBlobAccessRule(Rule):
    id = "AZ-STG-001"
    title = "Storage account allows public blob access"
    severity = Severity.HIGH
    applies_to = ("azurerm_storage_account",)

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        # allow_nested_items_to_be_public = true exposes containers/blobs publicly.
        if resource.has("allow_nested_items_to_be_public") and _is_true(
            resource.attr("allow_nested_items_to_be_public")
        ):
            yield self.finding(
                resource,
                detail=(
                    "allow_nested_items_to_be_public = true permits anonymous "
                    "public read of blobs/containers."
                ),
                remediation=(
                    "Set allow_nested_items_to_be_public = false unless anonymous "
                    "access is an explicit, reviewed requirement."
                ),
            )

        # public_network_access_enabled = true removes the network boundary.
        if resource.has("public_network_access_enabled") and _is_true(
            resource.attr("public_network_access_enabled")
        ):
            yield self.finding(
                resource,
                detail="public_network_access_enabled = true exposes the account to all networks.",
                remediation=(
                    "Set public_network_access_enabled = false and use private "
                    "endpoints or scoped network rules."
                ),
            )
