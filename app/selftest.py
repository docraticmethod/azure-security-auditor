"""End-to-end self-test: scan the fixtures and assert the expected verdict.

Run:  python -m app.selftest
"""

from __future__ import annotations

from collections import Counter

from app.scanner import scan_path


def main() -> int:
    findings = scan_path("test_infrastructure")
    by_sev = Counter(f.severity.value for f in findings)
    by_rule = Counter(f.rule_id for f in findings)

    print(f"total findings: {len(findings)}")
    print(f"by severity   : {dict(by_sev)}")
    print(f"by rule       : {dict(by_rule)}")

    # Expected verdict for the shipped fixtures.
    assert len(findings) == 8, f"expected 8 findings, got {len(findings)}"
    assert by_sev["CRITICAL"] == 5, by_sev
    assert by_sev["HIGH"] == 3, by_sev
    assert by_rule["AZ-NET-001"] == 3, by_rule
    assert by_rule["AZ-SQL-001"] == 2, by_rule
    assert by_rule["AZ-STG-001"] == 3, by_rule

    # Secure resources must NOT appear in findings.
    flagged = {f.resource for f in findings}
    for safe in (
        "azurerm_network_security_rule.allow_ssh_corp",
        "azurerm_network_security_rule.deny_all_ssh",
        "azurerm_network_security_rule.outbound_https",
        "azurerm_storage_account.secure_sa",
        "azurerm_sql_firewall_rule.office_only",
    ):
        assert safe not in flagged, f"false positive on {safe}"

    print("\n[ok] self-test passed — all assertions green.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
