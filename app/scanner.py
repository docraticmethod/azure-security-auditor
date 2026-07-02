"""Scan engine: walk .tf files, apply all rules, collect findings."""

from __future__ import annotations

from pathlib import Path

from app.hcl_normalize import load_resources
from app.rules import ALL_RULES, Finding


def scan_text(tf_text: str, source_file: str = "<memory>") -> list[Finding]:
    """Run every registered rule over a single Terraform document."""
    findings: list[Finding] = []
    for resource in load_resources(tf_text, source_file):
        for rule in ALL_RULES:
            if not rule.matches_type(resource):
                continue
            findings.extend(rule.evaluate(resource))
    return findings


def scan_path(path: str | Path) -> list[Finding]:
    """Scan a single .tf file or recurse a directory of them.

    Files that fail to parse are surfaced as their own error entries rather than
    aborting the whole scan.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"scan target does not exist: {path}")

    tf_files = [path] if path.is_file() else sorted(path.rglob("*.tf"))

    findings: list[Finding] = []
    for tf in tf_files:
        rel = str(tf)
        try:
            findings.extend(scan_text(tf.read_text(), rel))
        except Exception as exc:  # noqa: BLE001 — report, don't abort the batch
            from app.rules.base import Severity

            findings.append(
                Finding(
                    rule_id="PARSE-ERR",
                    title="Terraform file failed to parse",
                    severity=Severity.LOW,
                    resource=rel,
                    file=rel,
                    detail=f"{type(exc).__name__}: {exc}",
                    remediation="Fix the HCL syntax so the file can be audited.",
                )
            )
    return findings
