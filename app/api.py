"""FastAPI scan engine — the only component that touches the database."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from app import db
from app.rules import ALL_RULES
from app.scanner import scan_path

app = FastAPI(
    title="Azure Security Guardrail Auditor",
    description="API-first scanner for Azure Terraform misconfigurations.",
    version="1.0.0",
)


@app.on_event("startup")
def _startup() -> None:
    db.init_db()


class ScanRequest(BaseModel):
    target: str = Field(
        default="test_infrastructure",
        description="Path to a .tf file or directory of them.",
    )


class ScanResult(BaseModel):
    scan_id: int
    target: str
    total: int
    counts: dict
    findings: list[dict]


@app.get("/health")
def health() -> dict:
    return {"status": "up"}


@app.get("/rules")
def rules() -> list[dict]:
    """Expose the active rule catalogue for transparency in the dashboard."""
    return [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity.value,
            "applies_to": list(r.applies_to),
        }
        for r in ALL_RULES
    ]


@app.post("/scan", response_model=ScanResult)
def run_scan(req: ScanRequest) -> ScanResult:
    if not Path(req.target).exists():
        raise HTTPException(status_code=404, detail=f"target not found: {req.target}")

    findings = scan_path(req.target)
    scan_id = db.save_scan(req.target, findings)
    scan = db.get_scan(scan_id)
    return ScanResult(
        scan_id=scan_id,
        target=req.target,
        total=scan["total"],
        counts={
            "CRITICAL": scan["critical"],
            "HIGH": scan["high"],
            "MEDIUM": scan["medium"],
            "LOW": scan["low"],
        },
        findings=[f.to_dict() for f in findings],
    )


@app.get("/scans")
def scans(limit: int = Query(50, ge=1, le=500)) -> list[dict]:
    return db.list_scans(limit=limit)


@app.get("/scans/{scan_id}")
def scan_detail(scan_id: int) -> dict:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"scan {scan_id} not found")
    scan["findings"] = db.get_findings(scan_id=scan_id)
    return scan


@app.get("/findings")
def findings(
    scan_id: int | None = Query(None),
    severity: str | None = Query(None),
) -> list[dict]:
    return db.get_findings(scan_id=scan_id, severity=severity)
