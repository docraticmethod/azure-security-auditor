# Prompts Audit Log — Azure Security Guardrail Auditor

**Project:** Enterprise Security Guardrail Auditor (Azure-focused Terraform Scanner)
**Stack:** Python · FastAPI (scan engine) · Streamlit (dashboard) · SQLite · python-hcl2
**Human AI Architect (Master Orchestrator):** Blake Rogers
**Time Human Started Coding Agent:** July 2, 2026 2:14 pm
**Agent:** Claude Code (Opus 4.8)
**Started:** July 2, 2026 2:15 pm

---

## Pre-flight (done manually before agent handoff)
- venv built, deps frozen to `requirements.txt`
- `smoketest.py` green: imports · hcl2 nested-block parse · FastAPI /health · sqlite round-trip
- Known constraint characterized: hcl2 wraps scalars/keys in literal quotes — traversal must `.strip('"')`
- Git initialized; `.venv/` and `.env` gitignored

---

## Turn 01 — Kickoff
**Prompt:**
> Lead Architect mode: ON. We are building a Python-based, API-first Enterprise Security Guardrail Auditor (Azure-focused Terraform Scanner) using a free database and a dashboard.
> Rules:
> - No Manual Edits: You provide all logic and fixes. I will not edit any code.
> - Audit Log: You must maintain a file named prompts.md. After every turn, provide the prompt text block so I can append it.
> - Time-Check: Report 'Elapsed Time' at the end of every response. Goal is an MVP in 4-6 hours (Max window: 16h). Acknowledge and let's start.
>
> Context for you: The environment is already set up — venv, requirements.txt (fastapi, uvicorn, streamlit, python-hcl2), a passing smoketest.py, and SQLite ready. One known quirk: python-hcl2 wraps values and keys in literal quotes (e.g. "22" parses as '"22"'), so all rule comparisons must strip quotes first. Build that normalization in from the start.
>
> First step: generate dummy Azure .tf files in test_infrastructure/ — some secure, some intentionally flawed (open SSH/RDP on an NSG, public blob access on a Storage Account, SQL firewall 0.0.0.0). We need something to scan.

**Decisions (via clarifying questions):**
- Architecture: strict API-first — Streamlit → FastAPI → SQLite (only the API touches the DB).
- Scope: build straight through the MVP without pausing between turns.

**Delivered (Turns 01–05, single pass):**
- `test_infrastructure/` — 4 fixture files (network_insecure, network_secure, storage, database) mixing flawed + secure Azure resources.
- `app/hcl_normalize.py` — single choke point for the python-hcl2 quote quirk (`unq`/`get`/`load_resources` → `Resource` objects). Verified: `"22"` normalizes to `22`, ints pass through, hcl2 v8 `__is_block__` marker ignored.
- `app/rules/` — pluggable engine: `AZ-NET-001` (SSH/RDP exposure, port-range aware), `AZ-STG-001` (public blob / public network), `AZ-SQL-001` (firewall allow-all). Registered in `ALL_RULES`.
- `app/scanner.py` — walks `.tf`, applies all rules, per-file parse-error isolation.
- `app/db.py` + `app/api.py` — SQLite persistence + FastAPI (`/health`, `/rules`, `/scan`, `/scans`, `/scans/{id}`, `/findings`). Dynamic DB path via `AUDITOR_DB`.
- `dashboard.py` — Streamlit UI, HTTP-only to the API (severity metrics, bar chart, filterable table, remediation drill-down).
- `app/selftest.py` — asserts the fixtures yield exactly 8 findings (5 CRITICAL, 3 HIGH) with zero false positives. Green.
- `README.md`, `.gitignore` (`*.db`, `__pycache__`).

**Verification:** normalization spot-check ✓ · rule engine 8/8 correct ✓ · FastAPI TestClient (scan/history/filter/404) ✓ · live uvicorn over HTTP ✓ · `python -m app.selftest` ✓

**Elapsed (real):** ~18 min (started 2:15 pm → ~2:33 pm)

**ACTUAL finish TIME per architect: 2:27pm, actual elapsed time 12 minutes)

---

## Turn 02 — Fixes (verify-first)
**Started:** July 4, 2026 1:22 pm PDT
**Prompt:**
> Two items — investigate before changing anything, "don't fix it if it's not broken."
> 1. Streamlit severity chart reportedly plots y inverted (0 at top, bars hanging down); suspect an Altair scale/sort flip.
> 2. Confirm the python-hcl2 quote-quirk mitigation is intact — no rule bypasses the `app/hcl_normalize.py` choke point by calling `hcl2.load` or comparing raw values; verify selftest still asserts 8 findings.

**Findings:**
- **hcl2 choke point — INTACT, no change.** `hcl2` is imported only inside `app/hcl_normalize.py` (`hcl2_load`). All three rule modules import only `Resource` from `app.hcl_normalize` and read values exclusively via `resource.attr()` / `resource.has()`, both routed through `unq()`. No rule compares raw hcl2 values or calls `hcl2.load`. `grep` across `app/` confirms zero bypasses.
- **selftest — GREEN.** `python -m app.selftest` → 8 findings (5 CRITICAL, 3 HIGH; AZ-NET-001×3, AZ-SQL-001×2, AZ-STG-001×3), zero false positives.
- **Chart y-axis — spec is clean, but hardened anyway.** Inspected the exact Vega-Lite spec `st.bar_chart` emits via `built_in_chart_utils.generate_chart`: y is `quantitative` with empty `scale: {}` (no `reverse`), x ordinal, plain `bar` mark — no inversion in streamlit 1.58.0 / altair 6.2.2. Per architect direction, replaced the implicit `st.bar_chart` with an explicit `st.altair_chart` so the axis and severity order are deterministic and no longer at the mercy of Streamlit defaults.

**Actions:**
- Replaced `st.bar_chart(chart, color="#b3001b")` in `dashboard.py` with an explicit Altair bar chart: x sorted by `SEV_ORDER`, y quantitative with `scale=alt.Scale(domainMin=0, reverse=False)` and integer ticks, per-severity colors from `SEV_COLOR`, count labels on bars.

**Verification:** `app.selftest` ✓ · rule/normalizer grep audit ✓ · Vega-Lite spec inspection ✓ · dashboard import/compile ✓

**Finished:** July 4, 2026 1:32 pm PDT
**Elapsed (real):** ~10 min (1:22 pm → 1:32 pm)

---