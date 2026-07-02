# Azure Security Guardrail Auditor

API-first scanner that audits Azure **Terraform** for common security
misconfigurations, persists findings to SQLite, and visualizes them in a
Streamlit dashboard.

## Architecture

```
Streamlit dashboard ──HTTP──▶ FastAPI scan engine ──▶ SQLite
     (dashboard.py)              (app/api.py)          (auditor.db)
                                      │
                                      ▼
                             rule engine (app/rules/)
                                      │
                                      ▼
                        HCL normalization (app/hcl_normalize.py)
```

Strict **API-first**: the dashboard talks only to the API over HTTP; only the
API touches the database.

### The python-hcl2 quirk
python-hcl2 wraps scalar values *and* keys in literal double quotes
(`"22"` → `'"22"'`). All quote-stripping and block traversal is centralized in
`app/hcl_normalize.py` (`unq`, `get`, `load_resources`); rules never call hcl2
directly.

## Rules

| ID          | Severity  | Resource                        | Detects |
|-------------|-----------|---------------------------------|---------|
| `AZ-NET-001`| CRITICAL  | `azurerm_network_security_rule` | Inbound Allow exposing SSH (22) / RDP (3389) to `*`, `0.0.0.0/0`, or `Internet` (handles port ranges & lists) |
| `AZ-STG-001`| HIGH      | `azurerm_storage_account`       | `allow_nested_items_to_be_public` or `public_network_access_enabled` = true |
| `AZ-SQL-001`| CRITICAL  | `azurerm_sql_firewall_rule`     | Firewall spanning `0.0.0.0`–`255.255.255.255` or the `0.0.0.0`–`0.0.0.0` allow-all-Azure rule |

Add a rule by subclassing `Rule` in `app/rules/` and registering it in
`app/rules/__init__.py:ALL_RULES`.

## Run it

```bash
# 1. Start the scan API
.venv/bin/uvicorn app.api:app --reload

# 2. In another terminal, start the dashboard
.venv/bin/streamlit run dashboard.py
```

Open the dashboard, set the target path (defaults to `test_infrastructure/`),
and click **Scan now**.

### API endpoints
| Method | Path             | Purpose |
|--------|------------------|---------|
| GET    | `/health`        | Liveness |
| GET    | `/rules`         | Active rule catalogue |
| POST   | `/scan`          | Scan a path; body `{"target": "..."}` |
| GET    | `/scans`         | Scan history |
| GET    | `/scans/{id}`    | One scan + its findings |
| GET    | `/findings`      | Findings, filter by `scan_id` / `severity` |

Environment: `AUDITOR_DB` (default `auditor.db`), `AUDITOR_API`
(dashboard → API URL, default `http://127.0.0.1:8000`).

## Test fixtures
`test_infrastructure/` holds intentionally mixed secure/insecure Azure `.tf`
files. A clean scan yields **8 findings** (5 CRITICAL, 3 HIGH); the secure
counterparts (deny rules, outbound, scoped CIDRs, hardened storage, single-IP
firewall) correctly produce none.

## Pre-flight sanity
```bash
.venv/bin/python smoketest.py       # stack wiring
.venv/bin/python -m app.selftest    # end-to-end scan assertion
```
