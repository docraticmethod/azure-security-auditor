"""Smoketest: verify the stack is wired before handing off to the AI agent."""

import sys


def check_imports():
    import hcl2          # noqa: F401
    import fastapi       # noqa: F401
    import streamlit     # noqa: F401
    print(f"[ok] imports        python {sys.version.split()[0]}")


def check_hcl2_parse():
    import io
    import hcl2
    tf = 'resource "azurerm_network_security_rule" "x" {\n' \
         '  destination_port_range = "22"\n' \
         '  source_address_prefix  = "*"\n' \
         '}\n'
    def unq(s):
        return s.strip('"') if isinstance(s, str) else s

    def get(d, key):
        for k, v in d.items():
            if unq(k) == key:
                return v
        raise KeyError(f"{key} not in {list(d)}")

    parsed = hcl2.load(io.StringIO(tf))
    res = parsed["resource"][0]
    rule = get(get(res, "azurerm_network_security_rule"), "x")
    assert unq(rule["destination_port_range"]) == "22", rule
    assert unq(rule["source_address_prefix"]) == "*", rule
    print("[ok] hcl2 parse     traversed nested block, extracted port 22 + wildcard")


def check_fastapi():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()

    @app.get("/health")
    def health():
        return {"status": "up"}

    r = TestClient(app).get("/health")
    assert r.status_code == 200 and r.json() == {"status": "up"}, r.text
    print("[ok] fastapi        /health responds 200")


def check_sqlite():
    import sqlite3
    c = sqlite3.connect(":memory:")
    c.execute("create table t(x)")
    c.execute("insert into t values (42)")
    val = c.execute("select x from t").fetchone()[0]
    assert val == 42, val
    print(f"[ok] sqlite         round-trip write/read, engine {sqlite3.sqlite_version}")


if __name__ == "__main__":
    check_imports()
    check_hcl2_parse()
    check_fastapi()
    check_sqlite()
    print("\nAll green. Freeze it:  python -m pip freeze > requirements.txt")