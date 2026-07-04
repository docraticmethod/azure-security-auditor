"""Streamlit dashboard for the Azure Security Guardrail Auditor.

Strict API-first: this UI talks only to the FastAPI service over HTTP and never
imports the scanner or touches SQLite directly.
"""

from __future__ import annotations

import os

import altair as alt
import pandas as pd
import requests
import streamlit as st

API_URL = os.getenv("AUDITOR_API", "http://127.0.0.1:8000")

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLOR = {
    "CRITICAL": "#b3001b",
    "HIGH": "#e8590c",
    "MEDIUM": "#f08c00",
    "LOW": "#2f9e44",
}

st.set_page_config(page_title="Azure Security Auditor", page_icon="🛡️", layout="wide")


def api_get(path: str, **params):
    r = requests.get(f"{API_URL}{path}", params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def api_post(path: str, payload: dict):
    r = requests.post(f"{API_URL}{path}", json=payload, timeout=120)
    r.raise_for_status()
    return r.json()


def api_online() -> bool:
    try:
        return api_get("/health").get("status") == "up"
    except Exception:
        return False


st.title("🛡️ Azure Security Guardrail Auditor")
st.caption("API-first Terraform misconfiguration scanner")

if not api_online():
    st.error(
        f"Cannot reach the scan API at {API_URL}. "
        "Start it with:  `uvicorn app.api:app --reload`"
    )
    st.stop()

# ── Sidebar: trigger a scan ────────────────────────────────────────────────
with st.sidebar:
    st.header("Run a scan")
    target = st.text_input("Target path", value="test_infrastructure")
    if st.button("▶ Scan now", type="primary", use_container_width=True):
        try:
            with st.spinner(f"Scanning {target}…"):
                result = api_post("/scan", {"target": target})
            st.success(f"Scan #{result['scan_id']}: {result['total']} findings")
        except requests.HTTPError as e:
            st.error(f"Scan failed: {e.response.text}")

    st.divider()
    st.subheader("Active rules")
    for rule in api_get("/rules"):
        st.markdown(f"**{rule['id']}** · {rule['severity']}  \n{rule['title']}")

# ── Main: pick a scan from history ─────────────────────────────────────────
scans = api_get("/scans")
if not scans:
    st.info("No scans yet. Use the sidebar to run your first scan.")
    st.stop()

labels = {
    f"#{s['id']} · {s['target']} · {s['total']} findings · {s['created_at'][:19]}": s["id"]
    for s in scans
}
chosen = st.selectbox("Scan history", list(labels.keys()))
scan_id = labels[chosen]
scan = api_get(f"/scans/{scan_id}")

# ── Severity breakdown ─────────────────────────────────────────────────────
st.subheader("Severity breakdown")
cols = st.columns(4)
for col, sev in zip(cols, SEV_ORDER):
    col.metric(sev, scan.get(sev.lower(), 0))

findings = scan.get("findings", [])
if not findings:
    st.success("✅ No misconfigurations found in this scan.")
    st.stop()

df = pd.DataFrame(findings)
df["severity"] = pd.Categorical(df["severity"], categories=SEV_ORDER, ordered=True)
df = df.sort_values(["severity", "resource"])

# Explicit Altair chart so the y-axis origin/direction and severity order are
# deterministic (not left to st.bar_chart's implicit encoding).
counts = df["severity"].value_counts().reindex(SEV_ORDER).fillna(0).astype(int)
chart_df = pd.DataFrame({"severity": SEV_ORDER, "count": counts.values})

bars = (
    alt.Chart(chart_df)
    .mark_bar()
    .encode(
        x=alt.X("severity:N", sort=SEV_ORDER, title="Severity"),
        y=alt.Y(
            "count:Q",
            title="Findings",
            scale=alt.Scale(domainMin=0, reverse=False),
            axis=alt.Axis(tickMinStep=1),
        ),
        color=alt.Color(
            "severity:N",
            scale=alt.Scale(
                domain=SEV_ORDER,
                range=[SEV_COLOR[s] for s in SEV_ORDER],
            ),
            legend=None,
        ),
        tooltip=["severity", "count"],
    )
)
labels = bars.mark_text(dy=-6, color="#666").encode(text="count:Q")
st.altair_chart(bars + labels, use_container_width=True)

# ── Findings table + drill-down ────────────────────────────────────────────
st.subheader("Findings")

sev_filter = st.multiselect("Filter by severity", SEV_ORDER, default=SEV_ORDER)
view = df[df["severity"].isin(sev_filter)]

st.dataframe(
    view[["severity", "rule_id", "resource", "file", "detail"]],
    use_container_width=True,
    hide_index=True,
)

st.subheader("Remediation drill-down")
for _, row in view.iterrows():
    color = SEV_COLOR.get(row["severity"], "#666")
    with st.expander(f"[{row['severity']}] {row['resource']} — {row['title']}"):
        st.markdown(
            f"<span style='color:{color};font-weight:600'>{row['severity']}</span> "
            f"· `{row['rule_id']}` · `{row['file']}`",
            unsafe_allow_html=True,
        )
        st.markdown(f"**What tripped:** {row['detail']}")
        st.markdown(f"**Remediation:** {row['remediation']}")
