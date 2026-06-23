import sys
from pathlib import Path

# Ensure the repo root is importable (Streamlit Cloud doesn't add it by default).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import altair as alt
import pandas as pd
import streamlit as st

from streamlit_app.api_client import get_metrics

st.set_page_config(page_title="Productivity Metrics", page_icon="📊", layout="wide")

# --- Storytelling with Data palette ---
# Mute everything to grey; spend colour sparingly on what demands attention.
GREY = "#bfbfbf"
ACCENT = "#c00000"   # reserved for the elements we want the eye drawn to
LINE = "#8c8c8c"
TEXT = "#595959"
GRID = "#ebebeb"
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def style(chart):
    """Soft, gridded styling: keep a light background grid, mute the chrome."""
    return (
        chart.configure_view(stroke=None)
        .configure_axis(
            grid=True,
            gridColor=GRID,
            domainColor="#d9d9d9",
            tickColor="#d9d9d9",
            labelColor=TEXT,
            titleColor=TEXT,
        )
        .configure_title(color=TEXT, fontSize=15, anchor="start")
    )


st.title("📊 Productivity Metrics")

try:
    m = get_metrics()
except Exception as exc:
    st.error(f"Could not load metrics: {exc}")
    st.stop()

# --- KPI cards: most decision-relevant first (SWD step 1: context) ---
c1, c2, c3, c4 = st.columns(4)
c1.metric("Vulnerabilities caught", m["total_findings"])
c2.metric("Reviewer-time saved (min)", f"{m['time_saved_minutes']:.0f}")
c3.metric("Scans run", m["total_scans"])
c4.metric("Lines reviewed", m["total_lines_reviewed"])

# --- Lead with the takeaway, not the chart (SWD step 5: tell a story) ---
sev = {k: v for k, v in m["findings_by_severity"].items() if v > 0}
high_sev = sev.get("critical", 0) + sev.get("high", 0)

if m["total_findings"]:
    st.markdown(
        f"**Across {m['total_scans']} scan(s), the reviewer caught "
        f"{m['total_findings']} vulnerabilities — {high_sev} high or critical — "
        f"saving an estimated {m['time_saved_minutes']:.0f} minutes of manual review.**"
    )

st.caption(
    "Time saved = vulnerabilities caught × an assumed manual-triage time per "
    "finding (configurable via MINS_PER_FINDING). Finding counts are real data."
)

if not m["total_findings"]:
    st.info("No findings yet — run a scan on the Review page to populate these metrics.")
    st.stop()

left, right = st.columns(2)

# --- Findings by severity: highlight high/critical, mute the rest (SWD step 4) ---
with left:
    sev_df = pd.DataFrame({"severity": list(sev.keys()), "count": list(sev.values())})
    sev_chart = alt.Chart(sev_df).mark_bar(size=46).encode(
        x=alt.X("severity:N", sort=SEVERITY_ORDER, title=None, axis=alt.Axis(labelAngle=0)),
        y=alt.Y("count:Q", title="Findings"),
        color=alt.condition(
            alt.FieldOneOfPredicate(field="severity", oneOf=["critical", "high"]),
            alt.value(ACCENT),
            alt.value(GREY),
        ),
    ).properties(title="High & critical issues are where to focus", height=300)
    st.altair_chart(style(sev_chart), use_container_width=True)

# --- Findings by type: rank by frequency, highlight the most common (SWD step 4) ---
with right:
    by_type = m["findings_by_type"]
    type_df = pd.DataFrame(
        {"type": list(by_type.keys()), "count": list(by_type.values())}
    ).sort_values("count", ascending=False)
    top_type = str(type_df.iloc[0]["type"])
    type_chart = alt.Chart(type_df).mark_bar(size=22).encode(
        y=alt.Y("type:N", sort="-x", title=None),
        x=alt.X("count:Q", title="Findings"),
        color=alt.condition(
            alt.FieldEqualPredicate(field="type", equal=top_type),
            alt.value(ACCENT),
            alt.value(GREY),
        ),
    ).properties(title="Most common vulnerability types", height=300)
    st.altair_chart(style(type_chart), use_container_width=True)

# --- Risk trend: change over time, latest points accented (SWD steps 2 & 4) ---
trend = m["risk_trend"]
if len(trend) > 1:
    trend_df = pd.DataFrame(trend)
    line = alt.Chart(trend_df).mark_line(
        color=LINE, point=alt.OverlayMarkDef(color=ACCENT, size=60)
    ).encode(
        x=alt.X("scan_id:O", title="Scan"),
        y=alt.Y("risk_score:Q", title="Risk score", scale=alt.Scale(domain=[0, 100])),
    ).properties(title="Risk score across scans", height=300)
    st.altair_chart(style(line), use_container_width=True)
else:
    st.caption("Run more scans to see the risk-score trend over time.")
