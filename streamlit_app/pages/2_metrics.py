import altair as alt
import pandas as pd
import streamlit as st

from streamlit_app.api_client import get_metrics

st.set_page_config(page_title="Productivity Metrics", page_icon="📊", layout="wide")

# --- Storytelling with Data palette ---
# Mute everything to grey; spend colour sparingly on what demands attention.
GREY = "#bfbfbf"
ACCENT = "#c00000"   # reserved for the elements we want the eye drawn to
TEXT = "#595959"
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def declutter(chart):
    """Strip chart junk (SWD step 3): no border, no gridlines, soft axes."""
    return (
        chart.configure_view(stroke=None)
        .configure_axis(
            grid=False,
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
    base = alt.Chart(sev_df).encode(
        x=alt.X("severity:N", sort=SEVERITY_ORDER, title=None, axis=alt.Axis(labelAngle=0)),
        y=alt.Y("count:Q", title=None, axis=None),
    )
    bars = base.mark_bar(size=46).encode(
        color=alt.condition(
            alt.FieldOneOfPredicate(field="severity", oneOf=["critical", "high"]),
            alt.value(ACCENT),
            alt.value(GREY),
        )
    )
    labels = base.mark_text(dy=-7, color=TEXT, fontSize=13).encode(text="count:Q")
    st.altair_chart(
        declutter(
            (bars + labels).properties(
                title="High & critical issues are where to focus", height=300
            )
        ),
        use_container_width=True,
    )

# --- Findings by type: rank by frequency, highlight the most common (SWD step 4) ---
with right:
    by_type = m["findings_by_type"]
    type_df = pd.DataFrame(
        {"type": list(by_type.keys()), "count": list(by_type.values())}
    ).sort_values("count", ascending=False)
    top_type = str(type_df.iloc[0]["type"])
    base_t = alt.Chart(type_df).encode(
        y=alt.Y("type:N", sort="-x", title=None),
        x=alt.X("count:Q", title=None, axis=None),
    )
    bars_t = base_t.mark_bar(size=22).encode(
        color=alt.condition(
            alt.FieldEqualPredicate(field="type", equal=top_type),
            alt.value(ACCENT),
            alt.value(GREY),
        )
    )
    labels_t = base_t.mark_text(dx=8, align="left", color=TEXT, fontSize=13).encode(
        text="count:Q"
    )
    st.altair_chart(
        declutter(
            (bars_t + labels_t).properties(
                title="Most common vulnerability types", height=300
            )
        ),
        use_container_width=True,
    )

# --- Risk trend: change over time, latest point accented (SWD steps 2 & 4) ---
trend = m["risk_trend"]
if len(trend) > 1:
    trend_df = pd.DataFrame(trend)
    line = alt.Chart(trend_df).mark_line(
        color=GREY, point=alt.OverlayMarkDef(color=ACCENT, size=60)
    ).encode(
        x=alt.X("scan_id:O", title="Scan"),
        y=alt.Y("risk_score:Q", title="Risk score"),
    )
    st.altair_chart(
        declutter(line.properties(title="Risk score across scans", height=280)),
        use_container_width=True,
    )
else:
    st.caption("Run more scans to see the risk-score trend over time.")
