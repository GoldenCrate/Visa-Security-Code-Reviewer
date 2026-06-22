import altair as alt
import pandas as pd
import streamlit as st

from streamlit_app.api_client import get_metrics

st.set_page_config(page_title="Productivity Metrics", page_icon="📊", layout="wide")

st.title("📊 Productivity Metrics")

try:
    m = get_metrics()
except Exception as exc:
    st.error(f"Could not load metrics: {exc}")
    st.stop()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total scans", m["total_scans"])
c2.metric("Vulnerabilities caught", m["total_findings"])
c3.metric("Reviewer-time saved (min)", f"{m['time_saved_minutes']:.0f}")
c4.metric("Lines reviewed", m["total_lines_reviewed"])

st.caption(
    "Time saved = vulnerabilities caught × an assumed manual-triage time per "
    "finding (configurable via MINS_PER_FINDING). Finding counts are real data."
)

st.subheader("Findings by severity")
sev = m["findings_by_severity"]
if sev:
    sev_df = pd.DataFrame({"severity": list(sev.keys()), "count": list(sev.values())})
    st.altair_chart(
        alt.Chart(sev_df).mark_bar().encode(x="severity", y="count", color="severity"),
        use_container_width=True,
    )
else:
    st.info("No findings yet — run a scan on the Review page.")

st.subheader("Findings by type")
by_type = m["findings_by_type"]
if by_type:
    type_df = pd.DataFrame({"type": list(by_type.keys()), "count": list(by_type.values())})
    st.altair_chart(
        alt.Chart(type_df).mark_bar().encode(x="count", y=alt.Y("type", sort="-x")),
        use_container_width=True,
    )

st.subheader("Risk trend")
trend = m["risk_trend"]
if trend:
    trend_df = pd.DataFrame(trend)
    st.altair_chart(
        alt.Chart(trend_df).mark_line(point=True).encode(
            x="scan_id:O", y="risk_score:Q"
        ),
        use_container_width=True,
    )
