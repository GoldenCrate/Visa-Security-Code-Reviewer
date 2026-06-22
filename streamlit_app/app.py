import streamlit as st

from streamlit_app.api_client import submit_scan

st.set_page_config(page_title="AI Security Code Reviewer", page_icon="🛡️", layout="wide")

st.title("🛡️ AI Security Code Reviewer")
st.caption("Paste or upload code; an LLM reviews it for security vulnerabilities.")

SEVERITY_COLORS = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵",
}

language = st.selectbox("Language", ["python", "java", "javascript", "sql", "go"])

tab_paste, tab_upload = st.tabs(["Paste code", "Upload file"])
code = ""
source = "paste"

with tab_paste:
    pasted = st.text_area("Code", height=260, placeholder="Paste code here...")
    if pasted:
        code = pasted
        source = "paste"

with tab_upload:
    uploaded = st.file_uploader("Source file", type=["py", "java", "js", "sql", "go", "txt"])
    if uploaded is not None:
        code = uploaded.read().decode("utf-8", errors="replace")
        source = "upload"
        st.code(code, language=language)

if st.button("Review code", type="primary", disabled=not code):
    with st.spinner("Reviewing with Claude..."):
        try:
            result = submit_scan(code, language, source)
        except Exception as exc:  # surface API/connection errors to the user
            st.error(f"Review failed: {exc}")
        else:
            st.metric("Risk score", f"{result['risk_score']:.0f} / 100")
            findings = result["findings"]
            if not findings:
                st.success("No vulnerabilities found.")
            for f in findings:
                icon = SEVERITY_COLORS.get(f["severity"], "⚪")
                with st.expander(
                    f"{icon} {f['severity'].upper()} — {f['vuln_type']} "
                    f"(lines {f['line_start']}-{f['line_end']})"
                ):
                    st.write(f["description"])
                    st.markdown("**Suggested fix:**")
                    st.write(f["suggested_fix"])
