"""
LinkShield - Bulk Threat Scanner Subpage (SaaS Redesign)
"""

import streamlit as st
import pandas as pd
from url_validator import validate_url
from ui_components import render_page_header

def show():
    render_page_header(
        title="High-Throughput Bulk Scanner",
        subtitle="Batch evaluate enterprise lists of URLs from threat feeds, SIEM logs, or inbound communications.",
        badge_text="Batch Operations"
    )

    st.markdown('<div class="saas-card">', unsafe_allow_html=True)
    c1, c2 = st.columns([3, 1])
    with c1:
        uploaded_file = st.file_uploader(
            "Upload CSV file containing a list of target URLs:",
            type=["csv"],
            help="Upload a CSV with a column named 'url', 'link', or containing URL strings."
        )
    with c2:
        sample_csv = "url\nhttps://google.com\nhttp://192.168.1.1/update-account-bank\nhttps://github.com\nhttp://bit.ly/fake-login-verify\n"
        st.markdown("<div style='margin-top: 1.75rem;'></div>", unsafe_allow_html=True)
        st.download_button(
            "Download CSV Template",
            data=sample_csv,
            file_name="linkshield_bulk_template.csv",
            mime="text/csv",
            use_container_width=True
        )
    st.markdown('</div>', unsafe_allow_html=True)

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.markdown(f"<div style='font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.5rem;'>Loaded file with <strong>{len(df)}</strong> rows.</div>", unsafe_allow_html=True)

            url_col = None
            for col in df.columns:
                if "url" in col.lower() or "link" in col.lower():
                    url_col = col
                    break
            
            if not url_col:
                url_col = df.columns[0]
                st.warning(f"No column with 'url' found. Evaluating first column: '{url_col}'")

            if st.button("Start Batch Assessment", type="primary"):
                urls = df[url_col].dropna().tolist()
                progress_bar = st.progress(0)
                status_text = st.empty()

                engine = st.session_state.risk_engine
                results = []

                for idx, u in enumerate(urls):
                    u_str = str(u).strip()
                    status_text.markdown(f"<span style='font-size: 0.85rem; color: #94a3b8;'>Scanning ({idx + 1}/{len(urls)}): <code>{u_str[:45]}</code></span>", unsafe_allow_html=True)
                    
                    is_valid, msg, norm_url = validate_url(u_str)
                    if not is_valid:
                        results.append({
                            "URL": u_str,
                            "Risk Score": 0,
                            "Classification": "Invalid / SSRF Blocked",
                            "ML Assessment": "N/A",
                            "Primary Reason": msg
                        })
                    else:
                        rep = engine.analyze_url(norm_url)
                        st.session_state.history_mgr.save_scan(rep)
                        results.append({
                            "URL": rep["url"],
                            "Risk Score": rep["risk_score"],
                            "Classification": rep["classification"],
                            "ML Assessment": rep["ml_prediction"],
                            "Primary Reason": rep["risk_factors"][0] if rep.get("risk_factors") else "Standard Profile"
                        })
                    progress_bar.progress((idx + 1) / len(urls))

                status_text.empty()
                st.success(f"Batch processing completed for {len(results)} items.")

                res_df = pd.DataFrame(results)
                st.dataframe(res_df, use_container_width=True, hide_index=True)

                csv_bytes = res_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "Export Full Batch Report (CSV)",
                    data=csv_bytes,
                    file_name="linkshield_bulk_scan_report.csv",
                    mime="text/csv"
                )

        except Exception as e:
            st.error(f"Error parsing CSV file: {e}")
