"""
LinkShield - Scan History Subpage (SaaS Redesign)
"""

import streamlit as st
import pandas as pd
from ui_components import render_page_header

def show():
    render_page_header(
        title="Audit Logs & Scan History",
        subtitle="Search, filter, and export persistent records of analyzed URLs and security threat classifications.",
        badge_text="Audit Records"
    )

    history_mgr = st.session_state.history_mgr

    # Filter controls
    st.markdown('<div class="saas-card">', unsafe_allow_html=True)
    c1, c2, c3 = st.columns([3, 2, 1])
    with c1:
        search_kw = st.text_input("Filter by URL or Domain Keyword:", placeholder="e.g. paypal, account, github")
    with c2:
        class_filter = st.selectbox(
            "Classification Filter:",
            ["All", "Critical Risk", "High Risk", "Moderate Risk", "Low Risk", "Inconclusive"]
        )
    with c3:
        st.markdown("<div style='margin-top: 1.75rem;'></div>", unsafe_allow_html=True)
        if st.button("Clear Logs", type="secondary", use_container_width=True):
            history_mgr.clear_history()
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

    filtered = history_mgr.filter_history(search_query=search_kw, classification=class_filter)

    if not filtered:
        st.info("No matching records found in persistent scan log.")
        return

    table_data = []
    for r in filtered:
        reasons = r.get("risk_factors", [])
        primary_reason = reasons[0] if reasons else "No anomalous signals flagged"
        table_data.append({
            "Scan ID": r.get("id"),
            "Timestamp": r.get("timestamp"),
            "Target URL": r.get("url"),
            "Risk Score": f"{r.get('risk_score')}/100",
            "Classification": r.get("classification"),
            "ML Verdict": r.get("ml_prediction"),
            "Primary Finding": primary_reason
        })

    df_view = pd.DataFrame(table_data)
    st.dataframe(df_view, use_container_width=True, hide_index=True)

    csv_bytes = df_view.to_csv(index=False).encode('utf-8')
    st.download_button(
        "Export History to CSV",
        data=csv_bytes,
        file_name="linkshield_audit_history.csv",
        mime="text/csv"
    )
