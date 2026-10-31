"""
LinkShield - AI-Powered Universal URL Threat Detection and Security Analyzer
Main Application Entry Point (Cybersecurity SaaS Architecture)
"""

import os
import json
import streamlit as st
import pandas as pd
import plotly.express as px
from url_validator import validate_url
from risk_engine import RiskEngine
from history_manager import HistoryManager
from ui_components import (
    apply_saas_theme,
    render_page_header,
    render_saas_gauge,
    get_risk_pill_html
)

# Set page config once at top-level
st.set_page_config(
    page_title="LinkShield | Enterprise Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply CSS SaaS theme
apply_saas_theme()

# Initialize singletons in session state
if "risk_engine" not in st.session_state:
    st.session_state.risk_engine = RiskEngine()
if "history_mgr" not in st.session_state:
    st.session_state.history_mgr = HistoryManager()
if "current_nav" not in st.session_state:
    st.session_state.current_nav = "Overview"

# Clean Single Navigation System
st.sidebar.markdown("""
<div style="padding: 0.5rem 0.25rem 1rem 0.25rem;">
    <div style="font-size: 1.15rem; font-weight: 700; color: #f8fafc; letter-spacing: -0.02em;">
        🛡️ LinkShield
    </div>
    <div style="font-size: 0.75rem; color: #64748b; font-weight: 500;">
        Enterprise URL Threat Defense
    </div>
</div>
""", unsafe_allow_html=True)

nav_options = [
    "Overview",
    "URL Scanner",
    "Bulk Scanner",
    "QR Scanner",
    "Analytics Dashboard",
    "Scan History",
    "About"
]

# Ensure session_state index alignment
nav_index = nav_options.index(st.session_state.current_nav) if st.session_state.current_nav in nav_options else 0

selected_nav = st.sidebar.radio(
    "NAVIGATION",
    nav_options,
    index=nav_index,
    key="app_main_navigation",
    label_visibility="collapsed"
)

# Sync navigation state
if selected_nav != st.session_state.current_nav:
    st.session_state.current_nav = selected_nav
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("""
<div style="padding: 0.25rem; font-size: 0.72rem; color: #64748b; line-height: 1.5;">
    <div><strong>Engine Status:</strong> <span style="color: #34d399;">Active</span></div>
    <div><strong>Model:</strong> Tuned Random Forest</div>
    <div><strong>Security Policy:</strong> Strict SSRF Guard</div>
</div>
""", unsafe_allow_html=True)

# Navigation Routing
if st.session_state.current_nav == "Overview":
    render_page_header(
        title="Security Operations Overview",
        subtitle="Universal AI-powered threat detection, heuristic decomposition, and multi-feed threat correlation.",
        badge_text="Security Intelligence Platform"
    )

    history_mgr = st.session_state.history_mgr
    stats = history_mgr.get_summary_statistics()

    # Telemetry KPI row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="saas-card">
            <div class="saas-metric-title">Total URLs Audited</div>
            <div class="saas-metric-value">{stats['total_scans']}</div>
            <div class="saas-metric-sub">Session and persistent logs</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="saas-card">
            <div class="saas-metric-title">Threats Intercepted</div>
            <div class="saas-metric-value" style="color: #f87171;">{stats['threats_detected']}</div>
            <div class="saas-metric-sub">High & Critical risks confirmed</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="saas-card">
            <div class="saas-metric-title">Average Risk Score</div>
            <div class="saas-metric-value" style="color: #facc15;">{stats['avg_risk_score']}<span style="font-size: 1rem; color: #64748b;">/100</span></div>
            <div class="saas-metric-sub">Across all audited URLs</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown("""
        <div class="saas-card">
            <div class="saas-metric-title">AI Engine Accuracy</div>
            <div class="saas-metric-value" style="color: #38bdf8;">97.5%</div>
            <div class="saas-metric-sub">5-fold cross-validated</div>
        </div>
        """, unsafe_allow_html=True)

    # Quick Scan Input Card
    st.markdown('<div class="saas-card">', unsafe_allow_html=True)
    st.markdown("<div class='saas-metric-title'>Quick URL Security Check</div>", unsafe_allow_html=True)
    c_input, c_btn = st.columns([5, 1])
    with c_input:
        quick_target = st.text_input(
            "Quick URL Input",
            placeholder="Enter URL to evaluate (e.g. https://example.com or suspicious links)",
            label_visibility="collapsed"
        )
    with c_btn:
        quick_scan_exec = st.button("Analyze URL", type="primary", use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

    if quick_scan_exec and quick_target:
        is_valid, msg, norm_url = validate_url(quick_target)
        if not is_valid:
            st.error(f"Input Validation: {msg}")
        else:
            with st.spinner("Analyzing lexical vectors and cross-referencing threat feeds..."):
                rep = st.session_state.risk_engine.analyze_url(norm_url)
                st.session_state.history_mgr.save_scan(rep)

            st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
            c_g, c_d = st.columns([1, 1])
            with c_g:
                st.markdown('<div class="saas-card" style="padding: 0.75rem;">', unsafe_allow_html=True)
                st.plotly_chart(render_saas_gauge(rep["risk_score"], rep["classification"]), use_container_width=True)
                st.markdown('</div>', unsafe_allow_html=True)
            with c_d:
                pill = get_risk_pill_html(rep["classification"])
                st.markdown(f"""
                <div class="saas-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <span style="font-size: 0.75rem; font-weight: 600; color: #94a3b8; text-transform: uppercase;">Verdict</span>
                        {pill}
                    </div>
                    <div class="code-box" style="margin-bottom: 0.75rem;">{rep['url']}</div>
                    <div style="font-size: 0.82rem; color: #94a3b8;">
                        <div><strong>ML Assessment:</strong> {rep['ml_prediction']} ({rep['ml_confidence']}%)</div>
                        <div><strong>Key Finding:</strong> {rep['risk_factors'][0] if rep.get('risk_factors') else 'Standard baseline'}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

    # Activity & Distribution Grid
    col_hist, col_chart = st.columns([1.3, 1])

    with col_hist:
        st.markdown('<div class="saas-card">', unsafe_allow_html=True)
        st.markdown("<div class='saas-metric-title'>Recent Scan Activity</div>", unsafe_allow_html=True)
        recent_records = history_mgr.load_history()[:5]
        if recent_records:
            recent_table = []
            for r in recent_records:
                recent_table.append({
                    "Timestamp": r.get("timestamp", ""),
                    "Target URL": r.get("url", "")[:45] + "...",
                    "Score": f"{r.get('risk_score', 0)}/100",
                    "Classification": r.get("classification", "")
                })
            st.dataframe(pd.DataFrame(recent_table), use_container_width=True, hide_index=True)
        else:
            st.info("No prior scan records found. Run a scan above to start logging activity.")
        st.markdown('</div>', unsafe_allow_html=True)

    with col_chart:
        st.markdown('<div class="saas-card">', unsafe_allow_html=True)
        st.markdown("<div class='saas-metric-title'>Threat Level Breakdown</div>", unsafe_allow_html=True)
        cls_counts = stats["classifications"]
        if sum(cls_counts.values()) > 0:
            df_pie = pd.DataFrame(list(cls_counts.items()), columns=["Category", "Count"])
            fig_p = px.pie(
                df_pie,
                names="Category",
                values="Count",
                color="Category",
                color_discrete_map={
                    "Low Risk": "#10b981",
                    "Moderate Risk": "#eab308",
                    "High Risk": "#f97316",
                    "Critical Risk": "#ef4444",
                    "Inconclusive": "#64748b"
                },
                hole=0.45
            )
            fig_p.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={'color': '#94a3b8', 'family': 'Inter'},
                margin=dict(l=10, r=10, t=10, b=10),
                legend=dict(orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_p, use_container_width=True)
        else:
            st.info("Awaiting initial scans to display telemetry chart.")
        st.markdown('</div>', unsafe_allow_html=True)

    # Quick Navigation to Modules
    st.markdown('<div class="saas-card">', unsafe_allow_html=True)
    st.markdown("<div class='saas-metric-title'>Security Modules Shortcut</div>", unsafe_allow_html=True)
    btn_c1, btn_c2, btn_c3, btn_c4 = st.columns(4)
    with btn_c1:
        if st.button("Deep URL Scanner", use_container_width=True):
            st.session_state.current_nav = "URL Scanner"
            st.rerun()
    with btn_c2:
        if st.button("Bulk List Scanner", use_container_width=True):
            st.session_state.current_nav = "Bulk Scanner"
            st.rerun()
    with btn_c3:
        if st.button("Anti-Quishing QR", use_container_width=True):
            st.session_state.current_nav = "QR Scanner"
            st.rerun()
    with btn_c4:
        if st.button("Analytics & Benchmarks", use_container_width=True):
            st.session_state.current_nav = "Analytics Dashboard"
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

elif st.session_state.current_nav == "URL Scanner":
    import src_pages.url_scanner as p_url
    p_url.show()

elif st.session_state.current_nav == "Bulk Scanner":
    import src_pages.bulk_scanner as p_bulk
    p_bulk.show()

elif st.session_state.current_nav == "QR Scanner":
    import src_pages.qr_scanner as p_qr
    p_qr.show()

elif st.session_state.current_nav == "Analytics Dashboard":
    import src_pages.dashboard as p_dash
    p_dash.show()

elif st.session_state.current_nav == "Scan History":
    import src_pages.scan_history as p_hist
    p_hist.show()

elif st.session_state.current_nav == "About":
    import src_pages.about as p_about
    p_about.show()
