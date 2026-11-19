"""
LinkShield - URL Threat Scanner Subpage (SaaS Redesign)
"""

import streamlit as st
import pandas as pd
from url_validator import validate_url
from ui_components import render_page_header, render_saas_gauge, get_risk_pill_html

def show():
    render_page_header(
        title="Deep URL Threat Scanner",
        subtitle="Multi-vector URL inspection combining trained ML heuristics, VirusTotal, Google Safe Browsing, PhishTank, and TLS verification.",
        badge_text="Real-time Threat Engine"
    )

    with st.container():
        st.markdown("""
        <div style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.5rem; font-weight: 500;">
            Target URL or Hostname
        </div>
        """, unsafe_allow_html=True)
        
        c_in, c_btn = st.columns([5, 1])
        with c_in:
            target_url = st.text_input(
                "Target URL or Hostname",
                placeholder="https://secure-login.example.com/account/auth",
                label_visibility="collapsed"
            )
        with c_btn:
            scan_clicked = st.button("Analyze Threat", type="primary", use_container_width=True)

    if scan_clicked and target_url:
        is_valid, msg, norm_url = validate_url(target_url)
        if not is_valid:
            st.error(f"Validation Error: {msg}")
            return

        with st.spinner("Executing URL lexical feature extraction and querying threat databases..."):
            engine = st.session_state.risk_engine
            report = engine.analyze_url(norm_url)
            st.session_state.history_mgr.save_scan(report)

        st.markdown("<div style='margin-top: 1.5rem;'></div>", unsafe_allow_html=True)

        # Overview grid
        col_gauge, col_details = st.columns([1, 1])
        
        with col_gauge:
            st.markdown('<div class="saas-card" style="padding: 1rem;">', unsafe_allow_html=True)
            st.plotly_chart(render_saas_gauge(report["risk_score"], report["classification"]), use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_details:
            pill_html = get_risk_pill_html(report["classification"])
            vt = report.get("vt_stats", {})
            gsb = report.get("gsb_status", {})
            pt = report.get("phishtank_status", {})
            
            st.markdown(f"""
            <div class="saas-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                    <span style="font-size: 0.78rem; font-weight: 600; text-transform: uppercase; color: #94a3b8;">Threat Verdict</span>
                    {pill_html}
                </div>
                <div style="margin-bottom: 0.75rem;">
                    <div style="font-size: 0.75rem; color: #64748b; margin-bottom: 0.2rem;">Target URL</div>
                    <div class="code-box">{report['url']}</div>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-top: 0.75rem;">
                    <div>
                        <div style="font-size: 0.75rem; color: #64748b;">ML Model Assessment</div>
                        <div style="font-weight: 600; font-size: 0.9rem; color: #f8fafc;">{report['ml_prediction']}</div>
                        <div style="font-size: 0.75rem; color: #94a3b8;">{report['ml_confidence']}% confidence</div>
                    </div>
                    <div>
                        <div style="font-size: 0.75rem; color: #64748b;">VirusTotal Engines</div>
                        <div style="font-weight: 600; font-size: 0.9rem; color: {'#ef4444' if vt.get('malicious',0) > 0 else '#10b981'};">
                            {vt.get('malicious', 0)} Flags
                        </div>
                        <div style="font-size: 0.75rem; color: #94a3b8;">Status: {vt.get('status', 'N/A')}</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Tabs for deep forensic insights
        t1, t2, t3 = st.tabs(["Threat Indicators & Reasoning", "Extracted Lexical Features", "SSL / TLS Certificate"])

        with t1:
            st.markdown('<div class="saas-card">', unsafe_allow_html=True)
            st.markdown("##### Detected Risk Factors & Anomaly Indicators")
            for rf in report["risk_factors"]:
                st.markdown(f"<div style='margin-bottom: 0.4rem; font-size: 0.88rem; color: #fca5a5;'>- ⚠️ {rf}</div>", unsafe_allow_html=True)
            
            if report.get("positive_indicators"):
                st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
                st.markdown("##### Positive Trust Factors")
                for pi in report["positive_indicators"]:
                    st.markdown(f"<div style='margin-bottom: 0.4rem; font-size: 0.88rem; color: #86efac;'>- ✅ {pi}</div>", unsafe_allow_html=True)
            
            st.markdown("""
            <div style="margin-top: 1.25rem; padding: 0.75rem; background: rgba(30, 41, 59, 0.4); border-radius: 6px; font-size: 0.8rem; color: #94a3b8;">
                <strong>Enterprise Policy Invariant:</strong> LinkShield never declares a URL completely benign solely because blacklists report clean. A minimal baseline uncertainty threshold is maintained.
            </div>
            """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with t2:
            st.markdown('<div class="saas-card">', unsafe_allow_html=True)
            st.markdown("##### 24 Real Computable Lexical Features")
            feats = report["features"]
            feat_df = pd.DataFrame(list(feats.items()), columns=["Feature Name", "Extracted Value"])
            st.dataframe(feat_df, use_container_width=True, hide_index=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with t3:
            st.markdown('<div class="saas-card">', unsafe_allow_html=True)
            st.markdown("##### Cryptographic TLS Identity Inspection")
            ssl_info = report.get("ssl_info", {})
            st.json(ssl_info)
            st.markdown('</div>', unsafe_allow_html=True)
