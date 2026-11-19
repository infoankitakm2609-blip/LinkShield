"""
LinkShield - About Subpage (SaaS Redesign)
"""

import streamlit as st
from ui_components import render_page_header

def show():
    render_page_header(
        title="Platform Architecture & Specifications",
        subtitle="Technical documentation, security invariants, data sources, and machine learning methodologies powering LinkShield.",
        badge_text="System Architecture"
    )

    c1, c2 = st.columns([1, 1])

    with c1:
        st.markdown("""
        <div class="saas-card">
            <div class="saas-metric-title">Machine Learning Engine</div>
            <div style="font-size: 0.9rem; color: #cbd5e1; line-height: 1.6; margin-top: 0.5rem;">
                <p>LinkShield utilizes an ensemble Random Forest classifier trained on the <strong>UCI PhiUSIIL Phishing URL Dataset</strong>, audited to eliminate duplicate feature leakage.</p>
                <ul>
                    <li><strong>Features:</strong> 24 purely lexical and structural vectors (Shannon entropy, digit ratios, subdomain nesting, special character distributions).</li>
                    <li><strong>Regularization:</strong> Constrained tree depth, leaf sample boundaries, and feature subsampling to prevent leaf memorization.</li>
                    <li><strong>Validation:</strong> Stratified 5-Fold cross-validation with isolated preprocessing pipelines.</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="saas-card">
            <div class="saas-metric-title">Network & SSRF Safeguards</div>
            <div style="font-size: 0.9rem; color: #cbd5e1; line-height: 1.6; margin-top: 0.5rem;">
                <p>LinkShield incorporates strict SSRF defenses to protect application servers:</p>
                <ul>
                    <li>Rejects loopback (<code>127.0.0.0/8</code>, <code>::1</code>) and internal hostnames (<code>localhost</code>).</li>
                    <li>Blocks RFC 1918 private subnets (<code>10.0.0.0/8</code>, <code>172.16.0.0/12</code>, <code>192.168.0.0/16</code>).</li>
                    <li>Intercepts cloud instance metadata endpoints (<code>169.254.169.254</code>).</li>
                    <li>Never automatically follows HTTP redirects or executes remote client-side scripts.</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown("""
        <div class="saas-card">
            <div class="saas-metric-title">External Threat Intelligence Feeds</div>
            <div style="font-size: 0.9rem; color: #cbd5e1; line-height: 1.6; margin-top: 0.5rem;">
                <p>To supplement local ML heuristics, LinkShield interfaces with premier global threat feeds:</p>
                <ul>
                    <li><strong>VirusTotal v3 API:</strong> Queries 70+ antivirus and URL reputation scanners via SHA-256 base64 URL identifiers.</li>
                    <li><strong>Google Safe Browsing v4:</strong> Real-time lookup for malware, social engineering, and potentially harmful applications.</li>
                    <li><strong>PhishTank Community Feed:</strong> Active verified crowd-sourced phishing database checks.</li>
                    <li><strong>Cryptographic TLS Verification:</strong> Direct socket handshake to examine certificate issuers and expiration without rendering content.</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="saas-card">
            <div class="saas-metric-title">Technology Stack</div>
            <div style="font-size: 0.88rem; color: #cbd5e1; line-height: 1.6; margin-top: 0.5rem;">
                <table style="width: 100%; border-collapse: collapse; font-size: 0.82rem;">
                    <tr style="border-bottom: 1px solid #1e293b;">
                        <td style="padding: 0.35rem 0; color: #64748b;">Framework</td>
                        <td style="padding: 0.35rem 0; color: #f1f5f9; text-align: right;">Streamlit (Python 3.12)</td>
                    </tr>
                    <tr style="border-bottom: 1px solid #1e293b;">
                        <td style="padding: 0.35rem 0; color: #64748b;">Machine Learning</td>
                        <td style="padding: 0.35rem 0; color: #f1f5f9; text-align: right;">Scikit-learn, XGBoost, Joblib</td>
                    </tr>
                    <tr style="border-bottom: 1px solid #1e293b;">
                        <td style="padding: 0.35rem 0; color: #64748b;">Data Engine</td>
                        <td style="padding: 0.35rem 0; color: #f1f5f9; text-align: right;">Pandas, NumPy</td>
                    </tr>
                    <tr style="border-bottom: 1px solid #1e293b;">
                        <td style="padding: 0.35rem 0; color: #64748b;">Visualizations</td>
                        <td style="padding: 0.35rem 0; color: #f1f5f9; text-align: right;">Plotly Interactive Engine</td>
                    </tr>
                    <tr>
                        <td style="padding: 0.35rem 0; color: #64748b;">Storage</td>
                        <td style="padding: 0.35rem 0; color: #f1f5f9; text-align: right;">Database-free JSON & Synced CSV</td>
                    </tr>
                </table>
            </div>
        </div>
        """, unsafe_allow_html=True)
