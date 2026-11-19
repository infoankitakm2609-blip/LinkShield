"""
LinkShield - Analytics Dashboard Subpage (SaaS Redesign)
"""

import os
import json
import streamlit as st
import pandas as pd
import plotly.express as px
from ui_components import render_page_header

METRICS_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "model_metrics.json")

def show():
    render_page_header(
        title="Security Analytics & Model Benchmarks",
        subtitle="Operational telemetry, threat category distribution, and audited machine learning evaluations.",
        badge_text="Intelligence Telemetry"
    )

    history_mgr = st.session_state.history_mgr
    stats = history_mgr.get_summary_statistics()

    # Metric summary row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
        <div class="saas-card">
            <div class="saas-metric-title">Cumulative Scans</div>
            <div class="saas-metric-value">{stats['total_scans']}</div>
            <div class="saas-metric-sub">Session & saved records</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="saas-card">
            <div class="saas-metric-title">Threats Flagged</div>
            <div class="saas-metric-value" style="color: #f87171;">{stats['threats_detected']}</div>
            <div class="saas-metric-sub">High & Critical risks</div>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="saas-card">
            <div class="saas-metric-title">Mean Risk Index</div>
            <div class="saas-metric-value" style="color: #facc15;">{stats['avg_risk_score']}<span style="font-size: 1rem; color: #64748b;">/100</span></div>
            <div class="saas-metric-sub">Across all scan history</div>
        </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown("""
        <div class="saas-card">
            <div class="saas-metric-title">Production Model</div>
            <div class="saas-metric-value" style="font-size: 1.25rem; color: #38bdf8;">Random Forest</div>
            <div class="saas-metric-sub">Tuned & regularized</div>
        </div>
        """, unsafe_allow_html=True)

    # Visualization row
    col_pie, col_bar = st.columns([1, 1.2])

    with col_pie:
        st.markdown('<div class="saas-card">', unsafe_allow_html=True)
        st.markdown("<div class='saas-metric-title'>Historical Threat Breakdown</div>", unsafe_allow_html=True)
        cls_data = stats["classifications"]
        if sum(cls_data.values()) > 0:
            df_cls = pd.DataFrame(list(cls_data.items()), columns=["Category", "Count"])
            fig_pie = px.pie(
                df_cls,
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
                hole=0.48
            )
            fig_pie.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={'color': '#94a3b8', 'family': 'Inter'},
                margin=dict(l=10, r=10, t=10, b=10),
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No scan records available yet. Execute scans to populate distribution.")
        st.markdown('</div>', unsafe_allow_html=True)

    with col_bar:
        st.markdown('<div class="saas-card">', unsafe_allow_html=True)
        st.markdown("<div class='saas-metric-title'>Stratified 5-Fold Cross-Validation Benchmark</div>", unsafe_allow_html=True)
        if os.path.exists(METRICS_PATH):
            with open(METRICS_PATH, "r", encoding="utf-8") as f:
                metrics_data = json.load(f)
            cv_comp = metrics_data.get("cv_5fold_comparison", {})
            
            rows = []
            for m_name, vals in cv_comp.items():
                rows.append({
                    "Model": m_name,
                    "Accuracy": vals.get("accuracy", 0),
                    "Precision": vals.get("precision", 0),
                    "Recall": vals.get("recall", 0),
                    "F1-Score": vals.get("f1_score", 0)
                })
            
            if rows:
                df_bench = pd.DataFrame(rows)
                fig_bar = px.bar(
                    df_bench,
                    x="Model",
                    y=["Accuracy", "Precision", "Recall", "F1-Score"],
                    barmode="group",
                    color_discrete_sequence=["#0284c7", "#38bdf8", "#818cf8", "#34d399"]
                )
                fig_bar.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font={'color': '#94a3b8', 'family': 'Inter'},
                    margin=dict(l=10, r=10, t=20, b=10),
                    legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5),
                    yaxis=dict(range=[0.9, 1.0], gridcolor="#1e293b")
                )
                st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("Model evaluation telemetry file not found.")
        st.markdown('</div>', unsafe_allow_html=True)
