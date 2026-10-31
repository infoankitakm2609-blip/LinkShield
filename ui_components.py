"""
UI Styling and Reusable Components for LinkShield
Professional Cybersecurity SaaS Theme: Dark Navy (#0a0f1d), Charcoal (#111827),
Subtle Slate Blue (#1e293b), Muted Gray typography (#94a3b8), and Cyan accents (#06b6d4, #0284c7).
"""

import streamlit as st
import plotly.graph_objects as go

def apply_saas_theme():
    """Injects refined SaaS CSS stylesheet."""
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

        /* Base app styling */
        .stApp {
            background-color: #080d19;
            color: #f1f5f9;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        /* Sidebar container */
        [data-testid="stSidebar"] {
            background-color: #060a13;
            border-right: 1px solid #1e293b;
        }
        
        [data-testid="stSidebar"] hr {
            margin: 1rem 0;
            border-color: #1e293b;
        }

        /* SaaS Header styles */
        .saas-header {
            margin-bottom: 2rem;
            padding-bottom: 1.25rem;
            border-bottom: 1px solid #1e293b;
        }
        
        .saas-badge {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.75rem;
        }

        .saas-badge-cyan {
            background: rgba(6, 182, 212, 0.12);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.25);
        }

        .saas-title {
            font-size: 1.85rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            color: #f8fafc;
            margin: 0 0 0.5rem 0;
            line-height: 1.2;
        }

        .saas-subtitle {
            font-size: 0.95rem;
            color: #94a3b8;
            line-height: 1.5;
            margin: 0;
        }

        /* SaaS Cards */
        .saas-card {
            background-color: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1rem;
        }

        .saas-card:hover {
            border-color: #334155;
        }

        .saas-metric-title {
            font-size: 0.78rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #94a3b8;
            margin-bottom: 0.35rem;
        }

        .saas-metric-value {
            font-size: 1.75rem;
            font-weight: 700;
            color: #f8fafc;
            line-height: 1.2;
        }

        .saas-metric-sub {
            font-size: 0.75rem;
            color: #64748b;
            margin-top: 0.35rem;
        }

        /* Risk Pill Badges */
        .risk-pill {
            display: inline-block;
            padding: 0.2rem 0.65rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
            letter-spacing: 0.02em;
        }

        .risk-pill-low {
            background-color: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .risk-pill-moderate {
            background-color: rgba(234, 179, 8, 0.15);
            color: #facc15;
            border: 1px solid rgba(234, 179, 8, 0.3);
        }

        .risk-pill-high {
            background-color: rgba(249, 115, 22, 0.15);
            color: #fb923c;
            border: 1px solid rgba(249, 115, 22, 0.3);
        }

        .risk-pill-critical {
            background-color: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .risk-pill-inconclusive {
            background-color: rgba(100, 116, 139, 0.15);
            color: #94a3b8;
            border: 1px solid rgba(100, 116, 139, 0.3);
        }

        /* Input fields and buttons */
        div[data-baseweb="input"] {
            background-color: #0b1120 !important;
            border-color: #1e293b !important;
            border-radius: 6px !important;
        }
        
        div[data-baseweb="input"]:focus-within {
            border-color: #0284c7 !important;
        }

        .stButton>button {
            border-radius: 6px;
            font-weight: 600;
            padding: 0.5rem 1rem;
            transition: all 0.15s ease-in-out;
        }

        .code-box {
            font-family: 'JetBrains Mono', monospace;
            background: #020617;
            padding: 0.5rem 0.75rem;
            border-radius: 4px;
            border: 1px solid #1e293b;
            font-size: 0.82rem;
            color: #38bdf8;
            word-break: break-all;
        }
    </style>
    """, unsafe_allow_html=True)

def render_page_header(title: str, subtitle: str, badge_text: str = "LinkShield Enterprise"):
    """Standardized SaaS page header component."""
    st.markdown(f"""
    <div class="saas-header">
        <span class="saas-badge saas-badge-cyan">{badge_text}</span>
        <h1 class="saas-title">{title}</h1>
        <p class="saas-subtitle">{subtitle}</p>
    </div>
    """, unsafe_allow_html=True)

def get_risk_pill_html(classification: str) -> str:
    """Returns clean SaaS pill HTML for risk classification."""
    cls_lower = classification.lower()
    if "critical" in cls_lower:
        pill_class = "risk-pill-critical"
    elif "high" in cls_lower:
        pill_class = "risk-pill-high"
    elif "moderate" in cls_lower:
        pill_class = "risk-pill-moderate"
    elif "low" in cls_lower:
        pill_class = "risk-pill-low"
    else:
        pill_class = "risk-pill-inconclusive"
    return f'<span class="risk-pill {pill_class}">{classification}</span>'

def render_saas_gauge(score: int, classification: str):
    """Renders professional cybersecurity gauge chart in navy palette."""
    if score >= 75:
        bar_color = "#ef4444"
    elif score >= 50:
        bar_color = "#f97316"
    elif score >= 25:
        bar_color = "#eab308"
    else:
        bar_color = "#10b981"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"Risk Score Index ({classification})", 'font': {'size': 14, 'color': '#94a3b8'}},
        number={'suffix': "/100", 'font': {'color': bar_color, 'size': 32, 'family': 'Inter'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#334155", 'tickfont': {'color': '#64748b', 'size': 10}},
            'bar': {'color': bar_color, 'thickness': 0.28},
            'bgcolor': "#0b1120",
            'borderwidth': 1,
            'bordercolor': "#1e293b",
            'steps': [
                {'range': [0, 25], 'color': '#064e3b'},
                {'range': [25, 50], 'color': '#713f12'},
                {'range': [50, 75], 'color': '#7c2d12'},
                {'range': [75, 100], 'color': '#7f1d1d'}
            ]
        }
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=25, r=25, t=40, b=15),
        height=220
    )
    return fig
