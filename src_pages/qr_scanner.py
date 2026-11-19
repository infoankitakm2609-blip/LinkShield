"""
LinkShield - QR Code Threat Scanner Subpage (SaaS Redesign)
"""

import streamlit as st
from PIL import Image
from url_validator import validate_url
from ui_components import render_page_header, get_risk_pill_html

def decode_qr(img: Image.Image) -> str:
    """Decodes QR code from PIL image using OpenCV QRCodeDetector or pyzbar."""
    try:
        import cv2
        import numpy as np
        img_np = np.array(img.convert('RGB'))
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img_np)
        if data:
            return data
    except Exception:
        pass

    try:
        from pyzbar.pyzbar import decode
        objs = decode(img)
        if objs:
            return objs[0].data.decode('utf-8')
    except Exception:
        pass
    return ""

def show():
    render_page_header(
        title="QR Threat Scanner (Anti-Quishing)",
        subtitle="Safely decompose physical, printable, or digital QR codes to inspect the embedded URL payload prior to execution.",
        badge_text="Physical & Visual Vectors"
    )

    st.markdown('<div class="saas-card">', unsafe_allow_html=True)
    qr_file = st.file_uploader(
        "Upload image containing a QR code matrix (PNG, JPG, JPEG, WEBP):",
        type=["png", "jpg", "jpeg", "webp"]
    )
    st.markdown('</div>', unsafe_allow_html=True)

    if qr_file is not None:
        try:
            image = Image.open(qr_file)
            c1, c2 = st.columns([1, 1.2])

            with c1:
                st.markdown('<div class="saas-card">', unsafe_allow_html=True)
                st.markdown("<div style='font-size: 0.85rem; font-weight: 600; color: #94a3b8; margin-bottom: 0.5rem;'>Source Matrix</div>", unsafe_allow_html=True)
                st.image(image, use_container_width=True)
                st.markdown('</div>', unsafe_allow_html=True)

            with c2:
                with st.spinner("Decoding optical matrix patterns..."):
                    raw_payload = decode_qr(image)

                if not raw_payload:
                    st.warning("No readable QR matrix detected in uploaded image. Verify image focus and illumination.")
                    return

                st.markdown('<div class="saas-card">', unsafe_allow_html=True)
                st.markdown("<div style='font-size: 0.85rem; font-weight: 600; color: #94a3b8;'>Extracted Payload</div>", unsafe_allow_html=True)
                st.markdown(f"<div class='code-box' style='margin: 0.5rem 0;'>{raw_payload}</div>", unsafe_allow_html=True)

                is_valid, msg, norm_url = validate_url(raw_payload)
                if not is_valid:
                    st.error(f"Payload Safety Alert: {msg}")
                    st.markdown('</div>', unsafe_allow_html=True)
                    return

                with st.spinner("Executing threat analysis on parsed URL..."):
                    engine = st.session_state.risk_engine
                    report = engine.analyze_url(norm_url)
                    st.session_state.history_mgr.save_scan(report)

                pill = get_risk_pill_html(report["classification"])
                st.markdown(f"""
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 1rem; padding-top: 0.75rem; border-top: 1px solid #1e293b;">
                    <div>
                        <div style="font-size: 0.75rem; color: #64748b;">Risk Index</div>
                        <div style="font-size: 1.4rem; font-weight: 700; color: #f8fafc;">{report['risk_score']}/100</div>
                    </div>
                    <div>
                        {pill}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown("<div style='margin-top: 0.75rem;'></div>", unsafe_allow_html=True)
                st.markdown("<div style='font-size: 0.82rem; font-weight: 600; color: #94a3b8;'>Primary Risk Factors:</div>", unsafe_allow_html=True)
                for rf in report.get("risk_factors", [])[:3]:
                    st.markdown(f"<div style='font-size: 0.82rem; color: #fca5a5;'>- ⚠️ {rf}</div>", unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

        except Exception as e:
            st.error(f"Error handling QR image: {e}")
