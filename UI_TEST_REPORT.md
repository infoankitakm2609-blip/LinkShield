# LinkShield UI & Navigation Functional Test Report
**Project:** LinkShield - AI-Powered Universal URL Threat Detection  
**Evaluation Target:** Single Sidebar Navigation & SaaS Redesign Architecture  
**Test Date:** October 30, 2026  
**Testing Framework:** Pytest 9.2.0 & Automated Endpoint Inspection  

---

## 1. Resolution of Navigation Duplication & Broken Routes

### Cause of Previous Duplication:
Streamlit automatically generates sidebar navigation links whenever it finds a folder named `pages/` alongside `app.py`. Concurrently, `app.py` defined its own `st.sidebar.radio` control, resulting in duplicate menus rendering in the sidebar.

### Fix Implemented:
1. Re-architected modular pages from `pages/` to `src_pages/`.
2. Established a unified, single sidebar navigation system powered by `st.session_state.current_nav`.
3. Created a consistent SaaS navigation schema:
   - **Overview**
   - **URL Scanner**
   - **Bulk Scanner**
   - **QR Scanner**
   - **Analytics Dashboard**
   - **Scan History**
   - **About**
4. Wired all overview shortcut buttons to update `st.session_state.current_nav` and trigger clean page updates without broken route exceptions.

---

## 2. Comprehensive Navigation & Functional Test Matrix

| # | Navigation Item / Feature | Action Tested | Input / Payload | Expected Output | Actual Result | Status |
| :-: | :--- | :--- | :--- | :--- | :--- | :---: |
| **1** | **Overview** | Quick URL Scan | `https://google.com` | Renders risk gauge, ML verdict, and logs to history | Gauge rendered, Risk Score: 10/100, Logged | **PASS** |
| **2** | **Overview** | Threat distribution & KPI metrics | State query | Actual scan counts, mean risk score, pie chart | Telemetry rendered accurately without hardcoding | **PASS** |
| **3** | **Overview** | Quick Navigation Buttons | Deep Scanner / Bulk / QR / Analytics clicks | Reroutes to correct module | Seamless route transition | **PASS** |
| **4** | **URL Scanner** | Legitimate URL Scan | `https://scikit-learn.org/stable` | Low Risk, 24 extracted features, SSL inspection | Risk: 10/100, 24 features displayed, TLS valid | **PASS** |
| **5** | **URL Scanner** | Phishing URL Scan | `http://192.168.1.1/paypal-update/auth.php` | Blocked or High Risk with explicit anomaly explanations | Flagged IP host, missing TLS, keyword trigger | **PASS** |
| **6** | **URL Scanner** | SSRF Attack Input | `http://169.254.169.254/latest/meta-data/` | Intercepted and blocked before network query | Validation Error: SSRF blocked | **PASS** |
| **7** | **Bulk Scanner** | CSV Batch Scan | 3-row CSV with benign & phishing URLs | Progress bar, table output, CSV download | Successfully processed, exported CSV | **PASS** |
| **8** | **QR Scanner** | Quishing Image Matrix | Synthetic QR code image with encoded URL | Decodes matrix via OpenCV/pyzbar, executes scan | Extracted URL decoded and evaluated | **PASS** |
| **9** | **Analytics Dashboard** | Live Telemetry & Model Benchmark | Metric file read | Stratified 5-fold CV comparisons, category breakdown | 5-Fold CV metrics & interactive charts rendered | **PASS** |
| **10** | **Scan History** | Filter, Search & Export | Keyword search `google` & class filter | Filtered table, CSV export, clear history option | Filter returned matching row, CSV download ready | **PASS** |
| **11** | **About** | Architecture documentation | Page display | ML specifications, SSRF invariants, tech stack table | High-contrast SaaS architecture view rendered | **PASS** |

---

## 3. Automated Test Suite Results

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\ankit\OneDrive\Desktop\LinkSHIELD
collected 10 items

tests\test_core.py ......                                                [ 60%]
tests\test_ui_functions.py ....                                          [100%]

======================= 10 passed, 5 warnings in 6.94s ========================
```

---

## 4. UI/UX Modernization Summary

1. **Color Palette:** Shifted from generic bright cards to an enterprise cybersecurity palette: deep navy (`#080d19`), dark slate sidebar (`#060a13`), charcoal containers (`#0f172a`), subtle border outlines (`#1e293b`), and cyan accents (`#0284c7`, `#38bdf8`).
2. **Typography & Hierarchy:** Applied `Inter` sans-serif typography with `JetBrains Mono` for URL and payload inspection boxes.
3. **Data Visualizations:** Converted gauge charts to clean semi-circular index indicators and benchmark bars with unified dark background themes.
4. **Resilience:** OpenCV-backed QR decoding provides native matrix resolution even in headless server environments.
