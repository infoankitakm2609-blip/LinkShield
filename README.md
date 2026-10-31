# LinkShield: AI-Powered Universal URL Threat Detection and Security Analyzer

LinkShield is an enterprise-grade cybersecurity web application built with Streamlit, Scikit-learn, XGBoost, and external threat intelligence APIs (VirusTotal, Google Safe Browsing, PhishTank) to detect phishing, fraudulent, and malicious URLs.

## Project Structure
- `app.py`: Main Streamlit multi-page application entry point.
- `train_model.py`: Script to download/clean PhiUSIIL dataset, train Logistic Regression, Random Forest, XGBoost, evaluate, and save best model.
- `feature_extraction.py`: 20+ URL lexical, domain, structural, and security feature extractor.
- `url_validator.py`: Safe URL parsing, normalization, scheme validation, and SSRF prevention guards.
- `api_services.py`: Threat intelligence clients (VirusTotal, Google Safe Browsing, PhishTank, SSL/Whois).
- `risk_engine.py`: Multi-factor risk calculation engine producing 0-100 risk score and explanations.
- `history_manager.py`: JSON/CSV scan history manager with query/filter/export capabilities.
- `dataset/`: Directory for raw and processed datasets (PhiUSIIL).
- `models/`: Directory storing trained models, scalers, and evaluation metrics.
- `pages/`: Streamlit modular sub-pages.
- `tests/`: Automated unit and integration test suite.
