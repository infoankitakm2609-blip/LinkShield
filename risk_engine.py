import os
import joblib
import pandas as pd
from typing import Dict, Any, List, Tuple
from feature_extraction import extract_features, FEATURE_COLUMNS
from api_services import APIServices

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "best_model.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "models", "scaler.pkl")

class RiskEngine:
    """
    Combines ML model predictions, external threat intelligence APIs,
    and heuristic/structural URL analysis to compute an integrated 0-100 risk score.
    Gracefully handles missing or unavailable external APIs and inconclusive predictions.
    """

    def __init__(self):
        self.model = None
        self.scaler = None
        self._load_model()

    def _load_model(self):
        try:
            if os.path.exists(MODEL_PATH):
                self.model = joblib.load(MODEL_PATH)
            if os.path.exists(SCALER_PATH):
                self.scaler = joblib.load(SCALER_PATH)
        except Exception as e:
            print(f"Warning: Could not load ML model or scaler: {e}")

    def predict_ml(self, features_dict: Dict[str, Any]) -> Tuple[str, float]:
        """
        Runs ML model inference on extracted URL features.
        Returns (predicted_label, probability_of_phishing).
        """
        if self.model is None:
            return "Inconclusive (Model Not Available)", 0.5

        # Format into single-row dataframe matching training columns
        df = pd.DataFrame([features_dict])[FEATURE_COLUMNS]

        try:
            if self.scaler:
                df_scaled = self.scaler.transform(df)
            else:
                df_scaled = df

            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(df_scaled)[0]
                phish_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            else:
                pred = self.model.predict(df_scaled)[0]
                phish_prob = 1.0 if pred == 1 else 0.0

            # Inconclusive margin: if probability is right at boundary (0.48 - 0.52)
            if 0.48 <= phish_prob <= 0.52:
                label = "Inconclusive (Borderline Probability)"
            elif phish_prob > 0.5:
                label = "Phishing / Malicious"
            else:
                label = "Legitimate"
                
            return label, phish_prob
        except Exception as e:
            print(f"ML inference error: {e}")
            return "Inconclusive (Inference Error)", 0.5

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Full 7-step security analysis:
        1. Feature extraction
        2. ML Prediction
        3. External Threat APIs (VT, GSB, PhishTank)
        4. Domain and SSL analysis
        5. Multi-factor Risk Score Calculation (0 - 100)
        6. Risk factor explanations
        7. Classification category
        """
        risk_factors: List[str] = []
        positive_indicators: List[str] = []
        api_notices: List[str] = []

        # 1. Feature extraction
        features = extract_features(url)

        # Heuristic checks on features
        if features["is_ip"] == 1:
            risk_factors.append("URL host uses an IP address instead of a domain name (evasion technique).")
        if features["is_shortened"] == 1:
            risk_factors.append("URL uses a known link-shortener service which obfuscates the final destination.")
        if features["num_subdomains"] >= 3:
            risk_factors.append(f"Excessive subdomains detected ({features['num_subdomains']}), commonly used in phishing campaigns.")
        if features["num_at"] > 0:
            risk_factors.append("URL contains '@' symbol which can disguise target credentials or trick parsers.")
        if features["suspicious_keyword_count"] > 0:
            risk_factors.append(f"Detected {features['suspicious_keyword_count']} sensitive keywords (e.g., login, verify, banking).")
        if features["has_https"] == 0:
            risk_factors.append("Insecure HTTP protocol; transmissions lack cryptographic TLS encryption.")
        else:
            positive_indicators.append("Uses HTTPS protocol for encrypted communication.")
        if features["url_entropy"] > 4.5:
            risk_factors.append(f"High URL entropy ({features['url_entropy']}), indicating randomized or obfuscated characters.")

        # 2. ML Prediction
        ml_label, ml_prob = self.predict_ml(features)
        ml_is_inconclusive = "Inconclusive" in ml_label
        ml_score_component = ml_prob * 100

        if not ml_is_inconclusive:
            if ml_prob >= 0.70:
                risk_factors.append(f"AI/ML model classified this URL as phishing with {round(ml_prob*100, 1)}% confidence.")
            elif ml_prob <= 0.30:
                positive_indicators.append(f"AI/ML model found structural features typical of legitimate sites ({round((1-ml_prob)*100, 1)}% confidence).")
        else:
            api_notices.append(f"Machine learning prediction is {ml_label}.")

        # 3. Threat Intelligence APIs
        vt_data = APIServices.check_virustotal(url)
        gsb_data = APIServices.check_google_safe_browsing(url)
        phishtank_data = APIServices.check_phishtank(url)

        available_apis = 0
        total_apis = 3

        # VirusTotal
        if vt_data.get("available"):
            available_apis += 1
            if vt_data.get("malicious", 0) > 0:
                risk_factors.append(f"VirusTotal: Flagged malicious by {vt_data['malicious']} security vendors.")
        else:
            api_notices.append(f"VirusTotal feed unavailable ({vt_data.get('status', 'offline')}).")

        # Google Safe Browsing
        if gsb_data.get("available"):
            available_apis += 1
            if gsb_data.get("is_threat"):
                threats = ", ".join(gsb_data.get("threat_types", []))
                risk_factors.append(f"Google Safe Browsing: Threat detected ({threats}).")
        else:
            api_notices.append(f"Google Safe Browsing feed unavailable ({gsb_data.get('status', 'offline')}).")

        # PhishTank
        if phishtank_data.get("available"):
            available_apis += 1
            if phishtank_data.get("is_phish"):
                risk_factors.append("PhishTank: Identified and verified as an active phishing page.")
        else:
            api_notices.append(f"PhishTank feed unavailable ({phishtank_data.get('status', 'offline')}).")

        api_threat_confirmed = (
            vt_data.get("malicious", 0) > 0 or
            gsb_data.get("is_threat", False) or
            phishtank_data.get("is_phish", False)
        )

        # 4. Domain & SSL analysis
        ssl_info = APIServices.get_ssl_and_domain_info(url)
        if ssl_info.get("ssl_valid"):
            positive_indicators.append(f"Valid SSL certificate issued by {ssl_info.get('ssl_issuer') or 'trusted authority'}.")
        elif features["has_https"] == 1 and ssl_info.get("ssl_error"):
            risk_factors.append(f"SSL issue: {ssl_info.get('ssl_error')}")

        # 5. Composite Risk Score Calculation (0 - 100)
        # Adapt dynamic weights based on API availability:
        # If all APIs unavailable, fall back seamlessly to ML + Heuristics without failing
        heuristic_score = 0
        if features["is_ip"] == 1:
            heuristic_score += 25
        if features["is_shortened"] == 1:
            heuristic_score += 15
        if features["num_subdomains"] >= 3:
            heuristic_score += 10
        if features["num_at"] > 0:
            heuristic_score += 15
        if features["suspicious_keyword_count"] > 0:
            heuristic_score += min(20, features["suspicious_keyword_count"] * 8)
        if features["has_https"] == 0:
            heuristic_score += 15
        if features["url_entropy"] > 4.5:
            heuristic_score += 10

        api_score = 0
        if gsb_data.get("is_threat"):
            api_score = 70
        if phishtank_data.get("is_phish"):
            api_score = max(api_score, 70)
        if vt_data.get("malicious", 0) >= 3:
            api_score = max(api_score, 75)
        elif vt_data.get("malicious", 0) > 0:
            api_score = max(api_score, 45)

        if available_apis > 0:
            weight_ml = 0.45
            weight_api = 0.35
            weight_heuristics = 0.20
            raw_score = (ml_score_component * weight_ml) + (api_score * weight_api) + (heuristic_score * weight_heuristics)
        else:
            # Fallback weights when threat feeds are unconfigured or offline
            weight_ml = 0.65
            weight_heuristics = 0.35
            raw_score = (ml_score_component * weight_ml) + (heuristic_score * weight_heuristics)

        # Overrides: If threat feeds confirm malicious, score is at least 80
        if api_threat_confirmed:
            raw_score = max(raw_score, 80.0)

        # Security Invariant: Never declare 0/safe
        final_score = int(min(100, max(5, round(raw_score))))

        # 6. Classification Category
        # If ML is inconclusive AND no threat APIs available AND no definitive heuristics, classify as Inconclusive
        if ml_is_inconclusive and available_apis == 0 and heuristic_score < 15:
            classification = "Inconclusive"
        elif final_score >= 75:
            classification = "Critical Risk"
        elif final_score >= 50:
            classification = "High Risk"
        elif final_score >= 25:
            classification = "Moderate Risk"
        elif final_score >= 5:
            classification = "Low Risk"
        else:
            classification = "Inconclusive"

        if not risk_factors:
            risk_factors.append("No overt signatures or blacklist entries detected; standard internet caution recommended.")

        return {
            "url": url,
            "risk_score": final_score,
            "classification": classification,
            "ml_prediction": ml_label,
            "ml_confidence": round(ml_prob * 100, 2),
            "features": features,
            "vt_stats": vt_data,
            "gsb_status": gsb_data,
            "phishtank_status": phishtank_data,
            "ssl_info": ssl_info,
            "risk_factors": risk_factors,
            "positive_indicators": positive_indicators,
            "api_notices": api_notices,
            "available_apis_count": available_apis
        }
