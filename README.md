# LinkShield – AI/ML Based Phishing URL Detection System

<p align="center">
  <strong>AI-Powered URL Threat Detection & Security Analysis</strong>
</p>

<p align="center">
  An intelligent web application that analyzes URLs using Machine Learning, heuristic-based detection, and external threat intelligence to identify potentially malicious and phishing websites.
</p>

---

## About the Project

**LinkShield** is an AI/ML-based web application designed to detect phishing and suspicious URLs. It analyzes different URL characteristics, applies a trained Machine Learning model, evaluates suspicious patterns, and optionally integrates external threat intelligence services to assess potential security risks.

The application generates a risk score between 0 and 100 and provides a classification along with the factors contributing to the result.

LinkShield aims to provide users with an additional layer of protection against phishing websites and suspicious online links.

## Key Features

- **URL Scanner:** Analyze individual URLs and identify potentially malicious websites.
- **Machine Learning Detection:** Uses a trained Random Forest classification model to predict whether a URL is legitimate or potentially phishing.
- **Lexical Feature Extraction:** Extracts 24 URL-based features for ML-based analysis.
- **Heuristic Analysis:** Detects suspicious URL patterns, unusual characters, IP-based URLs, URL shorteners, and suspicious keywords.
- **External Threat Intelligence:** Supports integration with VirusTotal, Google Safe Browsing, and PhishTank.
- **SSL/TLS Certificate Inspection:** Retrieves domain and SSL certificate information.
- **Risk Scoring Engine:** Combines ML predictions, heuristic analysis, and available external threat intelligence into a composite risk score.
- **Bulk URL Scanner:** Analyzes multiple URLs using CSV input.
- **QR Code Scanner:** Extracts URLs from QR codes and analyzes them.
- **Analytics Dashboard:** Displays scan statistics and threat-level distribution.
- **Scan History:** Maintains records of previously analyzed URLs.
- **Risk Explanation:** Displays detected risk factors and positive trust indicators.

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Frontend / Web Framework | Streamlit |
| Machine Learning | Scikit-learn |
| ML Algorithm | Random Forest Classifier |
| Data Processing | Pandas, NumPy |
| Data Visualization | Plotly |
| HTTP Requests | Requests |
| URL Analysis | Python URL parsing, tldextract |
| SSL/TLS Inspection | Python ssl and socket |
| Environment Configuration | python-dotenv |
| Data Storage | JSON / CSV |
| External Threat Intelligence | VirusTotal, Google Safe Browsing, PhishTank |

## System Architecture

The application follows a multi-layer URL inspection approach.

```text
              USER INPUT
                  |
                  v
       URL / CSV / QR Code
                  |
                  v
          URL VALIDATION
                  |
                  v
       FEATURE EXTRACTION
          (24 Features)
                  |
          +-------+-------+
          |               |
          v               v
     ML MODEL       HEURISTIC ANALYSIS
   (Random Forest)   (Suspicious Patterns)
          |               |
          +-------+-------+
                  |
                  v
       EXTERNAL THREAT INTELLIGENCE
       (VirusTotal / Google Safe
          Browsing / PhishTank)
                  |
                  v
          SSL/TLS INSPECTION
                  |
                  v
            RISK ENGINE
                  |
                  v
          COMPOSITE RISK SCORE
                  |
                  v
          FINAL CLASSIFICATION
                  |
                  v
       RESULTS + EXPLANATION
                  |
                  v
          SCAN HISTORY
```

*External threat intelligence results depend on API configuration, availability, and service limits.*

## How LinkShield Works

### 1. URL Validation

The submitted URL is validated and normalized before analysis. The application checks URL structure, supported protocols, hostname syntax, and certain unsafe destinations.

### 2. Feature Extraction

The system extracts 24 numerical and categorical URL characteristics, including:

- URL length
- Domain length
- Path length
- Number of dots and hyphens
- Number of subdomains
- Number of special characters
- Number of digits
- Digit ratio
- URL entropy
- Domain entropy
- HTTPS presence
- IP address usage
- URL shortener detection
- Suspicious keyword count
- Suspicious domain patterns

### 3. Machine Learning Prediction

The extracted features are passed to the trained Random Forest classification model.

The model estimates whether the URL is legitimate or potentially phishing based on patterns learned during training.

### 4. Heuristic Analysis

The heuristic engine checks additional suspicious characteristics, such as:

- IP address-based URLs
- Excessive subdomains
- Suspicious keywords
- Unusual URL structures
- URL shorteners
- Missing HTTPS

### 5. External Threat Intelligence

LinkShield supports integration with:

- **VirusTotal:** Checks URL/domain reputation using available security intelligence.
- **Google Safe Browsing:** Checks against supported known unsafe URL categories.
- **PhishTank:** Checks reported phishing URLs.

These integrations require valid API credentials and network access. If an API is unavailable or not configured, its result should be treated as unavailable rather than as confirmation that a URL is safe.

### 6. SSL/TLS Inspection

The application retrieves available SSL/TLS certificate and domain information to provide additional context during URL analysis.

### 7. Risk Scoring and Classification

The risk engine combines the available analysis results into a composite risk score.

The current scoring formula is:

```text
Risk Score =
    (ML Score × 0.45)
  + (API Score × 0.35)
  + (Heuristic Score × 0.20)
```

The final score is bounded between 5 and 100.

### Risk Classification

| Risk Score | Classification |
|---|---|
| 5–24 | Low Risk |
| 25–49 | Moderate Risk |
| 50–74 | High Risk |
| 75–100 | Critical Risk |

**Note:** The risk score is a composite security indicator, not a mathematically calibrated probability that a website will attack the user.

## Project Structure

The following is an illustrative structure. Actual filenames and folders may vary depending on your project version.

```text
LinkShield/
│
├── app.py
│
├── api_services.py
├── feature_extraction.py
├── risk_engine.py
├── url_validator.py
├── history_manager.py
├── train_model.py
│
├── models/
│   ├── best_model.pkl
│   └── scaler.pkl
│
├── pages/
│   ├── URL Scanner
│   ├── Bulk Scanner
│   ├── QR Scanner
│   ├── Analytics Dashboard
│   └── Scan History
│
├── data/
│
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Installation and Setup

Follow these steps to run LinkShield on your local machine.

### Prerequisites

- Python 3.10 or higher (Python 3.12 recommended for the current development environment).
- pip package manager.
- Git (optional).
- Internet connection for external threat intelligence services.

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/LinkShield.git
```

Navigate to the project directory:

```bash
cd LinkShield
```

### Step 2: Create a Virtual Environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

Activate it on Linux/macOS:

```bash
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables

Create a `.env` file in the project root directory.

Add the following variables:

```env
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
PHISHTANK_API_KEY=
```

Add your own API credentials where available.

**Security Warning:** Never upload your actual `.env` file, API keys, or other secret credentials to GitHub.

### Step 5: Run the Application

```bash
streamlit run app.py
```

The application will normally be available at:

```text
http://localhost:8501
```

Open the displayed local URL in your web browser.

## Dataset and Model Training

LinkShield's training pipeline is designed to use the **PhiUSIIL Phishing URL Dataset**.

Dataset source:

[UCI Machine Learning Repository – PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)

The training pipeline compares multiple classification algorithms, including:

- Logistic Regression
- Random Forest
- XGBoost

The selected model is saved for use by the application's risk engine.

To execute the training script:

```bash
python train_model.py
```

**Important:** The training script may use a fallback dataset if the primary dataset cannot be downloaded and no processed dataset is available. Check the actual dataset source and training logs before reporting model performance.

## Model Evaluation

The project includes model evaluation and reporting functionality.

Common evaluation metrics include:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion Matrix
- Cross-validation performance

Model performance should be reported using verified results from the actual training run and an independently evaluated test dataset.

## Security Considerations

- API credentials must be stored in environment variables.
- The `.env` file must be excluded from version control.
- URL validation is performed before analysis.
- External API failures should not be interpreted as safe results.
- HTTPS does not guarantee that a website is legitimate.
- A low risk score does not guarantee that a URL is completely safe.
- Avoid opening suspicious URLs directly in a normal browser.

## Current Limitations

- Detection accuracy depends on the quality and representativeness of training data.
- Previously unseen phishing techniques may not always be detected.
- External threat intelligence depends on API availability and usage limits.
- SSL certificates alone cannot establish website legitimacy.
- URL-based analysis cannot identify every form of website-based malicious behavior.
- The application is a security analysis prototype and should not be considered a replacement for enterprise-grade security solutions.

## Future Enhancements

Potential improvements include:

- Deep Learning-based URL classification.
- Real-time threat intelligence integration.
- Improved phishing detection using domain reputation and DNS information.
- Advanced feature engineering.
- Improved model evaluation using leakage-resistant data splitting.
- Automated model retraining with updated datasets.
- Enhanced reporting and downloadable scan reports.
- Deployment on a cloud platform.

## Applications

LinkShield can be useful for:

- Analyzing suspicious links.
- Checking URLs received through emails or messages.
- Educational cybersecurity demonstrations.
- Understanding phishing URL characteristics.
- Performing bulk URL security analysis.
- Demonstrating Machine Learning applications in cybersecurity.

## Disclaimer

LinkShield is developed for educational, research, and cybersecurity awareness purposes.

The results are indicative assessments and should not be treated as absolute guarantees of website safety or maliciousness. Users should follow appropriate cybersecurity practices and verify suspicious links through trusted security resources.

## Author

**LinkShield – AI/ML Based Phishing URL Detection System**

Developed as an academic project in the field of Computer Science and Engineering (Artificial Intelligence and Machine Learning).

---

<p align="center">
  <strong>LinkShield – Analyze Smart. Browse Safe.</strong>
</p>
