# Machine Learning Overfitting & Data Leakage Audit Report
**Project:** LinkShield - AI-Powered Universal URL Threat Detection  
**Target Model:** Random Forest Classifier (Benchmarked vs. XGBoost & Logistic Regression)  
**Dataset Analyzed:** UCI PhiUSIIL Phishing URL Dataset (ID: 967)  
**Date of Audit:** October 30, 2026  
**Auditor:** LinkShield AI/ML Security Engineering  

---

## 1. Executive Summary

An initial reported accuracy of **99.36%** was audited for overfitting, statistical bias, data leakage, and real-world generalization deficiencies.

### Key Audit Findings:
1. **Duplicate URL Feature Leakage:** The original naive processed sample contained **1,123 duplicate rows (22.46%)**. When split randomly into 75% train and 25% test, **29.20% of test records had identical feature representations in the training partition**, creating artificial memorization and inflated test metrics.
2. **UCI PhiUSIIL Dataset Structural Bias:** While the UCI repository dataset contains 235,795 URLs, an inspection of the legitimate URLs revealed that **0 out of 5,000 legitimate entries contained URL paths or query strings** (all were bare homepage domains such as `https://domain.com/`). In contrast, phishing URLs had deep paths and query parameters. Consequently, naive models learned a spurious shortcut: *any URL with a path or query string was classified as phishing*, causing a collapse to **50.0% accuracy** on unseen real-world legitimate URLs.
3. **HTTP vs. HTTPS Feature Imbalance:** In the raw UCI dataset, 100% of sampled legitimate domains were HTTPS, whereas phishing URLs were a mix of HTTP and HTTPS. Naive models over-weighted `has_https` (accounting for **45.3% of total feature importance**).
4. **Regularization and Deduplication Remedy:** After complete deduplication (0.00% duplicates), multi-domain path balancing, and hyperparameter tuning with constraints (`max_depth=10`, `min_samples_leaf=2`, `min_samples_split=5`), the model achieves **97.45% ± 0.41% stratified 5-fold cross-validation accuracy** and increases unseen external test accuracy from **50.0% to 87.50% (F1 = 0.8889)**.

---

## 2. Leakage & Overfitting Analysis

### A. Training, Validation, and Testing Accuracy
| Phase | Naive Model (Raw) | Tuned & Regularized Model (Audited) |
| :--- | :---: | :---: |
| **Training Accuracy** | 99.87% | **99.50%** |
| **Testing Accuracy** | 99.36% | **97.27%** |
| **Overfitting Delta** | 0.51% (artificially deflated by duplicate leakage) | **2.23% (honest generalization margin)** |

### B. Stratified 5-Fold Cross-Validation (StandardScaler Fitted Inside Fold)
To guarantee zero preprocessing leakage (ensuring `StandardScaler` is fitted strictly on the 4 training folds before transforming the validation fold), stratified 5-fold CV was executed:

| Model | 5-Fold CV Accuracy | 5-Fold CV Precision | 5-Fold CV Recall | 5-Fold CV F1-Score | Std Dev |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Tuned)** | **97.45%** | **98.05%** | **97.62%** | **97.83%** | ± 0.0041 |
| **XGBoost (max_depth=6)** | 97.30% | 97.84% | 97.55% | 97.69% | ± 0.0072 |
| **Logistic Regression** | 95.31% | 96.22% | 95.71% | 95.96% | ± 0.0079 |

### C. Data Leakage & Duplicate URL Inspection
- **Raw Samples Checked:** 5,000
- **Duplicate Rows in Naive Set:** 1,123 (22.46%)
- **Test Set Leakage in Naive Split:** 365 / 1,250 test samples (29.20%) were identical clones of training vectors.
- **Remediation:** Full dataset deduplication applied before splitting. Cleaned dataset has **0 duplicate rows (0.00%)**, reducing test leakage to statistical noise (0.32% representing rare collision of identical structural lengths).

---

## 3. Genuine URL Feature Extractability Verification

Every feature in `feature_extraction.py` was inspected to ensure it is **strictly computable from the submitted URL string alone** without opening remote sockets, fabricating data, or accessing target content:

| Feature Name | Computation Method | Extractable Directly? | Verification Status |
| :--- | :--- | :---: | :---: |
| `url_length` | `len(url)` | Yes | Verified |
| `domain_length` | `len(hostname)` | Yes | Verified |
| `path_length` | `len(parsed.path)` | Yes | Verified |
| `num_dots` | `url.count('.')` | Yes | Verified |
| `num_hyphens` | `url.count('-')` | Yes | Verified |
| `num_subdomains` | Multi-level TLD parsing | Yes | Verified |
| `num_slash` | `url.count('/')` | Yes | Verified |
| `num_question` | `url.count('?')` | Yes | Verified |
| `num_equal` | `url.count('=')` | Yes | Verified |
| `num_at` | `url.count('@')` | Yes | Verified |
| `num_percent` | `url.count('%')` | Yes | Verified |
| `num_ampersand` | `url.count('&')` | Yes | Verified |
| `num_underscore` | `url.count('_')` | Yes | Verified |
| `num_digits` | `sum(c.isdigit())` | Yes | Verified |
| `digit_ratio` | `num_digits / url_length` | Yes | Verified |
| `url_entropy` | Shannon Entropy Formula | Yes | Verified |
| `domain_entropy` | Shannon Entropy on Domain | Yes | Verified |
| `has_https` | `parsed.scheme == 'https'` | Yes | Verified |
| `https_in_domain` | `'https' in domain` | Yes | Verified |
| `is_ip` | IPv4/IPv6 Regex & Octal parser | Yes | Verified |
| `is_shortened` | Known shortener domain set | Yes | Verified |
| `suspicious_keyword_count` | Keyword frequency list in URL | Yes | Verified |
| `suspicious_in_domain` | Keyword frequency list in domain | Yes | Verified |
| `special_char_ratio` | Special char set ratio | Yes | Verified |

**Result:** Zero non-extractable or phantom features exist in the model pipeline.

---

## 4. Evaluation on Separate Unseen External Dataset

A fresh, unseen test set of 40 URLs was constructed (20 verified legitimate high-traffic websites with deep paths, query strings, and digits; and 20 verified phishing URLs with active phishing payloads):

### Unseen Benchmark Comparison:
- **Naive Overfitted Model:**
  - Accuracy: **50.00%**
  - Confusion Matrix: `[[0, 20], [0, 20]]` (Classified all 20 legitimate URLs as phishing because they had paths and query strings).
- **Tuned & Regularized Model:**
  - Accuracy: **87.50%**
  - Precision: **80.00%**
  - Recall: **100.00%**
  - F1-Score: **0.8889**
  - Confusion Matrix: `[[15, 5], [0, 20]]` (Correctly identified 100% of real phishing threats, with 15/20 legitimate URLs recognized).

---

## 5. Hyperparameter Tuning & Model Comparison

Hyperparameters tuned for Random Forest to prevent tree leaf memorization:
- `n_estimators`: Increased from 100 to 150
- `max_depth`: Constrained from unlimited/12 to `10`
- `min_samples_split`: Set to `5` (prevents splitting on isolated noise samples)
- `min_samples_leaf`: Set to `2` (prevents 1-sample leaf memorization)
- `max_features`: Set to `'sqrt'`

| Metric | Random Forest (Tuned) | XGBoost | Logistic Regression |
| :--- | :---: | :---: | :---: |
| **5-Fold CV Accuracy** | **97.45%** | 97.30% | 95.31% |
| **5-Fold CV Precision** | **98.05%** | 97.84% | 96.22% |
| **5-Fold CV Recall** | **97.62%** | 97.55% | 95.71% |
| **5-Fold CV F1-Score** | **97.83%** | 97.69% | 95.96% |
| **Unseen External Test Acc** | **87.50%** | 85.00% | 82.50% |

**Winning Champion Model:** **Random Forest (Tuned & Regularized)** saved to `models/best_model.pkl` and `models/scaler.pkl`.

---

## 6. Recommendations & Best Practices

1. **Pre-processing Isolation:** The application now strictly uses `models/scaler.pkl` fitted exclusively on training data.
2. **Ensemble Redundancy:** LinkShield's `risk_engine.py` combines the ML model with VirusTotal, Google Safe Browsing, PhishTank, and SSL certificate verification, ensuring no single heuristic makes an isolated classification.
3. **Security Invariant Preserved:** The risk engine strictly enforces that no URL receives a 0 score (minimum baseline risk of 5), upholding the rule that "No URL is declared completely safe merely because no threat was found."
