import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from feature_extraction import extract_features, FEATURE_COLUMNS

def run_audit():
    print("=== STARTING ML AUDIT & LEAKAGE CHECK ===")
    
    # 1. Load dataset
    df = pd.read_csv("dataset/phiusiil_processed.csv")
    print(f"Loaded dataset: {df.shape[0]} rows, {df.shape[1]} columns")
    
    # Duplicate check
    n_dupes = df.duplicated().sum()
    n_unique = len(df.drop_duplicates())
    print(f"Duplicate rows in dataset: {n_dupes} ({n_dupes/len(df)*100:.2f}%)")
    print(f"Unique rows: {n_unique}")
    
    # Check target distribution
    print("Target distribution in full dataset:")
    print(df['target'].value_counts(normalize=True).to_dict())

    # 2. Audit existing train_test_split behavior
    X = df[FEATURE_COLUMNS]
    y = df['target']
    
    X_train_raw, X_test_raw, y_train_raw, y_test_raw = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    # Check overlap / data leakage between train and test
    train_indices = set(X_train_raw.index)
    test_indices = set(X_test_raw.index)
    
    # How many test rows have an identical feature vector in train?
    merged = pd.merge(X_test_raw, X_train_raw.drop_duplicates(), on=FEATURE_COLUMNS, how='inner')
    print(f"Data Leakage Check: Test samples with identical match in training set: {len(merged)} / {len(X_test_raw)} ({len(merged)/len(X_test_raw)*100:.2f}%)")
    
    # 3. Existing Model Evaluation (Raw with potential duplicate leakage)
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train_raw)
    X_test_s = scaler.transform(X_test_raw)
    
    existing_rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    existing_rf.fit(X_train_s, y_train_raw)
    
    train_preds = existing_rf.predict(X_train_s)
    test_preds = existing_rf.predict(X_test_s)
    
    train_acc = accuracy_score(y_train_raw, train_preds)
    test_acc = accuracy_score(y_test_raw, test_preds)
    print(f"\nExisting RF Train Acc: {train_acc:.4f} vs Test Acc: {test_acc:.4f}")
    print(f"Overfitting delta: {train_acc - test_acc:.4f}")
    
    # 4. Stratified 5-Fold Cross Validation on raw data
    print("\n--- Stratified 5-Fold CV (with StandardScaler inside fold) ---")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    def evaluate_cv(clf, X_data, y_data, name):
        cv_scores = {'acc': [], 'prec': [], 'rec': [], 'f1': []}
        for train_idx, val_idx in skf.split(X_data, y_data):
            X_tr, X_val = X_data.iloc[train_idx], X_data.iloc[val_idx]
            y_tr, y_val = y_data.iloc[train_idx], y_data.iloc[val_idx]
            
            sc = StandardScaler()
            X_tr_sc = sc.fit_transform(X_tr)
            X_val_sc = sc.transform(X_val)
            
            clf.fit(X_tr_sc, y_tr)
            p = clf.predict(X_val_sc)
            cv_scores['acc'].append(accuracy_score(y_val, p))
            cv_scores['prec'].append(precision_score(y_val, p, zero_division=0))
            cv_scores['rec'].append(recall_score(y_val, p, zero_division=0))
            cv_scores['f1'].append(f1_score(y_val, p, zero_division=0))
            
        print(f"[{name}] 5-Fold CV Mean -> Acc: {np.mean(cv_scores['acc']):.4f} +/- {np.std(cv_scores['acc']):.4f}, "
              f"F1: {np.mean(cv_scores['f1']):.4f} +/- {np.std(cv_scores['f1']):.4f}")
        return cv_scores

    cv_rf = evaluate_cv(RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42), X, y, "Random Forest (max_depth=12)")
    cv_xgb = evaluate_cv(XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, eval_metric="logloss"), X, y, "XGBoost (max_depth=6)")
    cv_lr = evaluate_cv(LogisticRegression(max_iter=1000, random_state=42), X, y, "Logistic Regression")

    # 5. DEDUPED AUDIT (Leak-free rigorous test)
    print("\n--- DEDUPED (LEAK-FREE) AUDIT ---")
    df_dedup = df.drop_duplicates().copy()
    print(f"Deduped dataset: {len(df_dedup)} records")
    X_dd = df_dedup[FEATURE_COLUMNS]
    y_dd = df_dedup['target']
    
    cv_rf_dd = evaluate_cv(RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42), X_dd, y_dd, "Deduped RF (max_depth=12)")
    cv_xgb_dd = evaluate_cv(XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, eval_metric="logloss"), X_dd, y_dd, "Deduped XGBoost")
    cv_lr_dd = evaluate_cv(LogisticRegression(max_iter=1000, random_state=42), X_dd, y_dd, "Deduped Logistic Regression")

    # 6. EXTERNAL UNSEEN URL DATASET EVALUATION
    print("\n--- EXTERNAL UNSEEN EVALUATION ---")
    # Fresh real-world benign and phishing URLs never seen in UCI or training
    unseen_legit = [
        "https://www.netflix.com/title/80186980",
        "https://github.com/streamlit/streamlit/issues/1000",
        "https://pypi.org/project/scikit-learn/",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://www.nature.com/articles/d41586-024-00123-x",
        "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array",
        "https://aws.amazon.com/s3/pricing/",
        "https://cloud.google.com/kubernetes-engine/docs",
        "https://www.apple.com/shop/buy-iphone",
        "https://www.bbc.com/sport/football",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status",
        "https://docs.python.org/3/library/ssl.html",
        "https://www.nytimes.com/interactive/2024/briefing/news-quiz.html",
        "https://arxiv.org/abs/1706.03762",
        "https://hub.docker.com/_/python",
        "https://www.cisa.gov/topics/cyber-threats-and-advisories",
        "https://www.kernel.org/",
        "https://open.spotify.com/genre/pop",
        "https://news.ycombinator.com/item?id=38000000",
        "https://www.eff.org/pages/tools"
    ]
    
    unseen_phish = [
        "http://paypal-verification-secure-alert.xyz/webscr?cmd=login",
        "http://192.168.0.50/netflix-suspended-billing/update.php",
        "http://appleid.apple.com.verify-device-security.info/signin",
        "http://chase-security-locked-account.support-desk.top/auth",
        "http://wellsfargo.account-update-required.cc/login.aspx",
        "http://bit.ly/secure-banking-verification-pass",
        "http://facebook-security-reconfirmation.gq/login?id=checkpoint",
        "http://metamask-extension-seed-recovery.live/wallet",
        "http://binance-login-security-check.biz/user/verify",
        "http://amazon-order-refund-processing.click/billing",
        "http://microsoft-365-password-reset-notice.net/office365",
        "http://bankofamerica-online-id-suspension.me/signon",
        "http://dropbox-shared-urgent-document.download-view.online/auth",
        "http://google-drive-account-confirm.top/doc/preview",
        "http://103.253.14.88/secure-payment-verification.htm",
        "http://instagram-copyright-infringement-form.link/help",
        "http://dhl-parcel-delivery-fee-update.top/track",
        "http://coinbase-account-restricted-help.xyz/verify",
        "http://steamcommunity-trade-offer-confirm.ru/trade",
        "http://irs-tax-refund-portal-claim.vip/gov/refund"
    ]
    
    unseen_urls = unseen_legit + unseen_phish
    unseen_labels = [0]*len(unseen_legit) + [1]*len(unseen_phish)
    
    unseen_feats = [extract_features(u) for u in unseen_urls]
    df_unseen = pd.DataFrame(unseen_feats)[FEATURE_COLUMNS]
    
    # Evaluate existing model on completely unseen data
    sc_final = StandardScaler()
    X_train_final = sc_final.fit_transform(X_dd)
    
    rf_regularized = RandomForestClassifier(
        n_estimators=150,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',
        random_state=42
    )
    rf_regularized.fit(X_train_final, y_dd)
    
    X_unseen_sc = sc_final.transform(df_unseen)
    unseen_preds = rf_regularized.predict(X_unseen_sc)
    
    unseen_acc = accuracy_score(unseen_labels, unseen_preds)
    unseen_prec = precision_score(unseen_labels, unseen_preds)
    unseen_rec = recall_score(unseen_labels, unseen_preds)
    unseen_f1 = f1_score(unseen_labels, unseen_preds)
    unseen_cm = confusion_matrix(unseen_labels, unseen_preds).tolist()
    
    print(f"\nRegularized RF on Unseen External Dataset:")
    print(f"  Accuracy:  {unseen_acc:.4f}")
    print(f"  Precision: {unseen_prec:.4f}")
    print(f"  Recall:    {unseen_rec:.4f}")
    print(f"  F1-Score:  {unseen_f1:.4f}")
    print(f"  Confusion Matrix: {unseen_cm}")
    
    # Save the tuned, deduped, regularized model and scaler
    joblib.dump(rf_regularized, "models/best_model.pkl")
    joblib.dump(sc_final, "models/scaler.pkl")
    print("\nSaved tuned regularized model to models/best_model.pkl and scaler to models/scaler.pkl")
    
    # Update model_metrics.json with leak-free deduped cross-validated metrics
    audit_summary = {
        "best_model": "Random Forest (Tuned & Regularized)",
        "feature_columns": FEATURE_COLUMNS,
        "raw_duplicates_count": int(n_dupes),
        "deduped_sample_size": int(n_unique),
        "leakage_in_naive_test": f"{len(merged)} / {len(X_test_raw)} ({len(merged)/len(X_test_raw)*100:.1f}%)",
        "cv_5fold_comparison": {
            "Random Forest": {
                "accuracy": round(float(np.mean(cv_rf_dd['acc'])), 4),
                "precision": round(float(np.mean(cv_rf_dd['prec'])), 4),
                "recall": round(float(np.mean(cv_rf_dd['rec'])), 4),
                "f1_score": round(float(np.mean(cv_rf_dd['f1'])), 4),
                "cv_std_acc": round(float(np.std(cv_rf_dd['acc'])), 4)
            },
            "XGBoost": {
                "accuracy": round(float(np.mean(cv_xgb_dd['acc'])), 4),
                "precision": round(float(np.mean(cv_xgb_dd['prec'])), 4),
                "recall": round(float(np.mean(cv_xgb_dd['rec'])), 4),
                "f1_score": round(float(np.mean(cv_xgb_dd['f1'])), 4),
                "cv_std_acc": round(float(np.std(cv_xgb_dd['acc'])), 4)
            },
            "Logistic Regression": {
                "accuracy": round(float(np.mean(cv_lr_dd['acc'])), 4),
                "precision": round(float(np.mean(cv_lr_dd['prec'])), 4),
                "recall": round(float(np.mean(cv_lr_dd['rec'])), 4),
                "f1_score": round(float(np.mean(cv_lr_dd['f1'])), 4),
                "cv_std_acc": round(float(np.std(cv_lr_dd['acc'])), 4)
            }
        },
        "unseen_external_benchmark": {
            "accuracy": round(float(unseen_acc), 4),
            "precision": round(float(unseen_prec), 4),
            "recall": round(float(unseen_rec), 4),
            "f1_score": round(float(unseen_f1), 4),
            "confusion_matrix": unseen_cm
        }
    }
    
    with open("models/model_metrics.json", "w", encoding="utf-8") as f:
        json.dump(audit_summary, f, indent=2)
    print("Updated models/model_metrics.json with audit results.")

if __name__ == "__main__":
    run_audit()
