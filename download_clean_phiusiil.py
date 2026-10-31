"""
Official PhiUSIIL Real Dataset Downloader and Cleaner for LinkShield
Downloads streaming data from UCI repository static URL,
extracts real URLs, removes duplicates, balances legitimate & phishing URLs,
extracts 24 genuine URL-computable features, and caches to dataset/phiusiil_processed.csv.
"""

import os
import csv
import io
import urllib.request
import pandas as pd
from feature_extraction import extract_features, FEATURE_COLUMNS

DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")
os.makedirs(DATASET_DIR, exist_ok=True)
CACHE_CSV = os.path.join(DATASET_DIR, "phiusiil_processed.csv")
UCI_DATA_URL = "https://archive.ics.uci.edu/static/public/967/data.csv"

def download_and_process(target_count_per_class=2500):
    print("Connecting to UCI PhiUSIIL repository...")
    req = urllib.request.Request(UCI_DATA_URL, headers={"User-Agent": "Mozilla/5.0 LinkShield-Auditor"})
    
    legit_urls = set()
    phish_urls = set()
    
    with urllib.request.urlopen(req, timeout=30) as resp:
        # Stream read line by line with CSV parser
        line_iter = (line.decode("utf-8-sig", errors="ignore") for line in resp)
        reader = csv.reader(line_iter)
        header = next(reader)
        url_idx = header.index("URL")
        label_idx = header.index("label")
        
        count = 0
        for row in reader:
            count += 1
            if len(row) <= max(url_idx, label_idx):
                continue
            
            raw_url = row[url_idx].strip()
            raw_label = row[label_idx].strip()
            
            if not raw_url or not raw_url.startswith("http"):
                continue
                
            # UCI PhiUSIIL encoding: label 1 = Legitimate, label 0 = Phishing
            # Standardize for LinkShield: 1 = Phishing (threat), 0 = Legitimate (benign)
            if raw_label == "1" and len(legit_urls) < target_count_per_class:
                legit_urls.add(raw_url)
            elif raw_label == "0" and len(phish_urls) < target_count_per_class:
                phish_urls.add(raw_url)
                
            if len(legit_urls) >= target_count_per_class and len(phish_urls) >= target_count_per_class:
                break
                
            if count % 2000 == 0:
                print(f"Processed {count} rows -> Collected: {len(legit_urls)} legit, {len(phish_urls)} phishing")

    print(f"\nFinal Unique URLs Collected:")
    print(f"  Legitimate (label=0): {len(legit_urls)}")
    print(f"  Phishing (label=1):   {len(phish_urls)}")
    
    all_urls = list(legit_urls) + list(phish_urls)
    all_labels = [0] * len(legit_urls) + [1] * len(phish_urls)
    
    print(f"\nExtracting 24 genuinely computable features from {len(all_urls)} URLs...")
    feature_rows = []
    valid_targets = []
    
    for idx, (u, l) in enumerate(zip(all_urls, all_labels)):
        try:
            feats = extract_features(u)
            feature_rows.append(feats)
            valid_targets.append(l)
        except Exception:
            continue
            
        if (idx + 1) % 1000 == 0:
            print(f"Extracted features for {idx + 1} / {len(all_urls)} URLs...")

    df_feats = pd.DataFrame(feature_rows)[FEATURE_COLUMNS]
    df_feats["target"] = valid_targets
    
    # Drop any inadvertent duplicate feature vectors
    initial_len = len(df_feats)
    df_feats = df_feats.drop_duplicates().reset_index(drop=True)
    print(f"Deduplicated features: {initial_len} -> {len(df_feats)} rows (Removed {initial_len - len(df_feats)} duplicates)")
    
    df_feats.to_csv(CACHE_CSV, index=False)
    print(f"Successfully saved clean dataset to {CACHE_CSV}")
    return df_feats

if __name__ == "__main__":
    download_and_process(2500)
