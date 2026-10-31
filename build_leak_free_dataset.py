"""
Dataset Preparation & Real-World Generalization Pipeline for LinkShield
Extracts verified URLs from UCI PhiUSIIL repository while correcting dataset bias
(augmenting legitimate URLs with deep paths, query strings, and standard domains),
removing duplicates, and computing genuine 24-feature lexical representations.
"""

import os
import csv
import urllib.request
import pandas as pd
from feature_extraction import extract_features, FEATURE_COLUMNS

DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")
os.makedirs(DATASET_DIR, exist_ok=True)
CACHE_CSV = os.path.join(DATASET_DIR, "phiusiil_processed.csv")
UCI_DATA_URL = "https://archive.ics.uci.edu/static/public/967/data.csv"

# Diverse real-world legitimate URLs containing deep paths, query parameters, digits, and hyphens
# to prevent the model from treating any path/query as an automatic phishing trigger
REAL_LEGIT_PATH_URLS = [
    "https://www.google.com/search?q=machine+learning+cybersecurity",
    "https://github.com/scikit-learn/scikit-learn/blob/main/README.rst",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.amazon.com/gp/help/customer/display.html?nodeId=508510",
    "https://www.microsoft.com/en-us/security/business/threat-protection",
    "https://stackoverflow.com/questions/tagged/python-3.x",
    "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
    "https://www.apple.com/shop/accessories/all",
    "https://www.linkedin.com/learning/topics/cybersecurity",
    "https://www.netflix.com/title/80186980",
    "https://www.nytimes.com/section/technology",
    "https://www.cnn.com/world/europe",
    "https://www.reddit.com/r/MachineLearning/comments/12345/neural_networks",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://docs.python.org/3/library/ssl.html",
    "https://scikit-learn.org/stable/modules/ensemble.html",
    "https://xgboost.readthedocs.io/en/stable/python/python_intro.html",
    "https://streamlit.io/components?category=charts",
    "https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/",
    "https://aws.amazon.com/s3/pricing/",
    "https://azure.microsoft.com/en-us/products/storage/",
    "https://hub.docker.com/_/python",
    "https://pypi.org/project/joblib/",
    "https://pypi.org/project/pandas/",
    "https://www.bbc.com/news/technology-68500000",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
    "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides",
    "https://archive.org/details/texts",
    "https://www.coursera.org/browse/data-science",
    "https://news.ycombinator.com/item?id=38000000",
    "https://www.eff.org/pages/tools",
    "https://www.cisa.gov/topics/cyber-threats-and-advisories",
    "https://www.kernel.org/doc/html/latest/",
    "https://open.spotify.com/genre/classical",
    "https://www.imdb.com/title/tt0111161/",
    "https://medium.com/topic/cybersecurity",
    "https://arxiv.org/abs/1706.03762",
    "https://gitlab.com/gitlab-org/gitlab/-/blob/master/README.md",
    "https://bitbucket.org/account/user/profile/"
]

def build_leak_free_dataset():
    print("Streaming UCI PhiUSIIL data from repository...")
    req = urllib.request.Request(UCI_DATA_URL, headers={"User-Agent": "Mozilla/5.0 LinkShield-Auditor"})
    
    phiusiil_legit = []
    phiusiil_phish = []
    
    with urllib.request.urlopen(req, timeout=30) as resp:
        line_iter = (line.decode("utf-8-sig", errors="ignore") for line in resp)
        reader = csv.reader(line_iter)
        header = next(reader)
        url_idx = header.index("URL")
        label_idx = header.index("label")
        
        for row in reader:
            if len(row) <= max(url_idx, label_idx):
                continue
            u = row[url_idx].strip()
            lbl = row[label_idx].strip()
            if not u.startswith("http"):
                continue
            
            # UCI PhiUSIIL: 1 = legit, 0 = phish.
            # LinkShield standardized: 0 = legit, 1 = phish.
            if lbl == "1" and len(phiusiil_legit) < 2000:
                phiusiil_legit.append(u)
            elif lbl == "0" and len(phiusiil_phish) < 2500:
                phiusiil_phish.append(u)
                
            if len(phiusiil_legit) >= 2000 and len(phiusiil_phish) >= 2500:
                break

    # Blend legitimate set: 2000 PhiUSIIL top-level domains + 500 diverse path/query URLs
    augmented_legit = phiusiil_legit + (REAL_LEGIT_PATH_URLS * 15)[:700]
    
    all_urls = augmented_legit + phiusiil_phish
    all_labels = [0] * len(augmented_legit) + [1] * len(phiusiil_phish)
    
    print(f"Total URLs to process: {len(all_urls)} (Legit: {len(augmented_legit)}, Phish: {len(phiusiil_phish)})")
    
    rows = []
    labels = []
    for u, l in zip(all_urls, all_labels):
        try:
            f = extract_features(u)
            rows.append(f)
            labels.append(l)
        except Exception:
            continue
            
    df = pd.DataFrame(rows)[FEATURE_COLUMNS]
    df["target"] = labels
    
    # Remove any duplicate feature vectors to prevent intra-split leakage
    df_clean = df.drop_duplicates().reset_index(drop=True)
    print(f"Clean deduped dataset shape: {df_clean.shape}")
    df_clean.to_csv(CACHE_CSV, index=False)
    print(f"Saved to {CACHE_CSV}")
    return df_clean

if __name__ == "__main__":
    build_leak_free_dataset()
