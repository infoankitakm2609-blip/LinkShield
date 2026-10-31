"""
LinkShield Balanced Dataset Generator
Incorporates real UCI PhiUSIIL phishing URLs alongside a balanced real-world legitimate sample
with standard web characteristics (paths, query strings, digits, articles, products, repos).
Removes duplicates and saves to dataset/phiusiil_processed.csv.
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

# Comprehensive list of diverse, verified benign URLs covering deep paths, digits, queries, subdomains
REPRESENTATIVE_BENIGN_URLS = [
    # Search & Queries
    "https://www.google.com/search?q=machine+learning+cybersecurity",
    "https://www.bing.com/search?q=open+source+intelligence+tools&qs=n",
    "https://duckduckgo.com/?q=python+dataclasses+tutorial&ia=web",
    "https://search.yahoo.com/search?p=streamlitofficial&fr=yfp",
    "https://scholar.google.com/scholar?hl=en&as_sdt=0%2C5&q=adversarial+url",
    
    # Software Repos & Documentation
    "https://github.com/scikit-learn/scikit-learn/blob/main/README.rst",
    "https://github.com/streamlit/streamlit/issues/1000",
    "https://github.com/torvalds/linux/commit/8038218a2024",
    "https://gitlab.com/gitlab-org/gitlab/-/blob/master/README.md",
    "https://bitbucket.org/account/user/profile/",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://docs.python.org/3/library/ssl.html",
    "https://docs.python.org/3/library/datetime.html#strftime-strptime-behavior",
    "https://scikit-learn.org/stable/modules/ensemble.html",
    "https://xgboost.readthedocs.io/en/stable/python/python_intro.html",
    "https://streamlit.io/components?category=charts",
    "https://pypi.org/project/scikit-learn/",
    "https://pypi.org/project/joblib/",
    "https://pypi.org/project/pandas/#history",
    "https://hub.docker.com/_/python",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
    "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides",
    "https://kubernetes.io/docs/concepts/overview/what-is-kubernetes/",
    "https://react.dev/learn/describing-the-ui",
    "https://numpy.org/doc/stable/reference/generated/numpy.ndarray.html",

    # Knowledge & Academic
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Random_forest",
    "https://en.wikipedia.org/wiki/Advanced_Encryption_Standard",
    "https://arxiv.org/abs/1706.03762",
    "https://arxiv.org/abs/2301.12345",
    "https://archive.org/details/texts",
    "https://www.coursera.org/browse/data-science",
    "https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-spring-2020/",
    "https://www.nature.com/articles/d41586-024-00123-x",
    "https://plato.stanford.edu/entries/logic-classical/",

    # Cloud & Tech
    "https://aws.amazon.com/s3/pricing/",
    "https://azure.microsoft.com/en-us/products/storage/",
    "https://cloud.google.com/kubernetes-engine/docs",
    "https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/",
    "https://www.cisa.gov/topics/cyber-threats-and-advisories",
    "https://www.kernel.org/doc/html/latest/",
    "https://www.nist.gov/cyberframework",

    # E-Commerce & Media & Social
    "https://www.amazon.com/gp/help/customer/display.html?nodeId=508510",
    "https://www.apple.com/shop/accessories/all",
    "https://www.apple.com/shop/buy-iphone/iphone-15-pro",
    "https://www.linkedin.com/learning/topics/cybersecurity",
    "https://www.netflix.com/title/80186980",
    "https://www.nytimes.com/section/technology",
    "https://www.nytimes.com/interactive/2024/briefing/news-quiz.html",
    "https://www.cnn.com/world/europe",
    "https://www.bbc.com/sport/football",
    "https://www.bbc.com/news/technology-68500000",
    "https://www.reddit.com/r/MachineLearning/comments/12345/neural_networks",
    "https://stackoverflow.com/questions/tagged/python-3.x",
    "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
    "https://open.spotify.com/genre/classical",
    "https://www.imdb.com/title/tt0111161/",
    "https://news.ycombinator.com/item?id=38000000",
    "https://www.eff.org/pages/tools",

    # Standard HTTP (Non-HTTPS) Legitimate
    "http://example.com",
    "http://www.columbia.edu/~fdc/sample.html",
    "http://info.cern.ch/hypertext/WWW/TheProject.html",
    "http://neverssl.com",
    "http://web.mit.edu",
    "http://www.gnu.org/licenses/gpl-3.0.html",
    "http://www.worldbank.org",
    "http://www.w3.org/History.html",
    "http://legacy.python.org",
    "http://www.ietf.org/rfc/rfc2616.txt"
]

def generate_robust_training_data():
    print("Reading UCI PhiUSIIL data stream...")
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
            if lbl == "1" and len(phiusiil_legit) < 1800:
                phiusiil_legit.append(u)
            elif lbl == "0" and len(phiusiil_phish) < 2200:
                phiusiil_phish.append(u)
                
            if len(phiusiil_legit) >= 1800 and len(phiusiil_phish) >= 2200:
                break

    # Balanced benign set: 1800 domain-level from UCI + representative path/query URLs
    augmented_benign = phiusiil_legit + (REPRESENTATIVE_BENIGN_URLS * 10)[:600]
    
    all_urls = augmented_benign + phiusiil_phish
    all_labels = [0] * len(augmented_benign) + [1] * len(phiusiil_phish)
    
    print(f"Extracted URLs: {len(all_urls)} (Benign: {len(augmented_benign)}, Phish: {len(phiusiil_phish)})")
    
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
    
    # Drop duplicates to prevent split leakage
    df_clean = df.drop_duplicates().reset_index(drop=True)
    print(f"Deduplicated dataset: {df_clean.shape}")
    df_clean.to_csv(CACHE_CSV, index=False)
    print(f"Dataset saved to {CACHE_CSV}")
    return df_clean

if __name__ == "__main__":
    generate_robust_training_data()
