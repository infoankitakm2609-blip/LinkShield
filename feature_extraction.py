import math
import re
import urllib.parse
from typing import Dict, Any, List

SHORTENER_DOMAINS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "rebrand.ly", "cutt.ly",
    "tiny.cc", "lnkd.in", "s.id", "v.gd", "qr.net", "shorte.st"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "banking", "secure", "signin",
    "ebayisapi", "webscr", "confirm", "security", "paypal", "wallet",
    "recovery", "password", "authenticate", "billing", "suspended",
    "appleid", "support", "service", "credential", "auth", "access"
]

def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def is_ip_address(hostname: str) -> int:
    """Detects whether hostname is an IPv4 or IPv6 address."""
    # IPv4 regex
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, hostname):
        return 1
    # Check for hex/octal or IPv6 bracketed
    if ":" in hostname:
        return 1
    return 0

def extract_features(url: str) -> Dict[str, Any]:
    """
    Extracts lexical, structural, statistical, and security features from a URL.
    Returns a dictionary of features strictly computable from the URL string.
    """
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    
    # Clean domain (strip port if present)
    domain = hostname.split(':')[0]
    
    # Subdomain calculation
    parts = domain.split('.')
    # If standard domain e.g. sub.example.com -> parts length 3 -> subdomains = max(0, 3 - 2)
    # Check if parts end in common 2-level TLDs like co.uk
    num_parts = len(parts)
    if num_parts > 2:
        if parts[-2] in {"co", "com", "org", "gov", "edu", "net"} and parts[-1] in {"uk", "in", "au", "br", "za"}:
            num_subdomains = max(0, num_parts - 3)
        else:
            num_subdomains = max(0, num_parts - 2)
    else:
        num_subdomains = 0

    url_lower = url.lower()
    domain_lower = domain.lower()
    path_lower = path.lower()

    # Feature metrics
    url_len = len(url)
    domain_len = len(domain)
    path_len = len(path)
    
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_at = url.count('@')
    num_question = url.count('?')
    num_percent = url.count('%')
    num_equal = url.count('=')
    num_slash = url.count('/')
    num_ampersand = url.count('&')
    num_underscore = url.count('_')
    
    # Digits count
    num_digits = sum(c.isdigit() for c in url)
    digit_ratio = round(num_digits / max(1, url_len), 4)

    # Entropy
    url_entropy = calculate_entropy(url)
    domain_entropy = calculate_entropy(domain)

    # HTTPS check
    has_https = 1 if parsed.scheme.lower() == "https" else 0
    # Misplaced HTTPS (https in domain/path e.g. http://paypal.com-https.secure...)
    https_in_domain = 1 if "https" in domain_lower else 0

    # IP address
    has_ip = is_ip_address(domain)

    # URL Shortening service
    is_shortened = 1 if domain_lower in SHORTENER_DOMAINS else 0

    # Suspicious keywords count in URL
    suspicious_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    suspicious_in_domain = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in domain_lower)

    # Special characters ratio
    special_chars = set("!#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
    num_special = sum(1 for c in url if c in special_chars)
    special_char_ratio = round(num_special / max(1, url_len), 4)

    return {
        "url_length": url_len,
        "domain_length": domain_len,
        "path_length": path_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_subdomains": num_subdomains,
        "num_slash": num_slash,
        "num_question": num_question,
        "num_equal": num_equal,
        "num_at": num_at,
        "num_percent": num_percent,
        "num_ampersand": num_ampersand,
        "num_underscore": num_underscore,
        "num_digits": num_digits,
        "digit_ratio": digit_ratio,
        "url_entropy": url_entropy,
        "domain_entropy": domain_entropy,
        "has_https": has_https,
        "https_in_domain": https_in_domain,
        "is_ip": has_ip,
        "is_shortened": is_shortened,
        "suspicious_keyword_count": suspicious_count,
        "suspicious_in_domain": suspicious_in_domain,
        "special_char_ratio": special_char_ratio
    }

FEATURE_COLUMNS: List[str] = [
    "url_length",
    "domain_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_subdomains",
    "num_slash",
    "num_question",
    "num_equal",
    "num_at",
    "num_percent",
    "num_ampersand",
    "num_underscore",
    "num_digits",
    "digit_ratio",
    "url_entropy",
    "domain_entropy",
    "has_https",
    "https_in_domain",
    "is_ip",
    "is_shortened",
    "suspicious_keyword_count",
    "suspicious_in_domain",
    "special_char_ratio"
]
