import os
import ssl
import socket
import datetime
import requests
import tldextract
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()

DEFAULT_TIMEOUT = 5  # 5 seconds to avoid freezing

class APIServices:
    """External threat intelligence and domain security lookup services."""

    @staticmethod
    def check_virustotal(url: str) -> Dict[str, Any]:
        """
        Queries VirusTotal API v3 for URL reputation.
        Returns detection statistics and engine categories.
        """
        if not VIRUSTOTAL_API_KEY:
            return {
                "available": False,
                "status": "API key not configured",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total": 0,
                "permalink": ""
            }

        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Accept": "application/json"
        }
        
        # VirusTotal v3 requires base64 URL identifier without padding
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        try:
            response = requests.get(endpoint, headers=headers, timeout=DEFAULT_TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                return {
                    "available": True,
                    "status": "Success",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values()),
                    "permalink": f"https://www.virustotal.com/gui/url/{url_id}"
                }
            elif response.status_code == 404:
                return {
                    "available": True,
                    "status": "URL not seen in VirusTotal database yet",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "total": 0,
                    "permalink": ""
                }
            elif response.status_code == 429:
                return {"available": False, "status": "Rate limit exceeded (429)", "malicious": 0}
            else:
                return {"available": False, "status": f"HTTP {response.status_code}", "malicious": 0}
        except requests.exceptions.Timeout:
            return {"available": False, "status": "Request timed out", "malicious": 0}
        except Exception as e:
            return {"available": False, "status": f"Connection error: {str(e)}", "malicious": 0}

    @staticmethod
    def check_google_safe_browsing(url: str) -> Dict[str, Any]:
        """
        Queries Google Safe Browsing Lookup API v4.
        """
        if not GOOGLE_SAFE_BROWSING_API_KEY:
            return {
                "available": False,
                "status": "API key not configured",
                "is_threat": False,
                "threat_types": []
            }

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {
                "clientId": "linkshield-threat-scanner",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            response = requests.post(endpoint, json=payload, timeout=DEFAULT_TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                matches = data.get("matches", [])
                if matches:
                    threat_types = list(set([m.get("threatType") for m in matches if m.get("threatType")]))
                    return {
                        "available": True,
                        "status": "Threat detected",
                        "is_threat": True,
                        "threat_types": threat_types
                    }
                else:
                    return {
                        "available": True,
                        "status": "No threats detected in database",
                        "is_threat": False,
                        "threat_types": []
                    }
            elif response.status_code == 429:
                return {"available": False, "status": "Rate limit exceeded (429)", "is_threat": False, "threat_types": []}
            else:
                return {"available": False, "status": f"HTTP {response.status_code}", "is_threat": False, "threat_types": []}
        except requests.exceptions.Timeout:
            return {"available": False, "status": "Request timed out", "is_threat": False, "threat_types": []}
        except Exception as e:
            return {"available": False, "status": f"Connection error: {str(e)}", "is_threat": False, "threat_types": []}

    @staticmethod
    def check_phishtank(url: str) -> Dict[str, Any]:
        """
        Queries PhishTank API for URL status.
        """
        endpoint = "https://checkurl.phishtank.com/checkurl/"
        data = {
            "url": url,
            "format": "json"
        }
        if PHISHTANK_API_KEY:
            data["app_key"] = PHISHTANK_API_KEY

        headers = {
            "User-Agent": "phishtank/LinkShield-1.0"
        }

        try:
            response = requests.post(endpoint, data=data, headers=headers, timeout=DEFAULT_TIMEOUT)
            if response.status_code == 200:
                res_json = response.json()
                results = res_json.get("results", {})
                is_phish = results.get("in_database", False) and results.get("valid", False)
                return {
                    "available": True,
                    "status": "In database" if is_phish else "Not listed as active phish",
                    "is_phish": bool(is_phish),
                    "verified": results.get("verified", False),
                    "phish_id": results.get("phish_id")
                }
            else:
                return {"available": False, "status": f"HTTP {response.status_code}", "is_phish": False}
        except requests.exceptions.Timeout:
            return {"available": False, "status": "Request timed out", "is_phish": False}
        except Exception as e:
            return {"available": False, "status": f"Lookup skipped: {str(e)}", "is_phish": False}

    @staticmethod
    def get_ssl_and_domain_info(url: str) -> Dict[str, Any]:
        """
        Inspects SSL certificate and domain details without opening HTTP page.
        Safe against SSRF and malicious scripts.
        """
        ext = tldextract.extract(url)
        domain = ext.registered_domain
        hostname = ext.fqdn or domain

        info = {
            "domain": domain,
            "hostname": hostname,
            "ssl_valid": False,
            "ssl_issuer": None,
            "ssl_expiry": None,
            "ssl_days_left": None,
            "ssl_error": None
        }

        if not hostname:
            info["ssl_error"] = "No hostname"
            return info

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    # Extract issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    info["ssl_issuer"] = issuer.get('organizationName') or issuer.get('commonName')
                    # Expiry date
                    not_after_str = cert.get('notAfter')
                    if not_after_str:
                        not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        info["ssl_expiry"] = not_after.strftime("%Y-%m-%d")
                        days_left = (not_after - datetime.datetime.utcnow()).days
                        info["ssl_days_left"] = days_left
                        info["ssl_valid"] = days_left > 0
                    else:
                        info["ssl_valid"] = True
        except ssl.SSLCertVerificationError as e:
            info["ssl_valid"] = False
            info["ssl_error"] = f"Certificate verification failed: {e.verify_message}"
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            info["ssl_valid"] = False
            info["ssl_error"] = f"SSL check unavailable: {type(e).__name__}"
        except Exception as e:
            info["ssl_valid"] = False
            info["ssl_error"] = str(e)

        return info
