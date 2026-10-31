import re
import ipaddress
import urllib.parse
from typing import Tuple, Optional

# Private / local IP ranges and loopbacks to prevent SSRF
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "loopback",
    "127.0.0.1",
    "0.0.0.0",
    "metadata.google.internal",
    "169.254.169.254"
}

def sanitize_url(raw_url: str) -> str:
    """Strip whitespace, unprintable characters, and surrounding quotes."""
    if not raw_url:
        return ""
    cleaned = raw_url.strip().strip("'\"<>")
    # If no protocol is specified, prepend https://
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', cleaned):
        cleaned = "https://" + cleaned
    return cleaned

def validate_url(raw_url: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates a URL against format, scheme, and SSRF restrictions.
    Returns: (is_valid, message, normalized_url)
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "URL cannot be empty.", None

    url = sanitize_url(raw_url)
    
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return False, f"Malformed URL: {str(e)}", None

    # Scheme check
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unsupported URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed.", None

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid domain or IP address.", None

    hostname_lower = hostname.lower()

    # SSRF Protection: Block localhost and known metadata hosts
    if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith(".local") or hostname_lower.endswith(".internal"):
        return False, f"Access to internal or local hostname '{hostname}' is blocked for security (SSRF prevention).", None

    # Check if host is an IP address
    try:
        ip_obj = ipaddress.ip_address(hostname_lower)
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in net:
                return False, f"Private / loopback IP address '{hostname}' is blocked for security (SSRF prevention).", None
    except ValueError:
        # Not an IP address, proceed with domain checks
        pass

    # Domain syntax checks
    domain_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    # Check either it's a valid public IP or a valid domain syntax
    is_valid_domain = bool(domain_pattern.match(hostname_lower))
    
    # Allow valid public IPs
    is_public_ip = False
    try:
        ip = ipaddress.ip_address(hostname_lower)
        is_public_ip = not ip.is_private and not ip.is_loopback and not ip.is_link_local
    except ValueError:
        is_public_ip = False

    if not is_valid_domain and not is_public_ip:
        return False, f"Invalid domain syntax or unresolvable hostname format: '{hostname}'", None

    # URL length sanity check (max 2048 chars standard)
    if len(url) > 2048:
        return False, "URL exceeds maximum allowable length of 2048 characters.", None

    return True, "Valid URL.", url
