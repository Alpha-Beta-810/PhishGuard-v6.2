# ================================================================
# feature_extractor.py — PhishGuard v3
# Unified feature extraction: URL structure + WHOIS + SSL + Lexical
# Used by BOTH training pipeline and Flask backend.
# ================================================================

import re
import math
import ssl
import socket
import datetime
import hashlib
import json
import os
from urllib.parse import urlparse, parse_qs
from collections import Counter

# ── Optional: python-whois (pip install python-whois) ──────────
try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# ── Brand list ─────────────────────────────────────────────────
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "twitter": "twitter.com",
    "bankofamerica": "bankofamerica.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "steam": "steampowered.com",
    "ebay": "ebay.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "whatsapp": "whatsapp.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "blockchain": "blockchain.com",
    "metamask": "metamask.io",
    "gmail": "gmail.com",
    "yahoo": "yahoo.com",
    "outlook": "outlook.com",
    "office": "office.com",
    "zoom": "zoom.us",
    "docusign": "docusign.com",
    # Extended Microsoft properties — these are legit, not impersonation
    "microsoftonline": "microsoftonline.com",
    "onedrive": "onedrive.live.com",
    "sharepoint": "sharepoint.com",
    "azurewebsites": "azurewebsites.net",
    # Extended Google
    "googleapis": "googleapis.com",
    "googleusercontent": "googleusercontent.com",
    # Extended Amazon
    "amazonaws": "amazonaws.com",
    "cloudfront": "cloudfront.net",
    # Other common legitimate
    "github": "github.com",
    "githubusercontent": "githubusercontent.com",
    "netlify": "netlify.app",
    "vercel": "vercel.app",
    "shopify": "shopify.com",
    "stripe": "stripe.com",
    "cloudflare": "cloudflare.com",
    "discord": "discord.com",
    "telegram": "telegram.org",
    "spotify": "spotify.com",
    "flipkart": "flipkart.com",
    "irctc": "irctc.co.in",
}

# Top-50 brand SLDs for Levenshtein typosquat detection
TOP_BRAND_SLDS = [
    "paypal","apple","google","microsoft","amazon","netflix","facebook",
    "instagram","linkedin","twitter","chase","wellsfargo","dropbox","adobe",
    "ebay","dhl","fedex","coinbase","binance","gmail","yahoo","outlook",
    "office","zoom","docusign","instagram","whatsapp","steam","bankofamerica",
]

HIGH_RISK_TLDS = {
    "tk","ml","ga","cf","gq","xyz","top","club","work",
    "click","link","online","site","info","pw","cc","su","ws","live",
    "icu","fun","vip","win","bid","trade","loan","stream",
}

SUSPICIOUS_KEYWORDS = [
    "login","verify","update","secure","account","bank","signin","webscr",
    "confirm","password","credential","support","billing","invoice","alert",
    "limited","suspended","unauthorized","validate","recover","unlock",
    "unusual","activity","notification","urgent","immediately",
]

# ── Simple Levenshtein (no external lib needed) ─────────────────
def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (0 if c1 == c2 else 1)))
        prev = curr
    return prev[-1]

def _min_brand_distance(sld: str) -> int:
    """Minimum Levenshtein distance from sld to any known brand."""
    if not sld:
        return 99
    return min(_levenshtein(sld.lower(), brand) for brand in TOP_BRAND_SLDS)

def _longest_token(url: str) -> int:
    tokens = re.split(r'[-_./=?&]', url)
    return max((len(t) for t in tokens), default=0)

def _vowel_ratio(s: str) -> float:
    letters = [c for c in s.lower() if c.isalpha()]
    if not letters:
        return 0.0
    vowels = sum(1 for c in letters if c in 'aeiou')
    return vowels / len(letters)

# ── Core helpers ───────────────────────────────────────────────
def _strip_protocol(url: str) -> str:
    return re.sub(r'^https?://', '', url.strip(), flags=re.IGNORECASE)

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

def _is_punycode_or_homoglyph(domain: str) -> int:
    if domain.startswith("xn--") or ".xn--" in domain:
        return 1
    try:
        domain.encode('ascii')
        return 0
    except UnicodeEncodeError:
        return 1

# ccTLD patterns for known brands: e.g. amazon.in, amazon.co.uk
# A domain like amazon.in is legitimate even though it doesn't end with amazon.com
_BRAND_CCTLD_PATTERN = re.compile(
    r'^(?:www\.)?([a-z0-9-]+)\.'      # optional www + SLD
    r'(?:co\.(?:uk|in|jp|au|nz|za)|'   # co.XX two-part ccTLD
    r'com\.(?:au|br|mx|ar|sg)|'         # com.XX two-part ccTLD
    r'[a-z]{2})$'                        # simple single ccTLD
)

def _check_brand_impersonation(domain: str) -> int:
    """
    Returns 1 if the domain impersonates a known brand but is NOT an
    official domain for that brand.

    Correctly handles:
    - ccTLD regional variants: amazon.in, google.co.uk → NOT impersonation
    - Subdomains of official domains: login.microsoftonline.com → NOT impersonation
    - Spoof attempts: amazon-secure.xyz, paypal-login.tk → IS impersonation

    Algorithm:
    1. Collect all brands whose name appears in the domain.
    2. For each matched brand, check if it is legitimate (official/ccTLD/subdomain).
    3. If ALL matching brands are legitimately resolved → not impersonation.
    4. If ANY brand cannot be resolved as legitimate → impersonation.
    """
    d = domain.lower()
    if d.startswith('www.'):
        d = d[4:]

    impersonation_found = False

    for brand, real_base in KNOWN_BRANDS.items():
        if brand not in d:
            continue

        # ── Legitimate checks (any of these → skip this brand, not impersonation) ──
        # 1. Exact match or direct subdomain of the canonical domain
        if d == real_base or d.endswith('.' + real_base):
            continue

        # 2. SLD exactly equals brand → legit regional/ccTLD variant
        #    e.g. amazon.in → parts[0]="amazon" = brand → legit
        #    e.g. amazon.co.uk → parts[0]="amazon" = brand → legit
        parts = d.split('.')
        sld = parts[0]  # always the leftmost part of the registered domain
        # For subdomains like login.amazon.in, sld check should use the domain part
        # Detect subdomain: if there are 3+ parts and none of the middle parts are ccTLD bridges
        if len(parts) >= 3:
            # Check if it's a subdomain of a ccTLD brand: login.amazon.in
            # The registered domain would be parts[-3] if parts[-2] in (co,com,net)
            # else parts[-2]
            if parts[-2] in ('co', 'com', 'net', 'org', 'gov', 'ac', 'edu'):
                # Two-part TLD: e.g. amazon.co.uk → registered = amazon
                reg_domain = parts[-3] if len(parts) >= 4 else parts[0]
            else:
                # Single TLD: e.g. login.amazon.in → registered = amazon
                reg_domain = parts[-2]
            if reg_domain == brand:
                continue  # Subdomain of a legit ccTLD brand variant
        elif len(parts) == 2:
            # e.g. amazon.in → parts[0] = amazon
            if sld == brand:
                continue

        # 3. The domain ends with a known official variant of this brand's parent domains
        #    (covers cases like login.microsoftonline.com where microsoftonline is in KNOWN_BRANDS)
        brand_is_legit_parent = any(
            d == b_real or d.endswith('.' + b_real)
            for b_real in KNOWN_BRANDS.values()
            if b_real != real_base and brand in b_real
        )
        if brand_is_legit_parent:
            continue

        # ── None of the legitimate checks passed → brand is being impersonated ──
        impersonation_found = True
        break

    return int(impersonation_found)

def _get_tld(domain: str) -> str:
    parts = domain.rstrip('.').split('.')
    return parts[-1].lower() if parts else ""

def _get_sld(domain: str) -> str:
    parts = domain.rstrip('.').split('.')
    return parts[-2].lower() if len(parts) >= 2 else ""

def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isdigit() for c in s) / len(s)


# ── Phase 1: WHOIS features ────────────────────────────────────
_whois_cache: dict = {}

def get_whois_features(domain: str, timeout: int = 5) -> dict:
    """
    Fetch WHOIS data and return domain-age features.
    Returns safe defaults on failure so training/inference never crash.
    Caches results to avoid repeated lookups.
    """
    defaults = {
        "domain_age_days": -1,       # -1 = unknown (treat as suspicious)
        "domain_age_known": 0,
        "domain_very_new": 1,        # assume new until proven otherwise
        "whois_privacy": 0,
    }

    if not WHOIS_AVAILABLE:
        return defaults

    # Strip subdomains for WHOIS lookup
    parts = domain.split('.')
    base = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

    if base in _whois_cache:
        return _whois_cache[base]

    try:
        socket.setdefaulttimeout(timeout)
        w = whois_lib.whois(base)

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        if created is None:
            _whois_cache[base] = defaults
            return defaults

        if isinstance(created, str):
            # Try to parse string dates
            for fmt in ('%Y-%m-%d', '%d-%b-%Y', '%Y-%m-%dT%H:%M:%SZ'):
                try:
                    created = datetime.datetime.strptime(created, fmt)
                    break
                except Exception:
                    continue

        age_days = (datetime.datetime.now() - created).days

        # Check for privacy protection keywords in registrant
        privacy_keywords = ["privacy", "protected", "redacted", "proxy", "guard", "whoisguard"]
        registrant = str(w.get('registrant_name', '') or '').lower()
        has_privacy = int(any(k in registrant for k in privacy_keywords))

        result = {
            "domain_age_days": min(age_days, 9999),  # cap for model stability
            "domain_age_known": 1,
            "domain_very_new": int(age_days < 30),
            "whois_privacy": has_privacy,
        }
        _whois_cache[base] = result
        return result

    except Exception:
        _whois_cache[base] = defaults
        return defaults
    finally:
        # CRITICAL: reset global socket timeout so Flask sockets are not affected
        socket.setdefaulttimeout(None)


# ── Phase 2: SSL Certificate features ─────────────────────────
_ssl_cache: dict = {}

def get_ssl_features(domain: str, timeout: int = 5) -> dict:
    """
    Check SSL certificate and return cert-based features.
    Returns safe defaults on failure.
    """
    defaults = {
        "has_ssl": 0,
        "ssl_cert_age_days": -1,
        "ssl_cert_known": 0,
        "ssl_cert_very_new": 1,
        "ssl_self_signed": 1,
        "ssl_domain_mismatch": 1,
    }

    # Strip port if present
    base_domain = domain.split(':')[0]
    parts = base_domain.split('.')
    base = '.'.join(parts[-2:]) if len(parts) >= 2 else base_domain

    if base in _ssl_cache:
        return _ssl_cache[base]

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        with socket.create_connection((base_domain, 443), timeout=min(timeout, 4)) as sock:
            with ctx.wrap_socket(sock, server_hostname=base_domain) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            _ssl_cache[base] = defaults
            return defaults

        # Parse not_before date
        not_before_str = cert.get('notBefore', '')
        try:
            not_before = datetime.datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
            cert_age_days = (datetime.datetime.now() - not_before).days
        except Exception:
            cert_age_days = -1

        # Check issuer for self-signed (issuer == subject)
        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        self_signed = int(issuer == subject)

        # Check SAN / CN matches domain
        san_list = []
        for san_type, san_val in cert.get('subjectAltName', []):
            if san_type == 'DNS':
                san_list.append(san_val.lower().lstrip('*.'))
        cn = subject.get('commonName', '').lower().lstrip('*.')
        all_names = san_list + ([cn] if cn else [])
        domain_match = any(base_domain.endswith(n) or n.endswith(base_domain) for n in all_names)

        result = {
            "has_ssl": 1,
            "ssl_cert_age_days": min(cert_age_days, 9999),
            "ssl_cert_known": 1,
            "ssl_cert_very_new": int(cert_age_days >= 0 and cert_age_days < 7),
            "ssl_self_signed": self_signed,
            "ssl_domain_mismatch": int(not domain_match),
        }
        _ssl_cache[base] = result
        return result

    except Exception:
        _ssl_cache[base] = defaults
        return defaults


# ── Main feature extraction ────────────────────────────────────
def extract_features(
    url: str,
    include_whois: bool = False,
    include_ssl: bool = False,
) -> dict:
    """
    Extract all URL features. WHOIS and SSL are off by default for
    fast batch training — enable them for live inference in the backend.
    """
    clean_url = _strip_protocol(url)
    parsed = urlparse("http://" + clean_url)
    domain = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment
    domain_parts = [p for p in domain.split('.') if p]
    tld = _get_tld(domain)
    sld = _get_sld(domain)
    subdomain_parts = domain_parts[:-2] if len(domain_parts) > 2 else []
    domain_no_dots = domain.replace('.', '')

    suspicious_count = sum(kw in clean_url.lower() for kw in SUSPICIOUS_KEYWORDS)
    brand_dist = _min_brand_distance(sld)

    features = {
        # ── URL length ───────────────────────────────────────
        "url_length":               len(clean_url),
        "domain_length":            len(domain),
        "path_length":              len(path),
        "query_length":             len(query),

        # ── Structure ────────────────────────────────────────
        "num_dots":                 clean_url.count('.'),
        "num_hyphens":              clean_url.count('-'),
        "num_slashes":              clean_url.count('/'),
        "num_query_params":         len(parse_qs(query)),
        "num_subdomains":           len(subdomain_parts),
        "path_depth":               len([p for p in path.split('/') if p]),

        # ── Symbol flags ─────────────────────────────────────
        "has_at_symbol":            int('@' in clean_url),
        "has_double_slash":         int('//' in path),
        "has_percent_encoding":     int('%' in clean_url),
        "has_fragment":             int(bool(fragment)),
        "has_port_in_url":          int(bool(re.search(r':\d{2,5}(?:/|$)', domain))),

        # ── IP ───────────────────────────────────────────────
        "has_ip_address":           int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}', domain))),

        # ── Domain composition ───────────────────────────────
        "domain_digit_ratio":       round(_digit_ratio(domain_no_dots), 4),
        "domain_entropy":           round(_shannon_entropy(domain_no_dots), 4),
        "subdomain_length":         len('.'.join(subdomain_parts)),
        "has_high_risk_tld":        int(tld in HIGH_RISK_TLDS),

        # ── Suspicious content ───────────────────────────────
        "has_suspicious_keyword":   int(suspicious_count > 0),
        "suspicious_keyword_count": suspicious_count,

        # ── Brand / IDN ──────────────────────────────────────
        "has_brand_impersonation":  _check_brand_impersonation(domain),
        "has_punycode_homoglyph":   _is_punycode_or_homoglyph(domain),

        # ── Obfuscation ──────────────────────────────────────
        "url_entropy":              round(_shannon_entropy(clean_url), 4),
        "has_hex_chars":            int(bool(re.search(r'%[0-9a-fA-F]{2}', clean_url))),

        # ── Phase 1: Lexical deep features ───────────────────
        "longest_token":            _longest_token(clean_url),
        "vowel_ratio":              round(_vowel_ratio(domain_no_dots), 4),
        "min_brand_levenshtein":    brand_dist,
        "is_typosquat":             int(0 < brand_dist <= 2),  # close but not exact match
        "unique_char_ratio":        round(len(set(domain_no_dots)) / max(len(domain_no_dots), 1), 4),
        "has_repeated_digits":      int(bool(re.search(r'\d{4,}', domain))),
    }

    # ── Phase 1: WHOIS features (live only or when enabled) ──
    if include_whois:
        features.update(get_whois_features(domain))
    else:
        features.update({
            "domain_age_days": -1,
            "domain_age_known": 0,
            "domain_very_new": 0,   # neutral during training
            "whois_privacy": 0,
        })

    # ── Phase 2: SSL features (live only or when enabled) ────
    if include_ssl:
        features.update(get_ssl_features(domain))
    else:
        features.update({
            "has_ssl": int(url.lower().startswith('https')),
            "ssl_cert_age_days": -1,
            "ssl_cert_known": 0,
            "ssl_cert_very_new": 0,
            "ssl_self_signed": 0,
            "ssl_domain_mismatch": 0,
        })

    return features


# ── Feature column order (must match training) ─────────────────
FEATURE_COLUMNS = list(extract_features("http://example.com").keys())

URL_ONLY_FEATURES = [f for f in FEATURE_COLUMNS if f not in {
    "domain_age_days", "domain_age_known", "domain_very_new", "whois_privacy",
    "has_ssl", "ssl_cert_age_days", "ssl_cert_known",
    "ssl_cert_very_new", "ssl_self_signed", "ssl_domain_mismatch",
}]


if __name__ == "__main__":
    tests = [
        "https://paypal-secure-login.xyz/verify/account?id=123",
        "https://google.com",
        "http://192.168.1.1/admin/login.php",
        "https://g00gle.com",                  # typosquat
        "https://www.amazon-support-billing.tk/update",
        "https://microsoft.com",
    ]
    for url in tests:
        f = extract_features(url)
        print(f"\n🔗 {url}")
        print(f"   brand_dist={f['min_brand_levenshtein']}  typosquat={f['is_typosquat']}  "
              f"longest_token={f['longest_token']}  entropy={f['domain_entropy']}")
        risky = {k: v for k, v in f.items() if v not in (0, 0.0, -1, '')}
        for k, v in list(risky.items())[:8]:
            print(f"   {k}: {v}")
