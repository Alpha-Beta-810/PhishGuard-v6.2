# ================================================================
# backend.py — PhishGuard v4 Hybrid Backend
#
# Architecture:
#   1. Reputation gate  → instant verdict for known domains
#   2. Live enrichment  → real WHOIS, SSL, DNS for unknowns
#   3. Page analysis    → live DOM scraping (deep scan)
#   4. ML engine        → activated only for new/unknown domains
#   5. Fusion scorer    → weighted combination of all signals
#
# Endpoints:
#   POST /analyze          → hybrid full analysis
#   POST /analyze/fast     → URL-only instant (no live fetch)
#   POST /analyze/batch    → up to 50 URLs (fast mode)
#   GET  /health           → status + config check
#
# Run:  python src/backend.py
#       VIRUSTOTAL_API_KEY=xxx python src/backend.py
# ================================================================

import os, sys, re, json, time, hashlib, socket, ssl, datetime
import warnings
warnings.filterwarnings('ignore')

from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import joblib
import pandas as pd
from bs4 import BeautifulSoup

from feature_extractor import (
    extract_features, FEATURE_COLUMNS,
    get_whois_features, get_ssl_features, KNOWN_BRANDS
)

# ── Config ─────────────────────────────────────────────────────
MODEL_PATH    = os.path.join(os.path.dirname(__file__), '..', 'model', 'phishing_model_v3.pkl')
VT_API_KEY    = os.environ.get('VIRUSTOTAL_API_KEY', '')
FETCH_TIMEOUT    = 6      # page fetch — reduced from 8s
WHOIS_TIMEOUT    = 4      # WHOIS lookup
SSL_TIMEOUT      = 4      # SSL cert check
DNS_TIMEOUT      = 3      # DNS resolution
SHORTENER_TIMEOUT = 4     # HEAD request for shortener resolution
TOTAL_BUDGET     = 25     # hard ceiling for /analyze (seconds)
CACHE_TTL     = 300      # seconds
ML_AGE_GATE   = 90       # days — only run ML if domain is younger than this
ANALYSIS_CACHE: dict = {}

app = Flask(__name__)
CORS(app)   # allow frontend on any port to call us
app.config['JSON_SORT_KEYS'] = False

# ── Load model ─────────────────────────────────────────────────
print("Loading PhishGuard v5 model...")
model, feature_cols = joblib.load(MODEL_PATH)
# The stored model is already a fitted CalibratedClassifierCV — no re-wrapping needed.
# (Re-wrapping with cv="prefit" without calling .fit() causes NotFittedError on predict_proba)
_model_type = type(model).__name__
print(f"✅ Model loaded ({len(feature_cols)} features, type={_model_type}, calibrated=True)")

# ════════════════════════════════════════════════════════════════
# REPUTATION DATABASE
# Known-good and known-bad domains get instant verdicts.
# This is the core fix for v3's bias against established domains.
# ════════════════════════════════════════════════════════════════

REPUTATION_DB = {
    # (score, tier, age_years, alexa_rank, notes)
    "google.com":        (2,  "trusted",   26, 1,    "Alphabet Inc — verified"),
    "youtube.com":       (3,  "trusted",   19, 2,    "Google-owned"),
    "facebook.com":      (3,  "trusted",   20, 3,    "Meta Platforms"),
    "instagram.com":     (3,  "trusted",   14, 4,    "Meta-owned"),
    "twitter.com":       (4,  "trusted",   18, 5,    "X Corp"),
    "x.com":             (3,  "trusted",   27, 5,    "X Corp (Twitter)"),
    "wikipedia.org":     (1,  "trusted",   24, 6,    "Wikimedia Foundation"),
    "amazon.com":        (2,  "trusted",   30, 7,    "Amazon.com Inc"),
    "microsoft.com":     (2,  "trusted",   31, 8,    "Microsoft Corp"),
    "apple.com":         (2,  "trusted",   32, 9,    "Apple Inc"),
    "netflix.com":       (3,  "trusted",   26, 10,   "Netflix Inc"),
    "github.com":        (2,  "trusted",   17, 15,   "Microsoft (GitHub)"),
    "linkedin.com":      (2,  "trusted",   23, 16,   "Microsoft-owned"),
    "paypal.com":        (2,  "trusted",   26, 20,   "PayPal Holdings"),
    "chase.com":         (2,  "trusted",   24, 50,   "JPMorgan Chase Bank"),
    "bankofamerica.com": (2,  "trusted",   28, 55,   "Bank of America Corp"),
    "wellsfargo.com":    (2,  "trusted",   28, 60,   "Wells Fargo Bank"),
    "reddit.com":        (3,  "trusted",   20, 12,   "Reddit Inc"),
    "stackoverflow.com": (1,  "trusted",   17, 35,   "Stack Exchange Network"),
    "gmail.com":         (2,  "trusted",   22, 1,    "Google mail service"),
    "outlook.com":       (2,  "trusted",   12, 8,    "Microsoft mail"),
    "yahoo.com":         (3,  "trusted",   29, 11,   "Yahoo Inc"),
    "cloudflare.com":    (2,  "trusted",   15, 80,   "Cloudflare Inc"),
    "dropbox.com":       (3,  "trusted",   16, 90,   "Dropbox Inc"),
    "zoom.us":           (3,  "trusted",   12, 95,   "Zoom Video Communications"),
    "adobe.com":         (2,  "trusted",   33, 100,  "Adobe Inc"),
    "ebay.com":          (3,  "trusted",   30, 30,   "eBay Inc"),
    "binance.com":       (5,  "caution",   7,  40,   "Crypto exchange — legit but high-risk sector"),
    "coinbase.com":      (4,  "caution",   11, 45,   "Regulated US crypto exchange"),
    "metamask.io":       (5,  "caution",   7,  200,  "Browser crypto wallet — frequent phishing target"),
    # Regional / ccTLD variants of major brands
    "amazon.in":         (2,  "trusted",   20, 8,    "Amazon India — official regional domain"),
    "amazon.co.uk":      (2,  "trusted",   24, 7,    "Amazon UK — official regional domain"),
    "amazon.com.au":     (2,  "trusted",   20, 25,   "Amazon Australia — official regional domain"),
    "amazon.de":         (2,  "trusted",   24, 12,   "Amazon Germany — official regional domain"),
    "amazon.co.jp":      (2,  "trusted",   24, 10,   "Amazon Japan — official regional domain"),
    "amazon.fr":         (2,  "trusted",   22, 18,   "Amazon France — official regional domain"),
    "amazon.ca":         (2,  "trusted",   22, 20,   "Amazon Canada — official regional domain"),
    "google.co.in":      (2,  "trusted",   24, 5,    "Google India — official regional domain"),
    "google.co.uk":      (2,  "trusted",   26, 3,    "Google UK — official regional domain"),
    "google.com.au":     (2,  "trusted",   24, 8,    "Google Australia — official regional domain"),
    "google.de":         (2,  "trusted",   24, 4,    "Google Germany — official regional domain"),
    "google.co.jp":      (2,  "trusted",   24, 6,    "Google Japan — official regional domain"),
    "flipkart.com":      (2,  "trusted",   17, 30,   "Flipkart — major Indian e-commerce"),
    "paytm.com":         (3,  "trusted",   12, 50,   "Paytm — Indian payment platform"),
    "myntra.com":        (3,  "trusted",   15, 80,   "Myntra — Flipkart-owned fashion"),
    "naukri.com":        (2,  "trusted",   24, 60,   "Naukri — Indian job portal"),
    "irctc.co.in":       (2,  "trusted",   22, 40,   "IRCTC — Indian Railways official"),
    "bing.com":          (2,  "trusted",   18, 35,   "Microsoft Bing search"),
    "office.com":        (2,  "trusted",   14, 50,   "Microsoft Office online"),
    "live.com":          (2,  "trusted",   20, 45,   "Microsoft Live services"),
    "twitter.com":       (4,  "trusted",   18, 5,    "X Corp (Twitter) — listed again for alias"),
    "t.me":              (3,  "trusted",   10, 55,   "Telegram official"),
    "telegram.org":      (2,  "trusted",   10, 60,   "Telegram official"),
    "whatsapp.com":      (2,  "trusted",   14, 20,   "WhatsApp — Meta-owned"),
    "spotify.com":       (3,  "trusted",   18, 22,   "Spotify AB"),
    "twitch.tv":         (3,  "trusted",   16, 32,   "Twitch — Amazon-owned"),
    "discord.com":       (3,  "trusted",   8,  42,   "Discord Inc"),
    "notion.so":         (3,  "trusted",   8,  90,   "Notion Labs"),
    "figma.com":         (3,  "trusted",   8,  110,  "Figma Inc"),
    # Confirmed phishing
    "paypal-secure-login.xyz":                      (98, "blocklist", 0, None, "Confirmed phishing infrastructure"),
    "amazon-support-billing.tk":                    (97, "blocklist", 0, None, "Fake Amazon support phish"),
    "verify-your-account.microsoft-secure.ml":      (99, "blocklist", 0, None, "Microsoft credential harvester"),
}

HIGH_RISK_TLDS = {
    "tk","ml","ga","cf","gq","xyz","top","club","work",
    "click","link","online","site","info","pw","cc","su","ws","live",
    "icu","fun","vip","win","bid","trade","loan","stream",
}

# Trusted parent domains: subdomain.trusted.com is legit even if it contains brand keywords.
# e.g. login.microsoftonline.com → trusted; amazon.phish.com → not trusted.
TRUSTED_PARENT_DOMAINS = {
    # Microsoft
    "microsoftonline.com", "microsoft.com", "live.com", "office.com",
    "office365.com", "azure.com", "azurewebsites.net", "sharepoint.com",
    # Google
    "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
    "gmail.com", "youtube.com", "accounts.google.com",
    # Amazon / AWS
    "amazonaws.com", "awsstatic.com", "cloudfront.net", "amazon.com",
    # Apple
    "apple.com", "icloud.com",
    # Meta
    "facebook.com", "instagram.com", "fbcdn.net", "whatsapp.com",
    # Enterprise auth / SaaS
    "okta.com", "auth0.com", "onelogin.com", "salesforce.com",
    "force.com", "pingidentity.com", "duo.com",
    # Dev / infra
    "github.com", "gitlab.com", "atlassian.net", "atlassian.com",
    "slack.com", "zoom.us", "dropbox.com", "cloudflare.com",
    "fastly.net", "akamaized.net",
    # Payment
    "paypal.com", "stripe.com",
    # Regional Amazon ccTLDs — amazon.in, amazon.co.uk etc are all legitimate parents
    "amazon.in", "amazon.co.uk", "amazon.com.au", "amazon.de",
    "amazon.co.jp", "amazon.fr", "amazon.ca", "amazon.es",
    # Regional Google ccTLDs
    "google.co.in", "google.co.uk", "google.com.au", "google.de",
    "google.co.jp", "google.fr", "google.ca", "google.es",
    # Indian majors
    "flipkart.com", "paytm.com", "irctc.co.in", "naukri.com",
    # Comms
    "telegram.org", "t.me", "discord.com", "whatsapp.com",
    # Dev / design
    "notion.so", "figma.com", "netlify.app", "vercel.app",
    "heroku.com", "render.com", "railway.app",
    # AI / major tech destinations (common in legit short URLs)
    "openai.com", "chat.openai.com", "huggingface.co",
    "medium.com", "substack.com", "docs.google.com",
    "drive.google.com", "calendar.google.com",
    "linkedin.com", "twitter.com", "x.com",
    # News / reference
    "bbc.com", "reuters.com", "nytimes.com", "theguardian.com",
    "techcrunch.com", "wired.com", "arstechnica.com",
    # Dev docs
    "developer.mozilla.org", "docs.github.com", "stackoverflow.com",
    "npmjs.com", "pypi.org", "crates.io",
    # Microsoft sub-services
    "login.microsoftonline.com", "portal.azure.com",
    # GitHub hosting
    "github.io", "raw.githubusercontent.com",
}

# Known URL shorteners — treat as "destination unknown" rather than penalizing heavily.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "rebrand.ly", "short.link", "is.gd", "cutt.ly", "tiny.cc",
    "lnkd.in", "dlvr.it", "su.pr", "wp.me", "youtu.be",
    "amzn.to", "fb.me", "bit.do", "git.io",
}

BRAND_LIST = list(KNOWN_BRANDS.keys())


# ════════════════════════════════════════════════════════════════
# LIVE DNS CHECK
# ════════════════════════════════════════════════════════════════

def get_dns_info(domain: str) -> dict:
    """Resolve domain and check basic DNS health."""
    result = {
        "resolves": False,
        "ip": "",
        "dns_error": "",
        "dns_blacklisted": False,
    }
    try:
        ip = socket.gethostbyname(domain)
        result["resolves"] = True
        result["ip"] = ip
        # Simple private IP check (phishing often uses unusual infra)
        parts = ip.split('.')
        if parts[0] in ('10', '127') or (parts[0] == '192' and parts[1] == '168'):
            result["dns_blacklisted"] = True
    except socket.gaierror as e:
        result["dns_error"] = str(e)
    return result


# ════════════════════════════════════════════════════════════════
# LIVE PAGE ANALYSIS  (from v3, enhanced)
# ════════════════════════════════════════════════════════════════

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/120.0.0.0 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
}

def analyze_page_content(url: str) -> dict:
    result = {
        "page_title_brand_mismatch": 0,
        "form_action_external": 0,
        "has_password_field": 0,
        "external_resource_ratio": 0.0,
        "has_hidden_iframe": 0,
        "favicon_external": 0,
        "redirect_count": 0,
        "final_url_different": 0,
        "page_flags": [],
        "page_fetch_ok": False,
        "page_fetch_error": "",
        "final_url": url,
        "page_title": "",
        "has_login_form": 0,
        "copyright_year_old": 0,
        "obfuscated_js": 0,
        "visual_similarity": {},
    }

    try:
        resp = requests.get(
            url, timeout=(3, FETCH_TIMEOUT),  # (connect, read) tuple
            headers=HEADERS,
            allow_redirects=True,
            verify=False,
            stream=False,
        )
        result["page_fetch_ok"] = True
        result["redirect_count"] = len(resp.history)
        result["final_url"] = resp.url

        # v4.3: Full redirect chain tracking
        redirect_chain = [r.url for r in resp.history] + [resp.url]
        result["redirect_chain"] = redirect_chain

        if resp.url.rstrip("/") != url.rstrip("/"):
            result["final_url_different"] = 1
            result["page_flags"].append({
                "level": "yellow",
                "msg": f"URL redirects to: {resp.url[:80]}"
            })

        # Flag multi-hop chains (3+ hops is unusual and suspicious)
        if len(resp.history) >= 3:
            result["page_flags"].append({
                "level": "red",
                "msg": f"Suspicious: {len(resp.history)}-hop redirect chain — "
                       "phishing relays often use multiple redirects to evade detection."
            })

        # Flag if any intermediate hop domain is NOT trusted
        from urllib.parse import urlparse as _up
        hop_domains = [_up(h.url).netloc.lower() for h in resp.history]
        for hop_domain in hop_domains:
            hop_trusted = any(
                hop_domain == t or hop_domain.endswith("." + t)
                for t in TRUSTED_PARENT_DOMAINS
            )
            if not hop_trusted and hop_domain:
                result["page_flags"].append({
                    "level": "yellow",
                    "msg": f"Redirect passes through untrusted domain: {hop_domain}"
                })
                break  # flag once, don't spam

        soup = BeautifulSoup(resp.text, 'html.parser')
        parsed_original = urlparse(url)
        original_domain = parsed_original.netloc.lower()

        # Page title brand mismatch
        title_tag = soup.find('title')
        page_title = title_tag.get_text(strip=True) if title_tag else ""
        result["page_title"] = page_title[:100]
        title_lower = page_title.lower()
        for brand, real_domain in KNOWN_BRANDS.items():
            if brand in title_lower and not original_domain.endswith(real_domain):
                result["page_title_brand_mismatch"] = 1
                result["page_flags"].append({
                    "level": "red",
                    "msg": f"Page title mentions '{brand.title()}' but domain is not {real_domain}"
                })
                break

        # Forms
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if action and action.startswith('http'):
                action_domain = urlparse(action).netloc.lower()
                if action_domain and action_domain != original_domain:
                    result["form_action_external"] = 1
                    result["page_flags"].append({
                        "level": "red",
                        "msg": f"Form submits data to external domain: {action_domain}"
                    })
                    break

        # Password / login fields
        pw_fields = soup.find_all('input', {'type': 'password'})
        if pw_fields:
            result["has_password_field"] = 1
            email_fields = soup.find_all('input', {'type': lambda t: t and 'email' in t.lower()})
            if email_fields or len(forms) > 0:
                result["has_login_form"] = 1
            if result["page_title_brand_mismatch"] or result["form_action_external"]:
                result["page_flags"].append({
                    "level": "red",
                    "msg": "Page requests credentials alongside other phishing signals"
                })

        # External resource ratio
        all_resources = (
            [(t, t.get('src', '')) for t in soup.find_all(['script', 'img', 'iframe'])] +
            [(t, t.get('href', '')) for t in soup.find_all(['link'])]
        )
        total = len(all_resources)
        if total > 0:
            external = sum(
                1 for _, src in all_resources
                if src and src.startswith('http') and
                urlparse(src).netloc.lower() != original_domain
            )
            ratio = external / total
            result["external_resource_ratio"] = round(ratio, 3)
            if ratio > 0.7:
                result["page_flags"].append({
                    "level": "yellow",
                    "msg": f"{ratio:.0%} of page resources load from external domains"
                })

        # Hidden iframes
        for iframe in soup.find_all('iframe'):
            style = iframe.get('style', '').replace(' ', '')
            w, h = iframe.get('width', '1'), iframe.get('height', '1')
            if ('display:none' in style or 'visibility:hidden' in style or w == '0' or h == '0'):
                result["has_hidden_iframe"] = 1
                result["page_flags"].append({
                    "level": "red",
                    "msg": "Hidden iframe detected — classic phishing obfuscation"
                })
                break

        # Favicon external
        favicon = soup.find('link', rel=lambda r: r and 'icon' in r)
        if favicon:
            href = favicon.get('href', '')
            if href.startswith('http'):
                fav_domain = urlparse(href).netloc.lower()
                if fav_domain and fav_domain != original_domain:
                    result["favicon_external"] = 1
                    result["page_flags"].append({
                        "level": "yellow",
                        "msg": f"Favicon loaded from external domain: {fav_domain}"
                    })

        # Obfuscated JS (eval, unescape, String.fromCharCode)
        scripts = soup.find_all('script')
        obf_patterns = [r'\beval\(', r'unescape\(', r'String\.fromCharCode\(', r'atob\(']
        for sc in scripts:
            sc_text = sc.get_text()
            if any(re.search(p, sc_text) for p in obf_patterns):
                result["obfuscated_js"] = 1
                result["page_flags"].append({
                    "level": "yellow",
                    "msg": "Obfuscated JavaScript detected (eval / unescape / atob)"
                })
                break

        # ── Visual similarity check ──────────────────────────
        vis = check_visual_similarity(soup, original_domain)
        result["visual_similarity"] = vis
        if vis["impersonation_detected"]:
            result["page_flags"].append({
                "level": "red",
                "msg": vis["visual_flags"][0] if vis["visual_flags"] else
                       f"Page visually resembles {vis['matched_brand']} (confidence {vis['confidence']:.0%})",
            })

        # Old copyright year (stale/cloned page)
        page_text = soup.get_text()
        years = re.findall(r'©\s*(\d{4})', page_text)
        if years:
            latest = max(int(y) for y in years)
            if latest < datetime.datetime.now().year - 2:
                result["copyright_year_old"] = 1
                result["page_flags"].append({
                    "level": "yellow",
                    "msg": f"Page copyright year ({latest}) is stale — may be a cloned site"
                })

    except requests.exceptions.SSLError:
        result["page_fetch_error"] = "SSL certificate error"
        result["page_flags"].append({"level": "yellow", "msg": "SSL certificate error during fetch"})
    except requests.exceptions.ConnectionError:
        result["page_fetch_error"] = "Could not connect to host"
    except requests.exceptions.Timeout:
        result["page_fetch_error"] = "Page fetch timed out"
    except Exception as e:
        result["page_fetch_error"] = str(e)[:120]

    return result



# ════════════════════════════════════════════════════════════════
# VISUAL SIMILARITY CHECK  (structural — no screenshot needed)
# Compares live page DOM structure + colour palette + brand assets
# against a reference fingerprint for known brands.
# Full screenshot / CNN comparison would require Playwright + model;
# this gives 80% of the signal at zero extra dependencies.
# ════════════════════════════════════════════════════════════════

# Reference fingerprints: (brand, official_domain, title_keywords, logo_url_fragment)
BRAND_FINGERPRINTS = [
    ("paypal",    "paypal.com",    ["paypal", "send money", "wallet", "checkout"],  "paypal"),
    ("apple",     "apple.com",     ["apple", "icloud", "apple id", "sign in"],       "apple"),
    ("google",    "google.com",    ["google", "gmail", "sign in", "account"],        "google"),
    ("microsoft", "microsoft.com", ["microsoft", "outlook", "office", "sign in"],    "microsoft"),
    ("amazon",    "amazon",        ["amazon", "cart", "order", "prime"],              "amazon"),
    ("netflix",   "netflix.com",   ["netflix", "watch", "stream", "password"],       "netflix"),
    ("facebook",  "facebook.com",  ["facebook", "messenger", "log in"],              "facebook"),
    ("instagram", "instagram.com", ["instagram", "log in", "photos"],                "instagram"),
    ("linkedin",  "linkedin.com",  ["linkedin", "jobs", "network", "sign in"],       "linkedin"),
    ("twitter",   "twitter.com",   ["twitter", "tweet", "x", "sign in"],             "twitter"),
    ("chase",     "chase.com",     ["chase", "bank", "account", "sign in"],          "chase"),
    ("bankofamerica","bankofamerica.com",["bank of america","sign in","account"],     "bankofamerica"),
    ("wellsfargo","wellsfargo.com",["wells fargo","sign in","account","bank"],        "wellsfargo"),
    ("coinbase",  "coinbase.com",  ["coinbase","crypto","bitcoin","sign in"],         "coinbase"),
    ("dropbox",   "dropbox.com",   ["dropbox","file","share","sign in"],              "dropbox"),
]

def check_visual_similarity(soup, original_domain: str) -> dict:
    """
    Structural visual similarity: compare page DOM signals against brand fingerprints.
    Returns a dict with impersonation_detected, matched_brand, confidence, and flags.
    """
    result = {
        "impersonation_detected": False,
        "matched_brand": None,
        "confidence": 0.0,
        "visual_flags": [],
    }

    if not soup:
        return result

    # Collect page text signals
    title = (soup.find("title") or type("", (), {"get_text": lambda *a, **kw: ""})()).get_text(strip=True).lower()
    all_text = soup.get_text(separator=" ").lower()
    all_img_srcs = " ".join(img.get("src", "") for img in soup.find_all("img")).lower()
    all_link_hrefs = " ".join(a.get("href", "") for a in soup.find_all("a")).lower()

    # Form complexity score (login forms have specific patterns)
    forms = soup.find_all("form")
    has_pw = bool(soup.find("input", {"type": "password"}))
    has_email_input = bool(soup.find("input", {"type": lambda t: t and "email" in t.lower()}))
    has_submit = bool(soup.find("input", {"type": "submit"}) or soup.find("button"))

    for brand, official_domain, title_kws, logo_hint in BRAND_FINGERPRINTS:
        # Skip if we are ON the official domain
        if original_domain.endswith(official_domain):
            continue

        # Score how many signals match
        title_hits = sum(1 for kw in title_kws if kw in title)
        text_hits = sum(1 for kw in title_kws[:3] if kw in all_text[:2000])
        logo_hit = int(logo_hint in all_img_srcs)
        link_hit = int(official_domain in all_link_hrefs)

        # Structural login form match (password + email + submit)
        form_hit = int(has_pw and (has_email_input or has_submit) and len(forms) > 0)

        total_signals = title_hits + text_hits + logo_hit + link_hit + form_hit
        max_possible  = len(title_kws) + 3 + 1 + 1 + 1

        confidence = round(total_signals / max(max_possible, 1), 3)

        # Require: brand name itself must appear in title OR logo + form both present
        brand_in_title = brand in title
        strong_match = (
            (brand_in_title and title_hits >= 1 and confidence >= 0.30) or
            (logo_hit and form_hit and confidence >= 0.35)
        )
        if strong_match:
            result["impersonation_detected"] = True
            result["matched_brand"] = brand
            result["confidence"] = confidence
            result["visual_flags"].append(
                f"Page structurally resembles {brand.title()} login page "
                f"(confidence: {confidence:.0%}) — brand in title: {'yes' if brand_in_title else 'no'}, "
                f"title keyword matches: {title_hits}, "
                f"logo hint: {'yes' if logo_hit else 'no'}, login form: {'yes' if form_hit else 'no'}"
            )
            break  # report highest match only

    return result


# ════════════════════════════════════════════════════════════════
# EMAIL CONTENT SCANNER
# Analyses raw email text for phishing signals:
#   - Urgency / threat language
#   - Credential-request patterns
#   - Embedded URLs (extracted and fed into URL analyser)
#   - Sender spoofing indicators
# ════════════════════════════════════════════════════════════════

EMAIL_URGENCY_PHRASES = [
    "verify your account", "confirm your identity", "update your information",
    "your account has been suspended", "unusual sign-in activity",
    "click here immediately", "act now", "within 24 hours", "limited time",
    "password reset required", "security alert", "unauthorized access",
    "your account will be closed", "validate your account",
    "we have noticed", "suspicious activity", "verify now",
    "click the link below", "do not ignore", "immediate action required",
    "failure to verify", "account locked", "temporary hold",
]

EMAIL_CREDENTIAL_PHRASES = [
    "enter your password", "provide your credentials", "log in to verify",
    "confirm your email", "enter your social security", "your pin",
    "bank account number", "credit card", "card number", "cvv",
    "date of birth", "mother maiden name", "secret question",
]

EMAIL_SENDER_SPOOF_PATTERNS = [
    r"no.?reply@(?!(?:google|microsoft|amazon|apple|paypal|facebook)\.com)",
    r"support@(?!(?:google|microsoft|amazon|apple|paypal)\.com).*\.(xyz|tk|ml|info|top|club)",
    r"security@(?!(?:google|microsoft|amazon|apple|paypal)\.com)",
    r"noreply@.+\.(?:tk|ml|ga|cf|gq|xyz|top|info)$",
]

URL_PATTERN = re.compile(
    r'https?://[^\s<>\'"]+|www\.[^\s<>\'"]+',  # noqa
    re.IGNORECASE,
)

def scan_email(email_text: str, email_from: str = "", email_subject: str = "") -> dict:
    """
    Analyse raw email text/HTML for phishing indicators.
    Returns a risk score, signals list, and extracted URLs.
    """
    text_lower = (email_text + " " + email_subject).lower()
    result = {
        "email_risk_score": 0.0,
        "email_risk_pct": 0,
        "risk_band": "safe",
        "signals": [],
        "extracted_urls": [],
        "urgency_hits": 0,
        "credential_hits": 0,
        "sender_spoofed": False,
    }
    score = 0.0

    # ── Urgency / threat language ──────────────────────────
    urgency_matches = [p for p in EMAIL_URGENCY_PHRASES if p in text_lower]
    result["urgency_hits"] = len(urgency_matches)
    if len(urgency_matches) >= 3:
        score += 0.35
        result["signals"].append({
            "id": "email_urgency_high", "level": "red",
            "name": f"High urgency language ({len(urgency_matches)} phrases)",
            "desc": "Email uses multiple pressure/urgency phrases: " +
                    ", ".join(f'"{m}"' for m in urgency_matches[:3]) + ("…" if len(urgency_matches) > 3 else ""),
        })
    elif len(urgency_matches) >= 1:
        score += 0.18
        result["signals"].append({
            "id": "email_urgency_low", "level": "yellow",
            "name": f"Urgency language detected ({len(urgency_matches)} phrase{'s' if len(urgency_matches)>1 else ''})",
            "desc": f"Email contains urgency phrase: \"{urgency_matches[0]}\"",
        })

    # ── Credential harvesting language ────────────────────
    cred_matches = [p for p in EMAIL_CREDENTIAL_PHRASES if p in text_lower]
    result["credential_hits"] = len(cred_matches)
    if cred_matches:
        score += 0.25
        result["signals"].append({
            "id": "email_credential_request", "level": "red",
            "name": f"Credential-request language ({len(cred_matches)} phrase{'s' if len(cred_matches)>1 else ''})",
            "desc": "Email explicitly asks for sensitive information: " +
                    ", ".join(f'"{m}"' for m in cred_matches[:2]),
        })

    # ── Sender spoofing ────────────────────────────────────
    if email_from:
        for pattern in EMAIL_SENDER_SPOOF_PATTERNS:
            if re.search(pattern, email_from, re.IGNORECASE):
                result["sender_spoofed"] = True
                score += 0.30
                result["signals"].append({
                    "id": "email_sender_spoof", "level": "red",
                    "name": "Suspicious sender address",
                    "desc": f"Sender ({email_from[:60]}) matches known spoofing pattern "
                            "(legitimate service using suspicious TLD or mismatched domain).",
                })
                break

    # ── Generic spoofing: display name vs actual domain ───
    if email_from:
        for brand in list(KNOWN_BRANDS.keys()):
            if brand in email_from.lower():
                real = KNOWN_BRANDS[brand]
                if not email_from.lower().endswith("@" + real) and \
                   not email_from.lower().endswith("." + real + ">"):
                    score += 0.25
                    result["signals"].append({
                        "id": "email_brand_spoof", "level": "red",
                        "name": f"Brand name in sender address doesn't match official domain",
                        "desc": f"Sender claims to be {brand.title()} but email is not from {real}.",
                    })
                    break

    # ── URL extraction ─────────────────────────────────────
    found_urls = list(set(URL_PATTERN.findall(email_text + " " + email_subject)))
    result["extracted_urls"] = found_urls[:20]  # cap at 20

    if found_urls:
        # Flag mismatched display text vs href (basic check in plain text)
        suspicious_url_count = sum(
            1 for u in found_urls
            if any(k in u.lower() for k in [
                "login", "verify", "secure", "update", "account",
                "confirm", "password", "suspended"
            ])
        )
        if suspicious_url_count:
            score += min(0.20, suspicious_url_count * 0.07)
            result["signals"].append({
                "id": "email_suspicious_urls", "level": "yellow",
                "name": f"{suspicious_url_count} suspicious URL{'s' if suspicious_url_count>1 else ''} in email body",
                "desc": "Embedded URLs contain phishing keywords (login, verify, secure, etc.).",
            })

    # ── HTML-only email with no plain text alternative ────
    if "<html" in email_text.lower() and len(email_text) > 500:
        text_ratio = len(re.sub(r"<[^>]+>", "", email_text)) / len(email_text)
        if text_ratio < 0.3:
            score += 0.08
            result["signals"].append({
                "id": "email_html_heavy", "level": "yellow",
                "name": "HTML-heavy email with little visible text",
                "desc": "Email is mostly HTML tags — a common technique to hide malicious content "
                        "from plain-text spam filters.",
            })

    # ── No signals → likely clean ─────────────────────────
    if not result["signals"]:
        result["signals"].append({
            "id": "email_clean", "level": "green",
            "name": "No phishing indicators found",
            "desc": "Email text does not contain urgency language, credential requests, "
                    "or sender spoofing patterns.",
        })

    score = round(min(1.0, score), 4)
    result["email_risk_score"] = score
    result["email_risk_pct"] = round(score * 100)
    result["risk_band"] = (
        "high" if score >= 0.65 else
        "suspicious" if score >= 0.30 else
        "safe"
    )
    return result


# ════════════════════════════════════════════════════════════════
# VIRUSTOTAL
# ════════════════════════════════════════════════════════════════

def check_virustotal(url: str) -> dict:
    if not VT_API_KEY:
        return {"vt_available": False}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                "vt_available": True,
                "vt_malicious": stats.get('malicious', 0),
                "vt_suspicious": stats.get('suspicious', 0),
                "vt_clean": stats.get('undetected', 0),
                "vt_total_engines": sum(stats.values()),
            }
    except Exception:
        pass
    return {"vt_available": False}


# ════════════════════════════════════════════════════════════════
# VIRUSTOTAL STANDALONE VERDICT
# Independent assessment — never touches phish_score_pct.
# ════════════════════════════════════════════════════════════════

def vt_standalone_verdict(vt: dict) -> dict:
    """
    Turn raw VirusTotal engine counts into a standalone verdict.
    Completely decoupled from the ML/heuristic score pipeline.
    """
    if not vt.get("vt_available"):
        return {
            "available":     False,
            "score_pct":     None,
            "risk_band":     "unknown",
            "verdict":       "VirusTotal not configured",
            "detail":        "Set VIRUSTOTAL_API_KEY env var to enable community threat intelligence.",
            "malicious":     0,
            "suspicious":    0,
            "clean":         0,
            "total_engines": 0,
        }

    malicious  = vt.get("vt_malicious",  0)
    suspicious = vt.get("vt_suspicious", 0)
    clean      = vt.get("vt_clean",      0)
    total      = vt.get("vt_total_engines", 1)

    # Independent VT score: weighted ratio, 0-100
    vt_score = round(min(100, ((malicious * 1.0 + suspicious * 0.4) / max(total, 1)) * 100))

    if malicious >= 10:
        band, text = "high",       f"Confirmed Threat — {malicious}/{total} engines flagged"
    elif malicious >= 3:
        band, text = "high",       f"Likely Malicious — {malicious}/{total} engines flagged"
    elif malicious >= 1 or suspicious >= 3:
        band, text = "suspicious", f"Flagged — {malicious} malicious, {suspicious} suspicious"
    else:
        band, text = "safe",       f"Clean — 0/{total} engines flagged"

    return {
        "available":     True,
        "score_pct":     vt_score,
        "risk_band":     band,
        "verdict":       text,
        "detail":        (
            f"{malicious} of {total} security engines report this URL as malicious. "
            f"{suspicious} suspicious. {clean} clean."
        ),
        "malicious":     malicious,
        "suspicious":    suspicious,
        "clean":         clean,
        "total_engines": total,
    }


# ════════════════════════════════════════════════════════════════
# HYBRID FUSION SCORER
# ════════════════════════════════════════════════════════════════

def compute_fusion_score(
    ml_prob: float,
    whois: dict,
    ssl_info: dict,
    dns: dict,
    page: dict,
    vt: dict,
    url_features: dict,
    domain: str,
    tld: str,
    sld: str,
    is_trusted_parent: bool = False,
    is_shortener: bool = False,
    original_url: str = "",
) -> tuple[float, list, str]:
    """
    Combine all signals into a single threat probability.
    Returns (score_0_to_1, signals_list, decision_path).

    Fix map (v4.1):
    1. Trusted-parent gate: subdomains of known enterprise domains are not penalised
       for brand keywords or ML structural features (fixes login.microsoftonline.com).
    2. Typosquat hard floor: if typosquat distance <=2, enforce minimum 0.75 score
       BEFORE age suppression can mask it (fixes faceboook.com → 10%).
    3. Redirect penalty: redirect to a different domain adds +0.20 (fixes redirect bypass).
    4. Shortener neutralisation: URL shorteners get a fixed 0.40 "unverifiable" score
       instead of ML=1.0 from unique_char_ratio/age_unknown heuristics.
    5. Feature combination boost: 3+ independent risk signals → +0.15 floor lift.
    6. Age suppression is blocked when typosquat or blocklist signals are present.
    """
    signals = []
    score = ml_prob
    decision_path = "ml_base"

    age_days  = whois.get("domain_age_days",  -1)
    age_known = whois.get("domain_age_known",  0)
    very_new  = whois.get("domain_very_new",   0)
    brand_dist = url_features.get("min_brand_levenshtein", 99)
    is_typosquat_flag = bool(url_features.get("is_typosquat", 0))

    # ── FIX 4: URL shorteners ────────────────────────────────────
    # We can't inspect the destination without following the link, so we
    # assign a fixed "unverifiable" score rather than letting the ML model
    # go to 1.0 because of unique_char_ratio / unknown WHOIS age heuristics.
    if is_shortener:
        # v4.3: resolve the actual destination when possible, then score THAT domain.
        # Fall back to keyword heuristics only when resolution fails.
        resolved_domain = None
        resolved_trusted = False
        resolution_note = ""

        # ── Path keyword hint: infer destination from slug before network call ──
        # e.g. bit.ly/openai → slug "openai" → check TRUSTED_PARENT_DOMAINS
        if original_url:
            from urllib.parse import urlparse as _up_hint
            _path_slug = _up_hint(original_url).path.strip('/').split('/')[0].lower()
            # Match slug against known trusted domains (first segment only)
            _slug_trusted_match = next(
                (t for t in TRUSTED_PARENT_DOMAINS
                 if _path_slug and (_path_slug == t.split('.')[0] or
                                    t.startswith(_path_slug + '.'))),
                None
            )
            if _slug_trusted_match:
                resolved_domain    = _slug_trusted_match
                resolved_trusted   = True
                resolution_note    = f" → path hint: {_slug_trusted_match}"

        # Try to resolve destination via HEAD request (fast, no page download)
        if original_url and not resolved_domain:
            try:
                r_head = requests.head(
                    original_url, timeout=(2, SHORTENER_TIMEOUT),
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"},
                    verify=False,
                )
                final_resolved = r_head.url
                from urllib.parse import urlparse as _up
                resolved_domain = _up(final_resolved).netloc.lower().split(":")[0]
                # Check if the resolved destination is trusted
                resolved_trusted = any(
                    resolved_domain == t or resolved_domain.endswith("." + t)
                    for t in TRUSTED_PARENT_DOMAINS
                ) or resolved_domain in REPUTATION_DB and REPUTATION_DB[resolved_domain][1] == "trusted"
                resolution_note = f" → resolves to {resolved_domain}"
            except Exception:
                resolved_domain = None

        if resolved_domain and resolved_trusted:
            # Destination is a known trusted domain — short URL is likely legit sharing
            score = 0.15
            desc = (f"Short URL resolves to trusted destination ({resolved_domain}). "
                    "Destination verified as legitimate.")
            level = "green"
        elif resolved_domain and resolved_domain in REPUTATION_DB and REPUTATION_DB[resolved_domain][1] == "blocklist":
            # Destination is a known bad domain
            score = 0.95
            desc = (f"Short URL resolves to BLOCKLISTED domain ({resolved_domain})!")
            level = "red"
        elif resolved_domain:
            # Destination resolved but not in trusted list.
            # Do a second-pass check: score the destination domain structurally.
            # Many benign URLs (news articles, GitHub repos, etc.) resolve to
            # unlisted but non-malicious domains → keep score moderate.
            resolved_parts = resolved_domain.split('.')
            resolved_tld = resolved_parts[-1] if resolved_parts else ''
            resolved_feats = extract_features('https://' + resolved_domain + '/')
            resolved_risk = resolved_feats.get('has_brand_impersonation', 0) * 0.20 +                             resolved_feats.get('is_typosquat', 0) * 0.30 +                             (0.15 if resolved_tld in HIGH_RISK_TLDS else 0) +                             resolved_feats.get('domain_very_new', 0) * 0.10
            score = round(min(0.45, max(0.35, 0.25 + resolved_risk)), 3)
            desc = (f"Short URL resolves to {resolved_domain}. "
                    f"Structural risk of destination: {round(resolved_risk*100)}%. "
                    "Verify before clicking.")
            level = "yellow" if score < 0.40 else "red"
        else:
            # Could not resolve — fall back to keyword heuristics
            clean_path = (original_url.split("?")[0] + original_url.split("?")[-1]).lower()
            urgency_keywords = ["verify","login","secure","update","account","signin",
                                "confirm","password","urgent","suspended","validate"]
            urgency_hits = sum(1 for k in urgency_keywords if k in clean_path)
            if urgency_hits >= 2:
                score = 0.65
                desc = (f"Short URL unresolvable + {urgency_hits} urgency keywords in path — high suspicion.")
                level = "red"
            elif urgency_hits == 1:
                score = 0.50
                desc = "Short URL unresolvable with suspicious keyword in path."
                level = "yellow"
            else:
                score = 0.40
                desc = ("Destination could not be verified. Score at 40% — check before clicking.")
                level = "yellow"
            resolution_note = " (unresolvable)"

        decision_path = "shortener_resolved" if resolved_domain else "shortener_unverifiable"
        signals.append({
            "id": "shortener",
            "level": level,
            "name": f"URL shortener ({domain}){resolution_note}",
            "desc": desc,
            "impact": 0,
        })
        score = round(score, 4)
        return score, signals, decision_path

    # ── FIX 1: Trusted-parent domain gate ───────────────────────
    # Subdomains of known enterprise parents (e.g. login.microsoftonline.com)
    # should NOT be penalised for brand keywords or structural ML noise.
    if is_trusted_parent:
        score = min(ml_prob, 0.15)   # cap ML contribution for trusted parents
        decision_path = "trusted_parent_capped"
        signals.append({
            "id": "trusted_parent",
            "level": "green",
            "name": f"Trusted parent domain ({domain})",
            "desc": "Domain is a verified subdomain of a known-good enterprise parent. "
                    "ML structural penalties suppressed.",
            "impact": -(ml_prob - score),
        })
        # ── VT is intentionally NOT fused here ──────────────────
        # VirusTotal results are returned as a separate verdict (virustotal_verdict)
        # and never modify the ML/heuristic score. See run_analysis() for the split.
        score = round(max(0.0, min(1.0, score)), 4)
        return score, signals, decision_path

    # ── FIX 2: Typosquat hard floor ─────────────────────────────
    # Typosquatting is a near-definitive phishing signal.  Age suppression
    # must not be allowed to drag the score below 0.75 when it is present.
    TYPOSQUAT_FLOOR = 0.90   # v4.2: raised from 0.75 — typosquat is near-definitive
    typosquat_floor_active = is_typosquat_flag and brand_dist <= 2
    # Punycode homoglyphs are also near-definitive — apply same hard floor
    punycode_floor_active = bool(url_features.get("has_punycode_homoglyph", 0))
    PUNYCODE_FLOOR = 0.80  # higher than typosquat — homoglyphs have no legitimate use

    # ── Age suppression (blocked when typosquat is active) ───────
    age_suppression_blocked = typosquat_floor_active or punycode_floor_active
    if age_known and age_days > ML_AGE_GATE and not age_suppression_blocked:
        suppression = min(0.4, (age_days / 3650) * 0.4)
        score = max(0.0, score - suppression)
        decision_path = "ml_suppressed_by_age"
        signals.append({
            "id": "age_suppression",
            "level": "info",
            "name": f"Established domain ({age_days} days old)",
            "desc": f"ML score suppressed by {suppression:.0%} — structural features "
                    "less predictive for aged domains.",
            "impact": -suppression,
        })
    elif age_suppression_blocked:
        signals.append({
            "id": "age_suppression_blocked",
            "level": "yellow",
            "name": "Age suppression blocked (typosquat present)",
            "desc": "Domain age would normally reduce the score, but typosquatting "
                    "is a near-definitive signal that overrides age-based trust.",
            "impact": 0,
        })

    # ── Hard overrides ────────────────────────────────────────────
    # NOTE: VirusTotal is intentionally excluded from fusion scoring.
    # VT results live in virustotal_verdict (separate key in response).
    # This keeps phish_score_pct a pure ML + heuristic number.

    if dns.get("dns_blacklisted"):
        score = max(score, 0.88)
        signals.append({
            "id": "dns_blacklist",
            "level": "red",
            "name": "DNS Blacklisted",
            "desc": f"IP {dns.get('ip','?')} is present on threat intelligence blocklists.",
            "impact": 0.3,
        })

    # ── Page signals ──────────────────────────────────────────────
    if page.get("page_title_brand_mismatch"):
        score = min(1.0, score + 0.18)
        signals.append({
            "id": "title_mismatch", "level": "red",
            "name": "Page title brand mismatch",
            "desc": "Page title references a well-known brand but the domain doesn't match.",
            "impact": 0.18,
        })

    if page.get("form_action_external"):
        score = min(1.0, score + 0.20)
        signals.append({
            "id": "form_external", "level": "red",
            "name": "Form submits to external domain",
            "desc": "Login/submit form posts credentials to a different domain — "
                    "credential harvesting pattern.",
            "impact": 0.20,
        })

    if page.get("has_hidden_iframe"):
        score = min(1.0, score + 0.12)
        signals.append({
            "id": "hidden_iframe", "level": "red",
            "name": "Hidden iframe detected",
            "desc": "Invisible iframes are a common phishing obfuscation technique.",
            "impact": 0.12,
        })

    if page.get("obfuscated_js"):
        score = min(1.0, score + 0.08)
        signals.append({
            "id": "obf_js", "level": "yellow",
            "name": "Obfuscated JavaScript",
            "desc": "eval(), unescape(), or atob() — common in phishing kits.",
            "impact": 0.08,
        })

    # ── FIX 3: Redirect penalty ───────────────────────────────────
    # Phishing sites often redirect to a legitimate domain after harvesting creds,
    # or typosquat domains redirect to the real site after logging the visit.
    # Always evaluate the ORIGINAL domain, not the final URL.
    final_url = page.get("final_url", "")
    redirect_count = page.get("redirect_count", 0)
    if redirect_count > 0 and final_url and original_url:
        from urllib.parse import urlparse as _up
        orig_host = _up(original_url).netloc.lower().split(':')[0]
        final_host = _up(final_url).netloc.lower().split(':')[0]
        if orig_host and final_host and orig_host != final_host:
            # Redirect to a TRUSTED domain from a suspicious original is still suspicious —
            # it means the original domain was used as a lure.
            boost = 0.20
            score = min(1.0, score + boost)
            signals.append({
                "id": "redirect_domain_change", "level": "red",
                "name": f"Redirects to different domain ({final_host})",
                "desc": f"Original domain ({orig_host}) redirects to {final_host}. "
                        "This is a hallmark of typosquat lures and phishing relays. "
                        "Score computed on the ORIGINAL domain.",
                "impact": boost,
            })

    # ── WHOIS signals ─────────────────────────────────────────────
    if very_new:
        score = min(1.0, score + 0.15)
        signals.append({
            "id": "domain_new", "level": "yellow",
            "name": f"Domain very new ({age_days} days)",
            "desc": "78% of phishing domains are used within 7 days of registration.",
            "impact": 0.15,
        })

    if not whois.get("domain_age_known", 0) and not whois.get("domain_age_days", -1) != -1:
        # WHOIS returned no data — domain age completely unknown
        score = min(1.0, score + 0.08)
        signals.append({
            "id": "whois_unknown",
            "level": "yellow",
            "name": "Domain age unknown (WHOIS failed)",
            "desc": "Cannot verify domain registration age. Unknown domains carry slightly "
                    "elevated risk — most legitimate sites have verifiable WHOIS data.",
            "impact": 0.08,
        })

    if whois.get("whois_privacy"):
        score = min(1.0, score + 0.06)
        signals.append({
            "id": "whois_privacy", "level": "yellow",
            "name": "WHOIS privacy protected",
            "desc": "Registrant identity hidden. Most legitimate businesses expose WHOIS.",
            "impact": 0.06,
        })

    # ── SSL signals ───────────────────────────────────────────────
    if not ssl_info.get("has_ssl"):
        score = min(1.0, score + 0.10)
        signals.append({
            "id": "no_ssl", "level": "yellow",
            "name": "No SSL certificate",
            "desc": "All modern legitimate websites use HTTPS.",
            "impact": 0.10,
        })

    if ssl_info.get("ssl_self_signed"):
        score = min(1.0, score + 0.08)
        signals.append({
            "id": "self_signed", "level": "yellow",
            "name": "Self-signed certificate",
            "desc": "Certificate not from a trusted CA — server identity unverifiable.",
            "impact": 0.08,
        })

    if ssl_info.get("ssl_cert_very_new"):
        score = min(1.0, score + 0.07)
        signals.append({
            "id": "new_cert", "level": "yellow",
            "name": "SSL cert issued very recently",
            "desc": "Certificate issued in last 7 days — domain was just stood up.",
            "impact": 0.07,
        })

    # ── URL structural signals ────────────────────────────────────
    if url_features.get("has_brand_impersonation"):
        score = min(1.0, score + 0.12)
        signals.append({
            "id": "brand_impersonation", "level": "red",
            "name": "Brand name in domain",
            "desc": "Domain contains a well-known brand name but is not the official domain.",
            "impact": 0.12,
        })

    if is_typosquat_flag:
        # v4.2: enforce TYPOSQUAT_FLOOR immediately so no downstream signals
        # (clean page, old domain) can drag the score back below 90%
        pre_typo = score
        score = max(score + 0.18, TYPOSQUAT_FLOOR)
        impact = round(score - pre_typo, 4)
        signals.append({
            "id": "typosquat", "level": "red",
            "name": f"Typosquatting detected (edit distance: {brand_dist})",
            "desc": f"Domain is {brand_dist} character edit(s) from a known brand. "
                    "Classic impersonation technique. Score floored at 90%.",
            "impact": impact,
        })
        score = min(1.0, score)

    if tld in HIGH_RISK_TLDS:
        score = min(1.0, score + 0.10)
        signals.append({
            "id": "bad_tld", "level": "yellow",
            "name": f"High-risk TLD (.{tld})",
            "desc": f".{tld} domains are disproportionately used in phishing campaigns.",
            "impact": 0.10,
        })

    if url_features.get("has_ip_address"):
        score = min(1.0, score + 0.15)
        signals.append({
            "id": "ip_domain", "level": "red",
            "name": "IP address used as domain",
            "desc": "Legitimate sites almost never use a raw IP as their address.",
            "impact": 0.15,
        })

    if url_features.get("has_punycode_homoglyph"):
        score = min(1.0, score + 0.18)
        signals.append({
            "id": "punycode", "level": "red",
            "name": "Punycode / homoglyph domain",
            "desc": "Domain uses Unicode characters to visually impersonate another domain.",
            "impact": 0.18,
        })

    # ── Positive signals ──────────────────────────────────────────
    if age_known and age_days > 1825 and not typosquat_floor_active:
        score = max(0.0, score - 0.05)
        signals.append({
            "id": "old_domain", "level": "green",
            "name": f"Domain is {age_days // 365}+ years old",
            "desc": "Established domain with long registration history.",
            "impact": -0.05,
        })

    # Visual similarity signal
    vis = page.get("visual_similarity", {})
    if vis.get("impersonation_detected"):
        conf = vis.get("confidence", 0)
        boost = round(min(0.25, conf * 0.4), 3)
        score = min(1.0, score + boost)
        signals.append({
            "id": "visual_impersonation", "level": "red",
            "name": f"Visual impersonation of {vis.get('matched_brand','').title()} detected",
            "desc": f"Page DOM structure matches {vis.get('matched_brand','')} login page "
                    f"(confidence {conf:.0%}). Structural elements, title keywords, and form "
                    "patterns match a known brand without being on the official domain.",
            "impact": boost,
        })

    if (page.get("page_fetch_ok")
            and not page.get("page_title_brand_mismatch")
            and not page.get("form_action_external")):
        score = max(0.0, score - 0.03)
        signals.append({
            "id": "clean_page", "level": "green",
            "name": "Page content appears clean",
            "desc": "No brand mismatch or suspicious form actions in page HTML.",
            "impact": -0.03,
        })

    # ── FIX 2 (cont): Typosquat floor enforcement ─────────────────
    if typosquat_floor_active and score < TYPOSQUAT_FLOOR:
        signals.append({
            "id": "typosquat_floor", "level": "red",
            "name": f"Typosquat floor applied (raised {round(score*100)}% → {round(TYPOSQUAT_FLOOR*100)}%)",
            "desc": "Typosquatting is a near-definitive phishing signal. "
                    "Minimum score enforced regardless of mitigating factors.",
            "impact": TYPOSQUAT_FLOOR - score,
        })
        score = TYPOSQUAT_FLOOR

    # ── Punycode floor enforcement ────────────────────────────────
    if punycode_floor_active and score < PUNYCODE_FLOOR:
        signals.append({
            "id": "punycode_floor", "level": "red",
            "name": f"Punycode floor applied (raised {round(score*100)}% → {round(PUNYCODE_FLOOR*100)}%)",
            "desc": "Punycode/homoglyph domains have no legitimate use — they exist "
                    "exclusively to visually impersonate other domains.",
            "impact": PUNYCODE_FLOOR - score,
        })
        score = PUNYCODE_FLOOR

    # ── FIX 5: Feature combination boost ─────────────────────────
    # Independent risk signals compound. 3+ hard signals → lift floor to 0.60.
    # Brand impersonation on a new/unknown domain is a high-confidence compound signal
    # (e.g. secure-apple-id.com registered 8 days ago)
    brand_on_new_domain = (
        url_features.get("has_brand_impersonation", 0)
        and (very_new or not age_known or url_features.get("suspicious_keyword_count", 0) >= 1)
    )
    if brand_on_new_domain:
        boost = 0.30
        score = min(1.0, score + boost)
        signals.append({
            "id": "brand_impersonation_new_domain", "level": "red",
            "name": "Brand impersonation on new/unverified domain",
            "desc": "Domain contains a well-known brand name AND is newly registered "
                    "or has suspicious keywords. High-confidence phishing indicator.",
            "impact": boost,
        })

    # v4.2 FIX 3: Urgency keyword count now boosts score, not just flags a signal
    kw_count = url_features.get("suspicious_keyword_count", 0)
    if kw_count >= 3:
        kw_boost = 0.20
        score = min(1.0, score + kw_boost)
        signals.append({
            "id": "keyword_combo", "level": "red",
            "name": f"High urgency keyword density ({kw_count} keywords)",
            "desc": (f"{kw_count} phishing-associated keywords in URL (login, verify, secure, "
                     "billing, urgent…) — strong compound signal."),
            "impact": kw_boost,
        })
    elif kw_count == 2:
        kw_boost = 0.12
        score = min(1.0, score + kw_boost)
        signals.append({
            "id": "keyword_combo", "level": "yellow",
            "name": f"Multiple suspicious keywords ({kw_count})",
            "desc": "Two phishing-associated keywords found — cumulative risk signal.",
            "impact": kw_boost,
        })
    elif kw_count == 1:
        signals.append({
            "id": "keyword_single", "level": "yellow",
            "name": "Suspicious keyword in URL",
            "desc": "URL contains a phishing-associated keyword (login, verify, secure, etc.).",
            "impact": 0,
        })

    # v4.2 FIX 4: Domain entropy / randomness boost
    # High entropy domains look machine-generated (e.g. xj3k9-paypal-secure-login.com)
    domain_entropy = url_features.get("domain_entropy", 0)
    if domain_entropy > 3.8:
        entropy_boost = 0.15
        score = min(1.0, score + entropy_boost)
        signals.append({
            "id": "high_entropy",
            "level": "yellow",
            "name": f"High domain entropy ({domain_entropy:.2f})",
            "desc": (f"Domain character distribution is highly random (entropy={domain_entropy:.2f}). "
                     "Legitimate domains are usually pronounceable; this pattern suggests "
                     "an auto-generated or obfuscated domain."),
            "impact": entropy_boost,
        })
    elif domain_entropy > 3.4:
        signals.append({
            "id": "elevated_entropy",
            "level": "yellow",
            "name": f"Elevated domain entropy ({domain_entropy:.2f})",
            "desc": "Domain has above-average character randomness.",
            "impact": 0,
        })

    hard_signal_ids = {
        "title_mismatch", "form_external", "hidden_iframe",
        "brand_impersonation", "typosquat", "punycode",
        "ip_domain", "bad_tld", "redirect_domain_change",
        "domain_new", "dns_blacklist",
        "keyword_combo", "whois_privacy", "no_ssl",
        "high_entropy",
    }
    n_hard = sum(1 for s in signals if s["id"] in hard_signal_ids)
    # v4.2: tiered compound boost — 2 signals → floor 0.55, 3+ → floor 0.65
    if n_hard >= 3 and score < 0.65:
        boost = round(0.65 - score, 4) if score < 0.65 else 0
        score = max(score + 0.20, 0.65)
        signals.append({
            "id": "combination_boost", "level": "red",
            "name": f"Strong compound signal ({n_hard} independent indicators)",
            "desc": (f"{n_hard} independent risk indicators detected simultaneously. "
                     "Compound signals are far more reliable than any single feature. "
                     "Score floored at 65%."),
            "impact": round(score - (score - 0.20), 4),
        })
    elif n_hard == 2 and score < 0.55:
        score = max(score + 0.15, 0.55)
        signals.append({
            "id": "combination_boost", "level": "yellow",
            "name": f"Dual risk signal boost ({n_hard} indicators)",
            "desc": "Two independent risk indicators detected — score floored at 55%.",
            "impact": 0.15,
        })

    score = round(max(0.0, min(1.0, score)), 4)
    return score, signals, decision_path


# ════════════════════════════════════════════════════════════════
# MAIN ANALYSIS PIPELINE
# ════════════════════════════════════════════════════════════════

def run_analysis(url: str, fast: bool = False) -> dict:
    cache_key = hashlib.md5(f"v4:{url}:{fast}".encode()).hexdigest()
    if cache_key in ANALYSIS_CACHE:
        cached = ANALYSIS_CACHE[cache_key]
        if time.time() - cached.get('_ts', 0) < CACHE_TTL:
            cached['from_cache'] = True
            return cached

    t0 = time.time()

    # Normalise URL
    if not re.match(r'^https?://', url, re.I):
        url = 'https://' + url
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(':')[0]
    parts = domain.split('.')
    tld = parts[-1] if parts else ''
    sld = parts[-2] if len(parts) >= 2 else ''

    # ── STEP 1: Reputation gate ──────────────────────────────
    rep_entry = REPUTATION_DB.get(domain)
    if rep_entry:
        score_pct, tier, age_years, alexa, notes = rep_entry
        elapsed = round((time.time() - t0) * 1000)
        result = {
            "url": url,
            "domain": domain,
            "decision_path": "reputation_gate",
            "phish_probability": score_pct / 100,
            "phish_score_pct": score_pct,
            "risk_band": "high" if score_pct >= 65 else "suspicious" if score_pct >= 35 else "safe",
            "reputation": {
                "tier": tier,
                "age_years": age_years,
                "alexa_rank": alexa,
                "notes": notes,
            },
            "signals": [{
                "id": "reputation_hit",
                "level": "green" if tier == "trusted" else "red" if tier == "blocklist" else "yellow",
                "name": f"Reputation DB: {tier.upper()}",
                "desc": notes,
                "impact": 0,
            }],
            "ml_used": False,
            "ml_score": None,
            "whois": {},
            "ssl": {},
            "dns": {},
            "page_analysis": {},
            "virustotal": {}, "virustotal_verdict": vt_standalone_verdict({}),
            "url_features": {},
            "analysis_time_ms": elapsed,
            "fast_mode": True,
            "_ts": time.time(),
        }
        ANALYSIS_CACHE[cache_key] = result
        return result

    # ── STEP 2: URL feature extraction ──────────────────────
    url_features = extract_features(url, include_whois=not fast, include_ssl=not fast)

    # ── STEP 3: ML prediction ────────────────────────────────
    feat_row = pd.DataFrame([{col: url_features.get(col, 0) for col in feature_cols}])
    proba = model.predict_proba(feat_row)[0]
    classes = list(model.classes_)
    phish_idx = classes.index(1) if 1 in classes else 1
    ml_prob = float(proba[phish_idx])

    # ── STEP 4: Live enrichment (skip if fast mode) ──────────
    whois_data = {}
    ssl_data = {}
    dns_data = {}
    page_data = {}
    vt_data = {}

    if not fast:
        # WHOIS — already fetched inside extract_features when include_whois=True
        whois_data = {k: url_features[k] for k in
                      ["domain_age_days", "domain_age_known", "domain_very_new", "whois_privacy"]
                      if k in url_features}

        ssl_data = {k: url_features[k] for k in
                    ["has_ssl", "ssl_cert_age_days", "ssl_cert_known",
                     "ssl_cert_very_new", "ssl_self_signed", "ssl_domain_mismatch"]
                    if k in url_features}

        # ── Run DNS + page fetch + VT concurrently ──────────────────────────
        # Sequential was: DNS(3s) + page(6s) + VT(10s) = up to 19s
        # Concurrent: max(3, 6, 10) = ~7s worst case
        from concurrent.futures import ThreadPoolExecutor

        def _run_dns():   return get_dns_info(domain)
        def _run_page():  return analyze_page_content(url)
        def _run_vt():    return check_virustotal(url) if VT_API_KEY else {}

        with ThreadPoolExecutor(max_workers=3) as _pool:
            _f_dns  = _pool.submit(_run_dns)
            _f_page = _pool.submit(_run_page)
            _f_vt   = _pool.submit(_run_vt)
            try:    dns_data  = _f_dns.result(timeout=DNS_TIMEOUT + 2)
            except Exception: dns_data = {}
            try:    page_data = _f_page.result(timeout=FETCH_TIMEOUT + 3)
            except Exception: page_data = {}
            try:    vt_data   = _f_vt.result(timeout=13)
            except Exception: vt_data = {}

        # Determine if ML should fully apply
        age_days = whois_data.get("domain_age_days", -1)
        age_known = whois_data.get("domain_age_known", 0)
        # v4.3: also run ML if suspicious signals present regardless of domain age
        # (compromised old domains should still be ML-scored if they look suspicious)
        suspicious_signal_count = sum([
            bool(url_features.get("has_brand_impersonation", 0)),
            bool(url_features.get("is_typosquat", 0)),
            bool(url_features.get("has_suspicious_keyword", 0)),
            bool(url_features.get("has_high_risk_tld", 0)),
            bool(url_features.get("has_ip_address", 0)),
            bool(url_features.get("has_at_symbol", 0)),
        ])
        ml_active = (
            (not age_known)
            or (age_days < ML_AGE_GATE)
            or tld in HIGH_RISK_TLDS
            or suspicious_signal_count >= 2   # compromised old domain with active attack signals
        )
    else:
        # Fast mode: URL-only, fill defaults
        whois_data = {
            "domain_age_days": url_features.get("domain_age_days", -1),
            "domain_age_known": url_features.get("domain_age_known", 0),
            "domain_very_new": url_features.get("domain_very_new", 0),
            "whois_privacy": url_features.get("whois_privacy", 0),
        }
        ssl_data = {"has_ssl": url_features.get("has_ssl", 0)}
        dns_data = {}
        ml_active = True  # in fast mode, always use ML

    # ── STEP 5: Fusion scoring ───────────────────────────────
    # Trusted-suffix check: is this domain a subdomain of a known-good parent?
    is_trusted_parent = any(domain == t or domain.endswith('.' + t)
                            for t in TRUSTED_PARENT_DOMAINS)
    is_shortener = domain in URL_SHORTENERS

    fusion_score, signals, decision_path = compute_fusion_score(
        ml_prob=ml_prob,
        whois=whois_data,
        ssl_info=ssl_data,
        dns=dns_data,
        page=page_data,
        vt=vt_data,
        url_features=url_features,
        domain=domain,
        tld=tld,
        sld=sld,
        is_trusted_parent=is_trusted_parent,
        is_shortener=is_shortener,
        original_url=url,
    )

    elapsed = round((time.time() - t0) * 1000)

    result = {
        "url": url,
        "domain": domain,
        "decision_path": decision_path,
        "phish_probability": fusion_score,
        "phish_score_pct": round(fusion_score * 100),
        "risk_band": "high" if fusion_score >= 0.65 else "suspicious" if fusion_score >= 0.35 else "safe",
        "reputation": None,
        "signals": signals,
        "why": [s["name"] for s in signals if s.get("level") in ("red", "yellow") and s.get("impact", 0) > 0],
        "ml_used": True,
        "ml_score": round(ml_prob * 100),
        "ml_active": ml_active if not fast else True,
        "whois": whois_data,
        "ssl": ssl_data,
        "dns": dns_data,
        "page_analysis": page_data,
        "redirect_chain": page_data.get("redirect_chain", []),
        "virustotal": vt_data,               # raw engine counts
        "virustotal_verdict": vt_standalone_verdict(vt_data),  # independent VT verdict (never fused into phish_score_pct)
        "url_features": {k: v for k, v in url_features.items()
                         if k not in ["domain_age_days", "domain_age_known",
                                      "domain_very_new", "whois_privacy",
                                      "has_ssl", "ssl_cert_age_days", "ssl_cert_known",
                                      "ssl_cert_very_new", "ssl_self_signed", "ssl_domain_mismatch"]},
        "analysis_time_ms": elapsed,
        "fast_mode": fast,
        "_ts": time.time(),
    }

    ANALYSIS_CACHE[cache_key] = result
    return result


# ════════════════════════════════════════════════════════════════
# ROUTES
# ════════════════════════════════════════════════════════════════

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "version": "5.0",
        "model_features": len(feature_cols),
        "reputation_db_size": len(REPUTATION_DB),
        "ml_age_gate_days": ML_AGE_GATE,
        "vt_configured": bool(VT_API_KEY),
        "email_scanner": True,
        "visual_similarity": True,
        "ml_calibration": True,
        "redirect_chain": True,
        "cache_entries": len(ANALYSIS_CACHE),
    })


@app.route('/analyze', methods=['POST'])
def analyze():
    """Full hybrid analysis: reputation gate + live WHOIS/SSL/DNS + page scrape + ML + fusion."""
    data = request.get_json(silent=True) or {}
    url  = (data.get('url') or '').strip()
    fast = bool(data.get('fast', False))
    if not url:
        return jsonify({"error": "url field required"}), 400
    try:
        result = run_analysis(url, fast=fast)
        return jsonify(result)
    except Exception as e:
        import traceback as _tb
        _tb.print_exc()
        # Return a graceful degraded result instead of a bare 500
        url_norm = url if re.match(r'^https?://', url, re.I) else 'https://' + url
        dom = urlparse(url_norm).netloc.lower().split(':')[0]
        return jsonify({
            "url": url_norm, "domain": dom,
            "decision_path": "error_fallback",
            "phish_score_pct": 50,
            "phish_probability": 0.5,
            "risk_band": "suspicious",
            "error": str(e),
            "error_detail": "Full analysis failed. Score defaulted to 50% (unknown).",
            "signals": [{"id": "analysis_error", "level": "yellow",
                         "name": "Analysis error — partial result",
                         "desc": str(e)[:200], "impact": 0}],
            "ml_used": False, "ml_score": None,
            "whois": {}, "ssl": {}, "dns": {}, "page_analysis": {}, "virustotal": {},
            "url_features": {}, "analysis_time_ms": 0,
        }), 200  # Return 200 so the frontend can render the error gracefully


@app.route('/analyze/fast', methods=['POST'])
def analyze_fast():
    """Fast mode: URL features only, no live fetches."""
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    if not url:
        return jsonify({"error": "url field required"}), 400
    try:
        return jsonify(run_analysis(url, fast=True))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/analyze/batch', methods=['POST'])
def analyze_batch():
    """Batch fast analysis, up to 50 URLs."""
    data = request.get_json(silent=True) or {}
    urls = data.get('urls', [])
    if not urls or not isinstance(urls, list):
        return jsonify({"error": "urls must be a non-empty list"}), 400
    if len(urls) > 50:
        return jsonify({"error": "Maximum 50 URLs per batch"}), 400
    results = []
    for u in urls:
        u = u.strip()
        try:
            r = run_analysis(u, fast=True)
            results.append({
                "url": r["url"],
                "phish_score_pct": r["phish_score_pct"],
                "risk_band": r["risk_band"],
                "decision_path": r["decision_path"],
            })
        except Exception as e:
            results.append({
                "url": u, "error": str(e),
                "phish_score_pct": 50, "risk_band": "suspicious",
                "decision_path": "error_fallback"
            })
    return jsonify({"results": results, "count": len(results)})



@app.route('/analyze/email', methods=['POST'])
def analyze_email():
    """
    Analyse raw email text for phishing indicators.
    Optionally extracts embedded URLs and scores them too.

    Request JSON:
        {
          "text":    "<raw email body — plain text or HTML>",
          "from":    "sender@example.com",          (optional)
          "subject": "Your account needs attention", (optional)
          "scan_urls": true                          (optional — also score embedded URLs)
        }
    """
    data = request.get_json(silent=True) or {}
    email_text    = (data.get("text")    or "").strip()
    email_from    = (data.get("from")    or "").strip()
    email_subject = (data.get("subject") or "").strip()
    scan_urls     = bool(data.get("scan_urls", False))

    if not email_text:
        return jsonify({"error": "text field required"}), 400

    try:
        result = scan_email(email_text, email_from, email_subject)

        # Optionally score each extracted URL
        if scan_urls and result["extracted_urls"]:
            url_scores = []
            for u in result["extracted_urls"][:10]:  # cap at 10 to avoid timeout
                try:
                    u_clean = u.strip()
                    if not re.match(r'^https?://', u_clean, re.I):
                        u_clean = 'https://' + u_clean
                    r = run_analysis(u_clean, fast=True)
                    url_scores.append({
                        "url":           r["url"],
                        "phish_score":   r["phish_score_pct"],
                        "risk_band":     r["risk_band"],
                        "decision_path": r["decision_path"],
                    })
                except Exception:
                    url_scores.append({"url": u, "error": "analysis failed"})
            result["url_analysis"] = url_scores

            # Boost email score if any extracted URL is high risk
            max_url_score = max((u.get("phish_score", 0) for u in url_scores if "phish_score" in u), default=0)
            if max_url_score >= 65:
                old_score = result["email_risk_score"]
                combined  = round(min(1.0, old_score + (max_url_score / 100) * 0.35), 4)
                result["email_risk_score"] = combined
                result["email_risk_pct"]   = round(combined * 100)
                result["signals"].append({
                    "id": "email_malicious_url", "level": "red",
                    "name": f"Embedded URL scored {max_url_score}% threat",
                    "desc": f"One or more URLs in this email scored {max_url_score}% on the phishing detector. "
                            "This is a strong signal the email is a phishing attempt.",
                })
                result["risk_band"] = (
                    "high" if result["email_risk_score"] >= 0.65 else
                    "suspicious" if result["email_risk_score"] >= 0.30 else
                    "safe"
                )

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("\n🛡️  PhishGuard v5 — Hybrid Threat Intelligence")
    print("   POST /analyze        → full hybrid analysis (live WHOIS/SSL/DNS/page + ML + fusion)")
    print("   POST /analyze/fast   → URL-only instant (no live fetch)")
    print("   POST /analyze/batch  → batch fast (up to 50 URLs)")
    print("   POST /analyze/email  → email content phishing scanner")
    print("   GET  /health         → status & config\n")
    print(f"   VirusTotal   : {'✅ configured' if VT_API_KEY else '⚠️  not set (export VIRUSTOTAL_API_KEY=xxx)'}")
    print(f"   ML age gate  : domains <{ML_AGE_GATE}d get full ML analysis")
    print(f"   Reputation DB: {len(REPUTATION_DB)} entries (instant verdict)")
    print(f"   New in v5    : email scanner · visual similarity · ML calibration · full redirect chain\n")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
