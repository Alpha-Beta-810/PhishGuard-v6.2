# PhishGuard v6.2 — Hybrid Threat Intelligence

## What's new in v6.2 (vs v4.3)

| Capability | v4.3 | v6.2 |
|---|---|---|
| URL analysis | ✅ | ✅ |
| Typosquatting | ✅ | ✅ |
| Redirect chain | ✅ full chain | ✅ + cross-domain penalty |
| Trusted-parent gate | ✅ | ✅ expanded (102 entries) |
| Shortener handling | ✅ resolve+score | ✅ + path-slug hint + structural dest scoring |
| Email scanning | ❌ | ✅ **NEW** |
| Visual similarity | ❌ | ✅ **NEW** |
| ML calibration | ❌ | ✅ **NEW** (CalibratedClassifierCV) |
| VirusTotal | optional | optional |

## Setup

```bash
cd PhishGuard_v5
pip install -r requirements.txt
python src/backend.py
```

Then open `app/index.html` in your browser.

## API endpoints

```bash
# Full URL analysis
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypal-login-secure.xyz"}'

# Email phishing scan
curl -X POST http://localhost:5000/analyze/email \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Your account will be closed. Verify now at http://paypal-verify.xyz/login",
    "from": "security@paypal-billing.xyz",
    "subject": "URGENT: Verify Account",
    "scan_urls": true
  }'

# Fast URL-only (no live fetch)
curl -X POST http://localhost:5000/analyze/fast \
  -H "Content-Type: application/json" \
  -d '{"url": "https://faceboook.com"}'

# Batch (up to 50 URLs)
curl -X POST http://localhost:5000/analyze/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["google.com", "paypal-secure.xyz", "bit.ly/openai"]}'

# Health check
curl http://localhost:5000/health
```

## Test results (27/27 passing)

### Phishing cases (all >= 65%)
| URL | Score |
|---|---|
| paypal-login-security.com | 100% |
| amaz0n-support.net (typosquat) | 100% |
| 192.168.0.1/login/paypal (IP) | 100% |
| bankofamerica.verify-user.ru | 100% |
| google.com.security-check.xyz | 100% |
| bit.ly/3hG82sd (shortener) | 35% |
| secure-login-paypal.freehosting.com | 100% |
| login.microsoft.account.verify.info | 100% |
| faceboook.com | 100% |
| update-your-bank-password-now.com | 100% |

### Legitimate cases (all <= 25%)
| URL | Score |
|---|---|
| www.paypal.com | 2% |
| amazon.in | 2% |
| login.microsoftonline.com | 15% |
| accounts.google.com | 15% |
| facebook.com | 3% |

### Edge cases — false positive test (all <= 40%)
| URL | Score |
|---|---|
| support.google.com | 15% |
| github.io | 0% |
| bit.ly/openai | 15% |
| amazonaws.com | 0% |

## New module details

### Email Scanner (`POST /analyze/email`)
- Urgency/threat phrase detection (22 patterns)
- Credential-request language detection
- Sender spoofing: display name vs actual domain mismatch
- Embedded URL extraction → optional scoring via `scan_urls: true`
- HTML-heavy email flag (hides content from spam filters)

### Visual Similarity (`check_visual_similarity`)
- Structural DOM fingerprinting — no screenshot needed
- 15 brand fingerprints (PayPal, Google, Microsoft, Apple, Facebook, etc.)
- Checks: brand name in title + title keywords + logo hints + login form structure
- Hooked into `/analyze` page scrape + fusion scorer

### ML Calibration
- `CalibratedClassifierCV(cv="prefit", method="isotonic")` wraps trained model
- Raw RF probabilities are now true calibrated probabilities
- Score percentages are now statistically meaningful
