# Phishing Email Detector

A sophisticated email security analysis tool that combines machine learning with rule-based heuristics to identify phishing attempts. This project demonstrates proficiency in email security, threat detection, and defensive cybersecurity techniques.

## Overview

Phishing remains one of the most prevalent attack vectors, with over 3.4 billion spam emails sent daily. This tool provides comprehensive analysis of email messages to identify social engineering attacks, helping security teams and individuals protect against credential theft, malware delivery, and business email compromise (BEC).

## Key Features

- **Multi-Layer Analysis**: Examines sender patterns, headers, content, URLs, and attachments
- **ML + Heuristics Hybrid**: Combines TF-IDF/Random Forest classification with expert-crafted detection rules
- **Email Authentication Verification**: Validates SPF, DKIM, and DMARC results
- **Typosquatting Detection**: Identifies lookalike domains using Levenshtein distance
- **Comprehensive Reporting**: Generates detailed JSON and text reports with actionable recommendations
- **Flexible Input**: Accepts .eml files or raw email text

## Phishing Indicators Analyzed

### 1. Sender Analysis
| Indicator | Description | Risk Level |
|-----------|-------------|------------|
| Free email impersonation | Brand name in display name but free email domain | High |
| Lookalike domains | Domains similar to legitimate brands (e.g., `paypa1.com`) | Critical |
| Reply-To mismatch | Different domain in Reply-To vs From header | Medium |
| Return-Path mismatch | Bounce address differs from sender domain | Medium |

### 2. Header Authentication
| Check | Pass Implications | Fail Implications |
|-------|-------------------|-------------------|
| **SPF** | Sender IP authorized by domain | Possible spoofing |
| **DKIM** | Message integrity verified | Message may be altered |
| **DMARC** | Domain policy enforced | No sender verification |

### 3. Content Patterns
- **Urgency Language**: "Act now", "immediate action required", "expires today"
- **Threat Indicators**: Account suspension threats, legal action warnings
- **Credential Requests**: Requests for passwords, SSN, credit card numbers
- **Action Phrases**: "Click here", "verify your account", "confirm your identity"

### 4. URL Analysis
| Indicator | Example | Risk |
|-----------|---------|------|
| Display/href mismatch | Shows `paypal.com` but links to `evil.com` | Critical |
| IP-based URLs | `http://192.168.1.1/login` | High |
| URL shorteners | `bit.ly`, `tinyurl.com` | Medium |
| Suspicious TLDs | `.tk`, `.ml`, `.xyz`, `.pw` | High |
| Typosquatting | `amaz0n.com`, `paypa1.com` | Critical |

### 5. Attachment Analysis
| File Type | Risk | Reason |
|-----------|------|--------|
| `.exe`, `.scr`, `.bat` | Critical | Executable files |
| `.docm`, `.xlsm` | High | Macro-enabled documents |
| `.zip`, `.rar` | Medium | Can hide malicious files |
| Double extensions | Critical | `invoice.pdf.exe` obfuscation |

## Detection Algorithm

### Risk Score Calculation

The tool uses a weighted multi-component scoring system:

```
Final Score = (Sender × 0.20) + (Headers × 0.15) + (Content × 0.25) +
              (URLs × 0.25) + (Attachments × 0.15)
```

Each component is scored 0.0-1.0 based on detected indicators:

```python
# Example: URL risk scoring
if is_ip_address:           risk += 0.40
if is_url_shortener:        risk += 0.30
if display_href_mismatch:   risk += 0.50
if is_typosquat:            risk += 0.45
if suspicious_tld:          risk += 0.25
```

### Critical Indicator Amplification

When multiple high-severity indicators are present, the score is amplified:
- 2+ critical indicators: Score × 1.25
- 3+ critical indicators: Score × 1.50

### Risk Level Classification

| Score Range | Level | Interpretation |
|-------------|-------|----------------|
| 0.00 - 0.24 | LOW | Likely legitimate |
| 0.25 - 0.49 | MEDIUM | Warrants caution |
| 0.50 - 0.74 | HIGH | Probable phishing |
| 0.75 - 1.00 | CRITICAL | Almost certainly phishing |

## Machine Learning Component

### Model Architecture
- **Vectorizer**: TF-IDF with 5,000 features, (1,2)-gram range
- **Classifier**: Random Forest with 100 estimators, balanced class weights
- **Training Features**: Subject line + body text combined

### Expected Performance Metrics
When trained on a balanced dataset of phishing and legitimate emails:

| Metric | Expected Score |
|--------|----------------|
| Accuracy | 94-97% |
| Precision | 92-95% |
| Recall | 93-96% |
| F1 Score | 93-95% |

*Note: Actual metrics depend on training data quality and size.*

## Installation

```bash
# Clone or navigate to the project
cd 10-phishing-detector

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download NLTK data (optional, for enhanced NLP)
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"
```

## Usage

### Command Line Interface

```bash
# Analyze a single email file
python phishing_detector.py samples/phishing/paypal_urgent.eml

# Analyze with JSON output
python phishing_detector.py email.eml --json

# Analyze raw email text
python phishing_detector.py --text "From: attacker@evil.com
Subject: URGENT: Verify your account
..."

# Batch process a directory
python phishing_detector.py samples/phishing/ --batch

# Use a trained ML model
python phishing_detector.py email.eml --model models/phishing_model.joblib
```

### Python API

```python
from phishing_detector import PhishingDetector, ReportGenerator

# Initialize detector
detector = PhishingDetector()

# Analyze an email file
result = detector.analyze_email("email.eml", is_file=True)

# Check the verdict
print(f"Is Phishing: {result.is_phishing}")
print(f"Risk Level: {result.risk_level}")
print(f"Risk Score: {result.risk_score:.2%}")

# Get top indicators
for indicator in result.top_indicators[:5]:
    print(f"  - {indicator}")

# Generate detailed report
reporter = ReportGenerator()
print(reporter.generate_text_report(result))
```

## Sample Output

### Analyzing a Phishing Email

```
======================================================================
PHISHING EMAIL ANALYSIS REPORT
======================================================================

VERDICT: LIKELY PHISHING
Risk Level: CRITICAL
Risk Score: 87.50%
Confidence: 91.25%

----------------------------------------------------------------------
DETAILED EXPLANATION
----------------------------------------------------------------------
PHISHING RISK ASSESSMENT: CRITICAL
Overall Risk Score: 87.50%

COMPONENT BREAKDOWN:
  - Sender Analysis:     80.00%
  - Header Analysis:     75.00%
  - Content Analysis:    85.00%
  - URL Analysis:        95.00%
  - Attachment Analysis: 0.00%

KEY INDICATORS:
  1. [URL] URL mismatch: displays 'paypal.com' but links to 'paypa1-secure-login.tk'
  2. [Sender] Display name mentions 'paypal' but email domain is 'paypa1-verify.com'
  3. [Sender] Domain 'paypa1-verify.com' appears to impersonate 'paypal'
  4. [Content] Requests for sensitive information: social security, credit card
  5. [Content] Threat language detected: account suspended, permanently closed
  6. [Header] SPF check result: fail
  7. [Header] DKIM check result: none
  8. [URL] Suspicious TLD: .tk
  9. [Content] Urgency language detected: urgent, immediately, within 24 hours

----------------------------------------------------------------------
RECOMMENDATIONS
----------------------------------------------------------------------
1. DO NOT interact with this email - delete immediately
2. Do not click any links or download attachments
3. Report this email to your IT security team
4. If you already clicked links, change your passwords immediately
5. Never enter credentials through email links

======================================================================
END OF REPORT
======================================================================
```

### Analyzing a Legitimate Email

```
======================================================================
PHISHING EMAIL ANALYSIS REPORT
======================================================================

VERDICT: LIKELY LEGITIMATE
Risk Level: LOW
Risk Score: 8.50%
Confidence: 91.50%

COMPONENT BREAKDOWN:
  - Sender Analysis:     0.00%
  - Header Analysis:     0.00%
  - Content Analysis:    5.00%
  - URL Analysis:        10.00%
  - Attachment Analysis: 0.00%

KEY INDICATORS:
  No significant phishing indicators detected.

RECOMMENDATIONS:
1. This email appears to be low risk
2. Standard email security practices apply
3. Remain vigilant for unexpected requests
```

## Project Structure

```
10-phishing-detector/
├── phishing_detector.py     # Main detection engine
├── requirements.txt         # Python dependencies
├── README.md               # Project documentation
├── models/                 # Trained ML models
│   └── (saved models go here)
└── samples/                # Sample emails for testing
    ├── phishing/           # Known phishing examples
    │   ├── paypal_urgent.eml
    │   ├── bank_alert.eml
    │   ├── microsoft_password.eml
    │   ├── amazon_prize.eml
    │   └── docusign_invoice.eml
    └── legitimate/         # Known legitimate examples
        ├── github_notification.eml
        ├── amazon_order.eml
        ├── company_newsletter.eml
        ├── paypal_receipt.eml
        └── linkedin_connection.eml
```

## Technologies Used

| Category | Technologies |
|----------|--------------|
| **Core Language** | Python 3.8+ |
| **Machine Learning** | scikit-learn (TF-IDF, Random Forest, Naive Bayes) |
| **Data Processing** | NumPy, Pandas |
| **Email Parsing** | Python email library, mail-parser |
| **URL Analysis** | tldextract, validators |
| **Text Similarity** | python-Levenshtein |
| **DNS Analysis** | dnspython |
| **CLI Interface** | Click, Rich |
| **Testing** | pytest |

## Security Considerations

- This tool is designed for **defensive analysis only**
- Sample phishing emails are clearly marked and non-functional
- All URLs in samples point to invalid/fake domains
- Never execute attachments from sample phishing emails
- Use in a controlled environment when analyzing real suspected phishing

## Future Enhancements

- [ ] Integration with VirusTotal API for URL/attachment scanning
- [ ] Browser extension for real-time email analysis
- [ ] YARA rules integration for advanced pattern matching
- [ ] REST API for enterprise deployment
- [ ] Support for MSG (Outlook) format
- [ ] Internationalized domain name (IDN) homograph detection
- [ ] Integration with threat intelligence feeds

## References

- [NIST SP 800-177: Trustworthy Email](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-177r1.pdf)
- [RFC 7208: SPF](https://tools.ietf.org/html/rfc7208)
- [RFC 6376: DKIM](https://tools.ietf.org/html/rfc6376)
- [RFC 7489: DMARC](https://tools.ietf.org/html/rfc7489)
- [CISA Phishing Guidance](https://www.cisa.gov/topics/cybersecurity-best-practices/phishing)

## License

This project is created for educational and portfolio purposes. Use responsibly and ethically.

---

*Developed as part of a cybersecurity portfolio demonstrating email security analysis and threat detection capabilities.*
