#!/usr/bin/env python3
"""
Phishing Email Detector
=======================
A comprehensive email security analysis tool that detects phishing attempts
using a combination of machine learning and rule-based heuristics.

Author: Security Analyst Portfolio Project
Target: Defense/Intelligence Internships
"""

import re
import email
import hashlib
import logging
from email import policy
from email.parser import BytesParser, Parser
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any
from urllib.parse import urlparse, unquote
from collections import Counter
import json

# Third-party imports
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import joblib

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

try:
    import Levenshtein
    HAS_LEVENSHTEIN = True
except ImportError:
    HAS_LEVENSHTEIN = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ============================================================================
# DATA CLASSES FOR STRUCTURED ANALYSIS
# ============================================================================

@dataclass
class URLAnalysis:
    """Detailed analysis of a URL found in email."""
    url: str
    display_text: str = ""
    domain: str = ""
    tld: str = ""
    is_ip_address: bool = False
    is_shortened: bool = False
    is_typosquat: bool = False
    typosquat_target: str = ""
    mismatch_detected: bool = False
    suspicious_tld: bool = False
    risk_score: float = 0.0
    indicators: List[str] = field(default_factory=list)


@dataclass
class AttachmentAnalysis:
    """Analysis of email attachments."""
    filename: str
    extension: str
    size_bytes: int
    content_type: str
    is_executable: bool = False
    is_archive: bool = False
    is_macro_enabled: bool = False
    double_extension: bool = False
    risk_score: float = 0.0
    indicators: List[str] = field(default_factory=list)


@dataclass
class HeaderAnalysis:
    """Analysis of email headers for authentication and anomalies."""
    spf_result: str = "none"
    dkim_result: str = "none"
    dmarc_result: str = "none"
    return_path_mismatch: bool = False
    reply_to_mismatch: bool = False
    suspicious_x_headers: List[str] = field(default_factory=list)
    received_chain_anomalies: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    indicators: List[str] = field(default_factory=list)


@dataclass
class ContentAnalysis:
    """Analysis of email body content."""
    urgency_phrases: List[str] = field(default_factory=list)
    threat_phrases: List[str] = field(default_factory=list)
    action_phrases: List[str] = field(default_factory=list)
    sensitive_requests: List[str] = field(default_factory=list)
    grammar_issues: int = 0
    excessive_punctuation: bool = False
    all_caps_ratio: float = 0.0
    risk_score: float = 0.0
    indicators: List[str] = field(default_factory=list)


@dataclass
class SenderAnalysis:
    """Analysis of sender information."""
    from_address: str = ""
    from_name: str = ""
    domain: str = ""
    is_free_email: bool = False
    is_lookalike: bool = False
    lookalike_target: str = ""
    name_email_mismatch: bool = False
    suspicious_pattern: bool = False
    risk_score: float = 0.0
    indicators: List[str] = field(default_factory=list)


@dataclass
class PhishingAnalysisResult:
    """Complete phishing analysis result."""
    is_phishing: bool
    confidence: float
    risk_score: float
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    sender_analysis: SenderAnalysis
    header_analysis: HeaderAnalysis
    content_analysis: ContentAnalysis
    url_analyses: List[URLAnalysis]
    attachment_analyses: List[AttachmentAnalysis]
    top_indicators: List[str]
    detailed_explanation: str
    recommendations: List[str]
    raw_features: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# PHISHING INDICATOR DATABASES
# ============================================================================

class PhishingIndicators:
    """Database of known phishing indicators and patterns."""

    # Urgency and threat language patterns
    URGENCY_PATTERNS = [
        r'\b(urgent|immediately|right away|asap|within 24 hours|within 48 hours)\b',
        r'\b(act now|act fast|don\'t delay|time sensitive|expires? today)\b',
        r'\b(limited time|last chance|final notice|final warning)\b',
        r'\b(hurry|rush|quick|fast action required)\b',
    ]

    THREAT_PATTERNS = [
        r'\b(account.*(suspend|terminat|clos|lock|restrict))',
        r'\b(suspend|terminat|clos|lock|restrict).*account\b',
        r'\b(legal action|lawsuit|prosecut|arrest|warrant)\b',
        r'\b(unauthorized (access|activity|transaction))\b',
        r'\b(security (breach|alert|warning|threat))\b',
        r'\b(your.*(compromised|hacked|stolen))\b',
        r'\b(failure to (comply|respond|verify))\b',
    ]

    ACTION_PATTERNS = [
        r'\b(click (here|below|the link|this link))\b',
        r'\b(verify your (account|identity|information))\b',
        r'\b(confirm your (account|identity|details|password))\b',
        r'\b(update your (information|account|details|password))\b',
        r'\b(log\s?in (immediately|now|to verify))\b',
        r'\b(reset your password)\b',
        r'\b(download (the |this )?(attached|attachment|file))\b',
    ]

    SENSITIVE_REQUEST_PATTERNS = [
        r'\b(social security|ssn|tax.?id)\b',
        r'\b(credit card|debit card|card number|cvv|cvc)\b',
        r'\b(bank account|routing number|account number)\b',
        r'\b(password|pin|passcode|security code)\b',
        r'\b(mother\'?s? maiden|security question)\b',
        r'\b(date of birth|dob|birthday)\b',
        r'\b(driver\'?s? licen[cs]e)\b',
    ]

    # Known brand targets for typosquatting detection
    COMMON_TARGETS = [
        'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
        'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'chase',
        'wellsfargo', 'bankofamerica', 'citibank', 'usbank', 'capitalone',
        'americanexpress', 'discover', 'irs', 'fedex', 'ups', 'usps', 'dhl',
        'walmart', 'target', 'bestbuy', 'ebay', 'adobe', 'docusign', 'zoom',
        'slack', 'salesforce', 'office365', 'outlook', 'yahoo', 'aol'
    ]

    # Suspicious TLDs commonly used in phishing
    SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free domains
        'xyz', 'top', 'work', 'click', 'link', 'info',
        'ru', 'cn', 'su', 'cc', 'ws', 'pw',  # High-abuse TLDs
        'zip', 'mov',  # New confusing TLDs
    ]

    # URL shortening services
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
        'buff.ly', 'j.mp', 'su.pr', 'tr.im', 'cli.gs', 'short.to',
        'budurl.com', 'ping.fm', 'post.ly', 'just.as', 'bkite.com',
        'snipr.com', 'snipurl.com', 'snurl.com', 'rb.gy', 'cutt.ly',
        'shorturl.at', 'tiny.cc', 'bc.vc', 'adf.ly', 'linktr.ee'
    ]

    # Free email providers (suspicious for corporate impersonation)
    FREE_EMAIL_PROVIDERS = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
        'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com', 'gmx.com',
        'icloud.com', 'me.com', 'live.com', 'msn.com', 'inbox.com'
    ]

    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = [
        '.exe', '.scr', '.pif', '.bat', '.cmd', '.com', '.vbs', '.vbe',
        '.js', '.jse', '.ws', '.wsf', '.msc', '.msi', '.msp', '.hta',
        '.cpl', '.jar', '.ps1', '.psm1', '.reg', '.lnk', '.inf', '.sct'
    ]

    # Macro-enabled document extensions
    MACRO_EXTENSIONS = [
        '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm', '.xlam',
        '.ppam', '.sldm'
    ]

    # Archive extensions (can hide malicious files)
    ARCHIVE_EXTENSIONS = [
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso', '.cab',
        '.arj', '.lzh', '.ace'
    ]


# ============================================================================
# CORE ANALYSIS ENGINE
# ============================================================================

class PhishingDetector:
    """
    Advanced phishing email detection engine combining ML and heuristics.

    The detector uses a multi-layered approach:
    1. Sender analysis - Examines email origin patterns
    2. Header analysis - Validates email authentication (SPF/DKIM/DMARC)
    3. Content analysis - Detects social engineering language
    4. URL analysis - Identifies malicious links and typosquatting
    5. Attachment analysis - Flags dangerous file types
    6. ML scoring - Uses trained model for probabilistic assessment
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the phishing detector.

        Args:
            model_path: Optional path to a pre-trained ML model
        """
        self.indicators = PhishingIndicators()
        self.model = None
        self.vectorizer = None

        if model_path and Path(model_path).exists():
            self._load_model(model_path)

        # Compile regex patterns for efficiency
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for better performance."""
        self.urgency_re = [re.compile(p, re.IGNORECASE) for p in self.indicators.URGENCY_PATTERNS]
        self.threat_re = [re.compile(p, re.IGNORECASE) for p in self.indicators.THREAT_PATTERNS]
        self.action_re = [re.compile(p, re.IGNORECASE) for p in self.indicators.ACTION_PATTERNS]
        self.sensitive_re = [re.compile(p, re.IGNORECASE) for p in self.indicators.SENSITIVE_REQUEST_PATTERNS]

        # URL extraction pattern
        self.url_pattern = re.compile(
            r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
            re.IGNORECASE
        )

        # Email pattern
        self.email_pattern = re.compile(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            re.IGNORECASE
        )

        # IP address pattern
        self.ip_pattern = re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        )

    def _load_model(self, model_path: str):
        """Load a pre-trained ML model."""
        try:
            model_data = joblib.load(model_path)
            self.model = model_data.get('model')
            self.vectorizer = model_data.get('vectorizer')
            logger.info(f"Loaded model from {model_path}")
        except Exception as e:
            logger.warning(f"Could not load model: {e}")

    def analyze_email(self, email_input: str, is_file: bool = False) -> PhishingAnalysisResult:
        """
        Perform comprehensive phishing analysis on an email.

        Args:
            email_input: Either a file path to .eml file or raw email text
            is_file: If True, email_input is treated as a file path

        Returns:
            PhishingAnalysisResult with complete analysis
        """
        # Parse the email
        msg = self._parse_email(email_input, is_file)

        # Extract email components
        subject = msg.get('Subject', '')
        from_header = msg.get('From', '')
        to_header = msg.get('To', '')
        reply_to = msg.get('Reply-To', '')
        return_path = msg.get('Return-Path', '')

        # Get body content
        body_text, body_html = self._extract_body(msg)
        full_body = body_text or self._html_to_text(body_html)

        # Get attachments
        attachments = self._extract_attachments(msg)

        # Perform component analyses
        sender_analysis = self._analyze_sender(from_header, reply_to, return_path)
        header_analysis = self._analyze_headers(msg)
        content_analysis = self._analyze_content(subject, full_body)
        url_analyses = self._analyze_urls(full_body, body_html)
        attachment_analyses = self._analyze_attachments(attachments)

        # Calculate composite risk score
        risk_score, risk_breakdown = self._calculate_risk_score(
            sender_analysis, header_analysis, content_analysis,
            url_analyses, attachment_analyses
        )

        # Determine risk level
        risk_level = self._determine_risk_level(risk_score)

        # Use ML model if available for additional confidence
        ml_score = self._get_ml_score(subject, full_body) if self.model else None

        # Combine heuristic and ML scores
        if ml_score is not None:
            final_score = (risk_score * 0.6) + (ml_score * 0.4)
        else:
            final_score = risk_score

        # Compile top indicators
        top_indicators = self._compile_top_indicators(
            sender_analysis, header_analysis, content_analysis,
            url_analyses, attachment_analyses
        )

        # Generate detailed explanation
        explanation = self._generate_explanation(
            risk_score, risk_breakdown, top_indicators
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            risk_level, top_indicators
        )

        return PhishingAnalysisResult(
            is_phishing=final_score >= 0.5,
            confidence=min(1.0, final_score + 0.1) if final_score >= 0.5 else 1.0 - final_score,
            risk_score=final_score,
            risk_level=risk_level,
            sender_analysis=sender_analysis,
            header_analysis=header_analysis,
            content_analysis=content_analysis,
            url_analyses=url_analyses,
            attachment_analyses=attachment_analyses,
            top_indicators=top_indicators[:10],
            detailed_explanation=explanation,
            recommendations=recommendations,
            raw_features=risk_breakdown
        )

    def _parse_email(self, email_input: str, is_file: bool) -> email.message.EmailMessage:
        """Parse email from file or raw text."""
        if is_file:
            path = Path(email_input)
            if not path.exists():
                raise FileNotFoundError(f"Email file not found: {email_input}")

            with open(path, 'rb') as f:
                return BytesParser(policy=policy.default).parse(f)
        else:
            return Parser(policy=policy.default).parsestr(email_input)

    def _extract_body(self, msg: email.message.EmailMessage) -> Tuple[str, str]:
        """Extract plain text and HTML body from email."""
        text_body = ""
        html_body = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        content = payload.decode(charset, errors='replace')

                        if content_type == 'text/plain':
                            text_body = content
                        elif content_type == 'text/html':
                            html_body = content
                except Exception:
                    continue
        else:
            content_type = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    content = payload.decode(charset, errors='replace')

                    if content_type == 'text/plain':
                        text_body = content
                    elif content_type == 'text/html':
                        html_body = content
            except Exception:
                pass

        return text_body, html_body

    def _html_to_text(self, html: str) -> str:
        """Convert HTML to plain text (basic implementation)."""
        if not html:
            return ""

        # Remove script and style elements
        text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)

        # Replace common HTML entities
        text = text.replace('&nbsp;', ' ')
        text = text.replace('&amp;', '&')
        text = text.replace('&lt;', '<')
        text = text.replace('&gt;', '>')
        text = text.replace('&quot;', '"')

        # Remove all tags
        text = re.sub(r'<[^>]+>', ' ', text)

        # Collapse whitespace
        text = re.sub(r'\s+', ' ', text)

        return text.strip()

    def _extract_attachments(self, msg: email.message.EmailMessage) -> List[Dict]:
        """Extract attachment information from email."""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = part.get('Content-Disposition', '')

                if 'attachment' in content_disposition or 'inline' in content_disposition:
                    filename = part.get_filename() or 'unknown'
                    content_type = part.get_content_type()

                    try:
                        payload = part.get_payload(decode=True)
                        size = len(payload) if payload else 0
                    except Exception:
                        size = 0

                    attachments.append({
                        'filename': filename,
                        'content_type': content_type,
                        'size': size
                    })

        return attachments

    def _analyze_sender(self, from_header: str, reply_to: str,
                        return_path: str) -> SenderAnalysis:
        """Analyze sender information for phishing indicators."""
        analysis = SenderAnalysis()

        # Extract email address and display name
        match = re.search(r'<([^>]+)>', from_header)
        if match:
            analysis.from_address = match.group(1).lower()
            analysis.from_name = from_header[:match.start()].strip().strip('"\'')
        else:
            analysis.from_address = from_header.strip().lower()

        # Extract domain
        if '@' in analysis.from_address:
            analysis.domain = analysis.from_address.split('@')[1]

        # Check for free email provider
        if analysis.domain in self.indicators.FREE_EMAIL_PROVIDERS:
            analysis.is_free_email = True
            analysis.indicators.append(f"Uses free email provider: {analysis.domain}")
            analysis.risk_score += 0.2

        # Check for name/email mismatch (e.g., "PayPal Security" but gmail.com)
        if analysis.from_name:
            name_lower = analysis.from_name.lower()
            for brand in self.indicators.COMMON_TARGETS:
                if brand in name_lower and brand not in analysis.domain:
                    analysis.name_email_mismatch = True
                    analysis.indicators.append(
                        f"Display name mentions '{brand}' but email domain is '{analysis.domain}'"
                    )
                    analysis.risk_score += 0.4
                    break

        # Check for lookalike domains
        lookalike_result = self._check_lookalike_domain(analysis.domain)
        if lookalike_result:
            analysis.is_lookalike = True
            analysis.lookalike_target = lookalike_result
            analysis.indicators.append(
                f"Domain '{analysis.domain}' appears to impersonate '{lookalike_result}'"
            )
            analysis.risk_score += 0.5

        # Check reply-to mismatch
        if reply_to:
            reply_email = self._extract_email(reply_to)
            if reply_email and '@' in reply_email:
                reply_domain = reply_email.split('@')[1]
                if reply_domain != analysis.domain:
                    analysis.indicators.append(
                        f"Reply-To domain ({reply_domain}) differs from sender ({analysis.domain})"
                    )
                    analysis.risk_score += 0.3

        # Check return-path mismatch
        if return_path:
            return_email = self._extract_email(return_path)
            if return_email and '@' in return_email:
                return_domain = return_email.split('@')[1]
                if return_domain != analysis.domain:
                    analysis.indicators.append(
                        f"Return-Path domain ({return_domain}) differs from sender ({analysis.domain})"
                    )
                    analysis.risk_score += 0.2

        # Check for suspicious patterns
        suspicious_patterns = [
            r'\d{5,}',  # Many numbers in local part
            r'^[a-z]{1,2}\d+',  # Letter(s) followed by numbers
            r'noreply.*support',  # Contradictory prefixes
            r'support.*noreply',
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, analysis.from_address):
                analysis.suspicious_pattern = True
                analysis.indicators.append("Sender address matches suspicious pattern")
                analysis.risk_score += 0.15
                break

        analysis.risk_score = min(1.0, analysis.risk_score)
        return analysis

    def _analyze_headers(self, msg: email.message.EmailMessage) -> HeaderAnalysis:
        """Analyze email headers for authentication and anomalies."""
        analysis = HeaderAnalysis()

        # Check Authentication-Results header
        auth_results = msg.get('Authentication-Results', '')

        # Parse SPF result
        spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        if spf_match:
            analysis.spf_result = spf_match.group(1).lower()
            if analysis.spf_result in ['fail', 'softfail', 'none']:
                analysis.indicators.append(f"SPF check result: {analysis.spf_result}")
                analysis.risk_score += 0.25

        # Parse DKIM result
        dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
        if dkim_match:
            analysis.dkim_result = dkim_match.group(1).lower()
            if analysis.dkim_result in ['fail', 'none']:
                analysis.indicators.append(f"DKIM check result: {analysis.dkim_result}")
                analysis.risk_score += 0.25

        # Parse DMARC result
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
        if dmarc_match:
            analysis.dmarc_result = dmarc_match.group(1).lower()
            if analysis.dmarc_result in ['fail', 'none']:
                analysis.indicators.append(f"DMARC check result: {analysis.dmarc_result}")
                analysis.risk_score += 0.25

        # Analyze Received headers for anomalies
        received_headers = msg.get_all('Received', [])
        if len(received_headers) > 10:
            analysis.received_chain_anomalies.append(
                f"Unusually long hop chain ({len(received_headers)} hops)"
            )
            analysis.risk_score += 0.1

        # Check for suspicious X-headers
        for header_name in msg.keys():
            if header_name.startswith('X-'):
                value = msg.get(header_name, '')
                if 'phish' in value.lower() or 'spam' in value.lower():
                    analysis.suspicious_x_headers.append(f"{header_name}: {value[:50]}")
                    analysis.risk_score += 0.2

        # Check X-Spam-Flag
        spam_flag = msg.get('X-Spam-Flag', '')
        if spam_flag.upper() == 'YES':
            analysis.indicators.append("X-Spam-Flag is set to YES")
            analysis.risk_score += 0.3

        # Check X-Spam-Score if present
        spam_score = msg.get('X-Spam-Score', '')
        if spam_score:
            try:
                score = float(spam_score)
                if score > 5:
                    analysis.indicators.append(f"High spam score: {score}")
                    analysis.risk_score += 0.2
            except ValueError:
                pass

        analysis.risk_score = min(1.0, analysis.risk_score)
        return analysis

    def _analyze_content(self, subject: str, body: str) -> ContentAnalysis:
        """Analyze email content for social engineering patterns."""
        analysis = ContentAnalysis()
        full_text = f"{subject} {body}".lower()

        # Check urgency patterns
        for pattern in self.urgency_re:
            matches = pattern.findall(full_text)
            analysis.urgency_phrases.extend(matches)

        if analysis.urgency_phrases:
            unique_urgency = list(set(analysis.urgency_phrases))
            analysis.indicators.append(
                f"Urgency language detected: {', '.join(unique_urgency[:3])}"
            )
            analysis.risk_score += min(0.3, len(unique_urgency) * 0.1)

        # Check threat patterns
        for pattern in self.threat_re:
            matches = pattern.findall(full_text)
            analysis.threat_phrases.extend(matches)

        if analysis.threat_phrases:
            unique_threats = list(set(analysis.threat_phrases))
            analysis.indicators.append(
                f"Threat language detected: {', '.join(unique_threats[:3])}"
            )
            analysis.risk_score += min(0.4, len(unique_threats) * 0.15)

        # Check action patterns
        for pattern in self.action_re:
            matches = pattern.findall(full_text)
            analysis.action_phrases.extend(matches)

        if analysis.action_phrases:
            unique_actions = list(set(analysis.action_phrases))
            analysis.indicators.append(
                f"Action requests detected: {', '.join(unique_actions[:3])}"
            )
            analysis.risk_score += min(0.25, len(unique_actions) * 0.08)

        # Check for sensitive information requests
        for pattern in self.sensitive_re:
            matches = pattern.findall(full_text)
            analysis.sensitive_requests.extend(matches)

        if analysis.sensitive_requests:
            unique_sensitive = list(set(analysis.sensitive_requests))
            analysis.indicators.append(
                f"Requests for sensitive information: {', '.join(unique_sensitive[:3])}"
            )
            analysis.risk_score += min(0.5, len(unique_sensitive) * 0.2)

        # Check for excessive punctuation (!!!, ???, etc.)
        excessive_punct = re.findall(r'[!?]{2,}', body)
        if excessive_punct:
            analysis.excessive_punctuation = True
            analysis.indicators.append("Excessive punctuation detected")
            analysis.risk_score += 0.1

        # Calculate ALL CAPS ratio
        if body:
            words = body.split()
            caps_words = [w for w in words if w.isupper() and len(w) > 2]
            analysis.all_caps_ratio = len(caps_words) / max(len(words), 1)

            if analysis.all_caps_ratio > 0.2:
                analysis.indicators.append(
                    f"High proportion of ALL CAPS text ({analysis.all_caps_ratio:.1%})"
                )
                analysis.risk_score += 0.15

        # Check for common grammar issues in phishing
        grammar_issues = [
            r'\b(kindly|do the needful|revert back|prepone)\b',  # Non-native patterns
            r'dear (customer|user|member|valued)\b',  # Generic greetings
            r'\b(we has|you was|they is)\b',  # Subject-verb disagreement
        ]

        for pattern in grammar_issues:
            if re.search(pattern, full_text, re.IGNORECASE):
                analysis.grammar_issues += 1

        if analysis.grammar_issues > 0:
            analysis.indicators.append(
                f"Potential grammar/language anomalies detected ({analysis.grammar_issues})"
            )
            analysis.risk_score += min(0.2, analysis.grammar_issues * 0.07)

        analysis.risk_score = min(1.0, analysis.risk_score)
        return analysis

    def _analyze_urls(self, text: str, html: str) -> List[URLAnalysis]:
        """Analyze URLs in email for malicious indicators."""
        url_analyses = []
        seen_urls = set()

        # Extract URLs from text
        text_urls = self.url_pattern.findall(text) if text else []

        # Extract URLs from HTML with display text
        html_links = []
        if html:
            link_pattern = re.compile(
                r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>',
                re.IGNORECASE
            )
            html_links = link_pattern.findall(html)

        # Process text URLs
        for url in text_urls:
            if url not in seen_urls:
                seen_urls.add(url)
                analysis = self._analyze_single_url(url, "")
                url_analyses.append(analysis)

        # Process HTML links
        for href, display_text in html_links:
            if href not in seen_urls:
                seen_urls.add(href)
                analysis = self._analyze_single_url(href, display_text)
                url_analyses.append(analysis)

        return url_analyses

    def _analyze_single_url(self, url: str, display_text: str) -> URLAnalysis:
        """Analyze a single URL for phishing indicators."""
        analysis = URLAnalysis(url=url, display_text=display_text)

        try:
            parsed = urlparse(url)
            analysis.domain = parsed.netloc.lower()
        except Exception:
            analysis.domain = ""
            analysis.indicators.append("Malformed URL")
            analysis.risk_score = 0.5
            return analysis

        # Remove port if present
        if ':' in analysis.domain:
            analysis.domain = analysis.domain.split(':')[0]

        # Extract TLD
        if HAS_TLDEXTRACT:
            try:
                extracted = tldextract.extract(url)
                analysis.tld = extracted.suffix
                analysis.domain = f"{extracted.domain}.{extracted.suffix}"
            except Exception:
                pass
        else:
            parts = analysis.domain.split('.')
            if len(parts) >= 2:
                analysis.tld = parts[-1]

        # Check if URL uses IP address
        if self.ip_pattern.match(analysis.domain):
            analysis.is_ip_address = True
            analysis.indicators.append("URL uses IP address instead of domain name")
            analysis.risk_score += 0.4

        # Check for URL shortener
        for shortener in self.indicators.URL_SHORTENERS:
            if shortener in analysis.domain:
                analysis.is_shortened = True
                analysis.indicators.append(f"Uses URL shortening service: {shortener}")
                analysis.risk_score += 0.3
                break

        # Check for suspicious TLD
        if analysis.tld in self.indicators.SUSPICIOUS_TLDS:
            analysis.suspicious_tld = True
            analysis.indicators.append(f"Suspicious TLD: .{analysis.tld}")
            analysis.risk_score += 0.25

        # Check for display/href mismatch
        if display_text:
            display_clean = display_text.strip().lower()

            # Check if display looks like a URL but differs
            if display_clean.startswith(('http://', 'https://', 'www.')):
                try:
                    display_parsed = urlparse(
                        display_clean if '://' in display_clean else f'http://{display_clean}'
                    )
                    display_domain = display_parsed.netloc.lower()

                    if display_domain and display_domain != analysis.domain:
                        analysis.mismatch_detected = True
                        analysis.indicators.append(
                            f"URL mismatch: displays '{display_domain}' but links to '{analysis.domain}'"
                        )
                        analysis.risk_score += 0.5
                except Exception:
                    pass

            # Check if display mentions a brand but URL is different
            for brand in self.indicators.COMMON_TARGETS:
                if brand in display_clean and brand not in analysis.domain:
                    analysis.mismatch_detected = True
                    analysis.indicators.append(
                        f"Display text mentions '{brand}' but URL domain is '{analysis.domain}'"
                    )
                    analysis.risk_score += 0.4
                    break

        # Check for typosquatting
        typosquat_result = self._check_typosquatting(analysis.domain)
        if typosquat_result:
            analysis.is_typosquat = True
            analysis.typosquat_target = typosquat_result
            analysis.indicators.append(
                f"Possible typosquatting: '{analysis.domain}' mimics '{typosquat_result}'"
            )
            analysis.risk_score += 0.45

        # Check for suspicious URL patterns
        suspicious_url_patterns = [
            (r'login|signin|verify|secure|account|update|confirm', "Contains credential-related keywords"),
            (r'@', "Contains @ symbol (potential URL obfuscation)"),
            (r'%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}', "Heavy URL encoding"),
            (r'-{2,}|_{2,}', "Multiple consecutive dashes/underscores"),
        ]

        for pattern, description in suspicious_url_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                analysis.indicators.append(description)
                analysis.risk_score += 0.1

        analysis.risk_score = min(1.0, analysis.risk_score)
        return analysis

    def _analyze_attachments(self, attachments: List[Dict]) -> List[AttachmentAnalysis]:
        """Analyze email attachments for dangerous file types."""
        analyses = []

        for attachment in attachments:
            filename = attachment.get('filename', 'unknown')
            content_type = attachment.get('content_type', '')
            size = attachment.get('size', 0)

            # Get file extension
            ext = ''
            if '.' in filename:
                ext = '.' + filename.rsplit('.', 1)[-1].lower()

            analysis = AttachmentAnalysis(
                filename=filename,
                extension=ext,
                size_bytes=size,
                content_type=content_type
            )

            # Check for executable
            if ext in self.indicators.DANGEROUS_EXTENSIONS:
                analysis.is_executable = True
                analysis.indicators.append(f"Dangerous file extension: {ext}")
                analysis.risk_score += 0.6

            # Check for macro-enabled documents
            if ext in self.indicators.MACRO_EXTENSIONS:
                analysis.is_macro_enabled = True
                analysis.indicators.append(f"Macro-enabled document: {ext}")
                analysis.risk_score += 0.5

            # Check for archives
            if ext in self.indicators.ARCHIVE_EXTENSIONS:
                analysis.is_archive = True
                analysis.indicators.append(f"Archive file that may contain hidden content: {ext}")
                analysis.risk_score += 0.3

            # Check for double extensions (e.g., document.pdf.exe)
            if filename.count('.') >= 2:
                parts = filename.rsplit('.', 2)
                if len(parts) >= 3:
                    second_ext = '.' + parts[-2].lower()
                    if second_ext in self.indicators.DANGEROUS_EXTENSIONS:
                        analysis.double_extension = True
                        analysis.indicators.append(
                            f"Double extension detected: hidden {second_ext} extension"
                        )
                        analysis.risk_score += 0.7

            # Check for suspicious content type mismatches
            if content_type:
                if 'application/octet-stream' in content_type and ext in ['.pdf', '.doc', '.docx']:
                    analysis.indicators.append(
                        "Content-Type mismatch: generic binary type for document"
                    )
                    analysis.risk_score += 0.2

            analysis.risk_score = min(1.0, analysis.risk_score)
            analyses.append(analysis)

        return analyses

    def _check_lookalike_domain(self, domain: str) -> Optional[str]:
        """Check if domain is a lookalike of a known brand."""
        if not domain:
            return None

        domain_lower = domain.lower()

        # Direct substring checks
        for brand in self.indicators.COMMON_TARGETS:
            # Check for brand with typos or additions
            if brand in domain_lower and domain_lower != f"{brand}.com":
                # e.g., "paypal-secure.com", "paypal.verify.com"
                return brand

            # Check for common character substitutions
            substitutions = {
                'a': ['4', '@'],
                'e': ['3'],
                'i': ['1', 'l', '!'],
                'o': ['0'],
                's': ['5', '$'],
                'l': ['1', 'i'],
            }

            # Generate simple variants
            for orig, replacements in substitutions.items():
                if orig in brand:
                    for repl in replacements:
                        variant = brand.replace(orig, repl)
                        if variant in domain_lower:
                            return brand

        # Use Levenshtein distance for close matches
        if HAS_LEVENSHTEIN:
            domain_base = domain_lower.split('.')[0] if '.' in domain_lower else domain_lower

            for brand in self.indicators.COMMON_TARGETS:
                distance = Levenshtein.distance(domain_base, brand)
                # If only 1-2 characters different, likely typosquat
                if 0 < distance <= 2 and len(brand) >= 5:
                    return brand

        return None

    def _check_typosquatting(self, domain: str) -> Optional[str]:
        """Check for typosquatting patterns in domain."""
        if not domain:
            return None

        # Use lookalike check as typosquatting is a form of it
        return self._check_lookalike_domain(domain)

    def _extract_email(self, header: str) -> str:
        """Extract email address from a header value."""
        match = re.search(r'<([^>]+)>', header)
        if match:
            return match.group(1)

        match = self.email_pattern.search(header)
        if match:
            return match.group(0)

        return header.strip()

    def _calculate_risk_score(
        self,
        sender: SenderAnalysis,
        header: HeaderAnalysis,
        content: ContentAnalysis,
        urls: List[URLAnalysis],
        attachments: List[AttachmentAnalysis]
    ) -> Tuple[float, Dict[str, float]]:
        """Calculate composite risk score with weighted components."""
        weights = {
            'sender': 0.20,
            'header': 0.15,
            'content': 0.25,
            'urls': 0.25,
            'attachments': 0.15,
        }

        # Get max URL and attachment risk
        max_url_risk = max([u.risk_score for u in urls], default=0)
        max_attach_risk = max([a.risk_score for a in attachments], default=0)

        breakdown = {
            'sender': sender.risk_score,
            'header': header.risk_score,
            'content': content.risk_score,
            'urls': max_url_risk,
            'attachments': max_attach_risk,
        }

        # Calculate weighted score
        total_score = sum(breakdown[k] * weights[k] for k in weights)

        # Apply amplification for high-risk combinations
        critical_indicators = 0
        if sender.is_lookalike or sender.name_email_mismatch:
            critical_indicators += 1
        if any(u.mismatch_detected or u.is_typosquat for u in urls):
            critical_indicators += 1
        if content.sensitive_requests:
            critical_indicators += 1
        if any(a.is_executable or a.double_extension for a in attachments):
            critical_indicators += 1

        # Amplify score for multiple critical indicators
        if critical_indicators >= 3:
            total_score = min(1.0, total_score * 1.5)
        elif critical_indicators >= 2:
            total_score = min(1.0, total_score * 1.25)

        breakdown['critical_indicators'] = critical_indicators
        breakdown['weighted_total'] = total_score

        return total_score, breakdown

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level category from score."""
        if risk_score >= 0.75:
            return "CRITICAL"
        elif risk_score >= 0.5:
            return "HIGH"
        elif risk_score >= 0.25:
            return "MEDIUM"
        else:
            return "LOW"

    def _get_ml_score(self, subject: str, body: str) -> Optional[float]:
        """Get phishing probability from ML model."""
        if not self.model or not self.vectorizer:
            return None

        try:
            text = f"{subject} {body}"
            features = self.vectorizer.transform([text])
            proba = self.model.predict_proba(features)[0]
            # Return probability of phishing class
            return proba[1] if len(proba) > 1 else proba[0]
        except Exception as e:
            logger.warning(f"ML scoring failed: {e}")
            return None

    def _compile_top_indicators(
        self,
        sender: SenderAnalysis,
        header: HeaderAnalysis,
        content: ContentAnalysis,
        urls: List[URLAnalysis],
        attachments: List[AttachmentAnalysis]
    ) -> List[str]:
        """Compile top indicators from all analyses."""
        all_indicators = []

        # Weight indicators by severity
        for indicator in sender.indicators:
            all_indicators.append((sender.risk_score, f"[Sender] {indicator}"))

        for indicator in header.indicators:
            all_indicators.append((header.risk_score, f"[Header] {indicator}"))

        for indicator in content.indicators:
            all_indicators.append((content.risk_score, f"[Content] {indicator}"))

        for url in urls:
            for indicator in url.indicators:
                all_indicators.append((url.risk_score, f"[URL] {indicator}"))

        for attach in attachments:
            for indicator in attach.indicators:
                all_indicators.append((attach.risk_score, f"[Attachment] {indicator}"))

        # Sort by risk score and return indicator text
        all_indicators.sort(key=lambda x: x[0], reverse=True)
        return [ind[1] for ind in all_indicators]

    def _generate_explanation(
        self,
        risk_score: float,
        breakdown: Dict[str, float],
        indicators: List[str]
    ) -> str:
        """Generate human-readable explanation of analysis."""
        lines = []

        level = self._determine_risk_level(risk_score)
        lines.append(f"PHISHING RISK ASSESSMENT: {level}")
        lines.append(f"Overall Risk Score: {risk_score:.2%}")
        lines.append("")
        lines.append("COMPONENT BREAKDOWN:")
        lines.append(f"  - Sender Analysis:     {breakdown.get('sender', 0):.2%}")
        lines.append(f"  - Header Analysis:     {breakdown.get('header', 0):.2%}")
        lines.append(f"  - Content Analysis:    {breakdown.get('content', 0):.2%}")
        lines.append(f"  - URL Analysis:        {breakdown.get('urls', 0):.2%}")
        lines.append(f"  - Attachment Analysis: {breakdown.get('attachments', 0):.2%}")
        lines.append("")

        if indicators:
            lines.append("KEY INDICATORS:")
            for i, indicator in enumerate(indicators[:10], 1):
                lines.append(f"  {i}. {indicator}")
        else:
            lines.append("No significant phishing indicators detected.")

        return "\n".join(lines)

    def _generate_recommendations(
        self,
        risk_level: str,
        indicators: List[str]
    ) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []

        if risk_level == "CRITICAL":
            recommendations.append("DO NOT interact with this email - delete immediately")
            recommendations.append("Do not click any links or download attachments")
            recommendations.append("Report this email to your IT security team")
            recommendations.append("If you already clicked links, change your passwords immediately")
        elif risk_level == "HIGH":
            recommendations.append("Treat this email with extreme caution")
            recommendations.append("Verify the sender through an independent channel")
            recommendations.append("Do not click links - navigate to websites directly")
            recommendations.append("Report to your security team for further analysis")
        elif risk_level == "MEDIUM":
            recommendations.append("Exercise caution with this email")
            recommendations.append("Verify sender identity before taking any action")
            recommendations.append("Hover over links to verify destinations before clicking")
            recommendations.append("Consider reporting for security review")
        else:
            recommendations.append("This email appears to be low risk")
            recommendations.append("Standard email security practices apply")
            recommendations.append("Remain vigilant for unexpected requests")

        # Add specific recommendations based on indicators
        indicator_text = " ".join(indicators).lower()

        if "attachment" in indicator_text:
            recommendations.append("Scan any attachments with antivirus before opening")

        if "url" in indicator_text or "link" in indicator_text:
            recommendations.append("Verify all URLs by hovering before clicking")

        if "password" in indicator_text or "credential" in indicator_text:
            recommendations.append("Never enter credentials through email links")

        return recommendations


# ============================================================================
# ML MODEL TRAINING
# ============================================================================

class PhishingModelTrainer:
    """Train a machine learning model for phishing detection."""

    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words='english',
            lowercase=True,
            min_df=2,
            max_df=0.95
        )

        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )

    def train(
        self,
        texts: List[str],
        labels: List[int],
        test_size: float = 0.2
    ) -> Dict[str, float]:
        """
        Train the phishing detection model.

        Args:
            texts: List of email texts
            labels: List of labels (0 = legitimate, 1 = phishing)
            test_size: Proportion for test set

        Returns:
            Dictionary of evaluation metrics
        """
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=test_size, random_state=42, stratify=labels
        )

        # Vectorize
        X_train_vec = self.vectorizer.fit_transform(X_train)
        X_test_vec = self.vectorizer.transform(X_test)

        # Train
        self.model.fit(X_train_vec, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test_vec)

        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'train_samples': len(X_train),
            'test_samples': len(X_test)
        }

        return metrics

    def save(self, path: str):
        """Save trained model to disk."""
        model_data = {
            'model': self.model,
            'vectorizer': self.vectorizer
        }
        joblib.dump(model_data, path)
        logger.info(f"Model saved to {path}")

    def load(self, path: str):
        """Load trained model from disk."""
        model_data = joblib.load(path)
        self.model = model_data['model']
        self.vectorizer = model_data['vectorizer']
        logger.info(f"Model loaded from {path}")


# ============================================================================
# REPORT GENERATION
# ============================================================================

class ReportGenerator:
    """Generate formatted analysis reports."""

    @staticmethod
    def generate_text_report(result: PhishingAnalysisResult) -> str:
        """Generate a plain text report."""
        lines = []
        lines.append("=" * 70)
        lines.append("PHISHING EMAIL ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Summary
        verdict = "LIKELY PHISHING" if result.is_phishing else "LIKELY LEGITIMATE"
        lines.append(f"VERDICT: {verdict}")
        lines.append(f"Risk Level: {result.risk_level}")
        lines.append(f"Risk Score: {result.risk_score:.2%}")
        lines.append(f"Confidence: {result.confidence:.2%}")
        lines.append("")

        lines.append("-" * 70)
        lines.append("DETAILED EXPLANATION")
        lines.append("-" * 70)
        lines.append(result.detailed_explanation)
        lines.append("")

        lines.append("-" * 70)
        lines.append("SENDER ANALYSIS")
        lines.append("-" * 70)
        sender = result.sender_analysis
        lines.append(f"From Address: {sender.from_address}")
        lines.append(f"Display Name: {sender.from_name}")
        lines.append(f"Domain: {sender.domain}")
        lines.append(f"Free Email Provider: {'Yes' if sender.is_free_email else 'No'}")
        lines.append(f"Lookalike Domain: {'Yes - ' + sender.lookalike_target if sender.is_lookalike else 'No'}")
        lines.append(f"Risk Score: {sender.risk_score:.2%}")
        lines.append("")

        lines.append("-" * 70)
        lines.append("HEADER ANALYSIS")
        lines.append("-" * 70)
        header = result.header_analysis
        lines.append(f"SPF Result: {header.spf_result}")
        lines.append(f"DKIM Result: {header.dkim_result}")
        lines.append(f"DMARC Result: {header.dmarc_result}")
        lines.append(f"Risk Score: {header.risk_score:.2%}")
        lines.append("")

        lines.append("-" * 70)
        lines.append("CONTENT ANALYSIS")
        lines.append("-" * 70)
        content = result.content_analysis
        if content.urgency_phrases:
            lines.append(f"Urgency Phrases: {', '.join(content.urgency_phrases[:5])}")
        if content.threat_phrases:
            lines.append(f"Threat Phrases: {', '.join(content.threat_phrases[:5])}")
        if content.sensitive_requests:
            lines.append(f"Sensitive Requests: {', '.join(content.sensitive_requests[:5])}")
        lines.append(f"Risk Score: {content.risk_score:.2%}")
        lines.append("")

        if result.url_analyses:
            lines.append("-" * 70)
            lines.append("URL ANALYSIS")
            lines.append("-" * 70)
            for i, url in enumerate(result.url_analyses[:5], 1):
                lines.append(f"URL {i}: {url.url[:60]}...")
                lines.append(f"  Domain: {url.domain}")
                lines.append(f"  Suspicious TLD: {'Yes' if url.suspicious_tld else 'No'}")
                lines.append(f"  URL Shortener: {'Yes' if url.is_shortened else 'No'}")
                lines.append(f"  Typosquatting: {'Yes - ' + url.typosquat_target if url.is_typosquat else 'No'}")
                lines.append(f"  Risk Score: {url.risk_score:.2%}")
            lines.append("")

        if result.attachment_analyses:
            lines.append("-" * 70)
            lines.append("ATTACHMENT ANALYSIS")
            lines.append("-" * 70)
            for attach in result.attachment_analyses:
                lines.append(f"File: {attach.filename}")
                lines.append(f"  Extension: {attach.extension}")
                lines.append(f"  Executable: {'Yes' if attach.is_executable else 'No'}")
                lines.append(f"  Macro-Enabled: {'Yes' if attach.is_macro_enabled else 'No'}")
                lines.append(f"  Double Extension: {'Yes' if attach.double_extension else 'No'}")
                lines.append(f"  Risk Score: {attach.risk_score:.2%}")
            lines.append("")

        lines.append("-" * 70)
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 70)
        for i, rec in enumerate(result.recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)

        return "\n".join(lines)

    @staticmethod
    def generate_json_report(result: PhishingAnalysisResult) -> str:
        """Generate a JSON report for programmatic consumption."""
        report = {
            'verdict': {
                'is_phishing': result.is_phishing,
                'confidence': result.confidence,
                'risk_score': result.risk_score,
                'risk_level': result.risk_level
            },
            'sender': {
                'address': result.sender_analysis.from_address,
                'display_name': result.sender_analysis.from_name,
                'domain': result.sender_analysis.domain,
                'is_free_email': result.sender_analysis.is_free_email,
                'is_lookalike': result.sender_analysis.is_lookalike,
                'lookalike_target': result.sender_analysis.lookalike_target,
                'risk_score': result.sender_analysis.risk_score,
                'indicators': result.sender_analysis.indicators
            },
            'headers': {
                'spf_result': result.header_analysis.spf_result,
                'dkim_result': result.header_analysis.dkim_result,
                'dmarc_result': result.header_analysis.dmarc_result,
                'risk_score': result.header_analysis.risk_score,
                'indicators': result.header_analysis.indicators
            },
            'content': {
                'urgency_phrases': result.content_analysis.urgency_phrases,
                'threat_phrases': result.content_analysis.threat_phrases,
                'sensitive_requests': result.content_analysis.sensitive_requests,
                'risk_score': result.content_analysis.risk_score,
                'indicators': result.content_analysis.indicators
            },
            'urls': [
                {
                    'url': u.url,
                    'domain': u.domain,
                    'is_shortened': u.is_shortened,
                    'is_typosquat': u.is_typosquat,
                    'mismatch_detected': u.mismatch_detected,
                    'risk_score': u.risk_score,
                    'indicators': u.indicators
                }
                for u in result.url_analyses
            ],
            'attachments': [
                {
                    'filename': a.filename,
                    'extension': a.extension,
                    'is_executable': a.is_executable,
                    'is_macro_enabled': a.is_macro_enabled,
                    'double_extension': a.double_extension,
                    'risk_score': a.risk_score,
                    'indicators': a.indicators
                }
                for a in result.attachment_analyses
            ],
            'top_indicators': result.top_indicators,
            'recommendations': result.recommendations
        }

        return json.dumps(report, indent=2)


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Main CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Phishing Email Detector - Analyze emails for phishing indicators',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python phishing_detector.py email.eml
  python phishing_detector.py email.eml --json
  python phishing_detector.py --text "From: attacker@evil.com..."
  python phishing_detector.py samples/phishing/ --batch
        '''
    )

    parser.add_argument(
        'input',
        nargs='?',
        help='Path to .eml file or directory for batch processing'
    )

    parser.add_argument(
        '--text', '-t',
        type=str,
        help='Raw email text to analyze'
    )

    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='Output results in JSON format'
    )

    parser.add_argument(
        '--batch', '-b',
        action='store_true',
        help='Process all .eml files in a directory'
    )

    parser.add_argument(
        '--model', '-m',
        type=str,
        help='Path to trained ML model'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize detector
    detector = PhishingDetector(model_path=args.model)
    reporter = ReportGenerator()

    if args.text:
        # Analyze raw text
        result = detector.analyze_email(args.text, is_file=False)
        if args.json:
            print(reporter.generate_json_report(result))
        else:
            print(reporter.generate_text_report(result))

    elif args.input:
        path = Path(args.input)

        if args.batch and path.is_dir():
            # Batch processing
            eml_files = list(path.glob('*.eml'))
            if not eml_files:
                print(f"No .eml files found in {path}")
                return

            print(f"Processing {len(eml_files)} email files...\n")

            results_summary = []
            for eml_file in eml_files:
                try:
                    result = detector.analyze_email(str(eml_file), is_file=True)
                    status = "PHISHING" if result.is_phishing else "LEGITIMATE"
                    results_summary.append({
                        'file': eml_file.name,
                        'status': status,
                        'risk_level': result.risk_level,
                        'score': result.risk_score
                    })
                    print(f"  {eml_file.name}: {status} ({result.risk_level}, {result.risk_score:.2%})")
                except Exception as e:
                    print(f"  {eml_file.name}: ERROR - {e}")

            print(f"\nProcessed {len(results_summary)} files")
            phishing_count = sum(1 for r in results_summary if r['status'] == 'PHISHING')
            print(f"Phishing detected: {phishing_count}/{len(results_summary)}")

        elif path.is_file():
            # Single file processing
            result = detector.analyze_email(str(path), is_file=True)
            if args.json:
                print(reporter.generate_json_report(result))
            else:
                print(reporter.generate_text_report(result))

        else:
            print(f"Error: {path} is not a valid file or directory")
            return

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
