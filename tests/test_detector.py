#!/usr/bin/env python3
"""
Unit Tests for Phishing Email Detector
======================================
Comprehensive test suite covering all detection components.
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_detector import (
    PhishingDetector,
    PhishingIndicators,
    SenderAnalysis,
    URLAnalysis,
    AttachmentAnalysis,
    ReportGenerator
)


class TestPhishingIndicators:
    """Test the indicator database patterns."""

    def test_urgency_patterns_exist(self):
        """Verify urgency patterns are defined."""
        indicators = PhishingIndicators()
        assert len(indicators.URGENCY_PATTERNS) > 0

    def test_dangerous_extensions(self):
        """Verify dangerous file extensions list."""
        indicators = PhishingIndicators()
        assert '.exe' in indicators.DANGEROUS_EXTENSIONS
        assert '.bat' in indicators.DANGEROUS_EXTENSIONS
        assert '.ps1' in indicators.DANGEROUS_EXTENSIONS

    def test_suspicious_tlds(self):
        """Verify suspicious TLDs list."""
        indicators = PhishingIndicators()
        assert 'tk' in indicators.SUSPICIOUS_TLDS
        assert 'ml' in indicators.SUSPICIOUS_TLDS

    def test_url_shorteners(self):
        """Verify URL shorteners list."""
        indicators = PhishingIndicators()
        assert 'bit.ly' in indicators.URL_SHORTENERS
        assert 'tinyurl.com' in indicators.URL_SHORTENERS


class TestPhishingDetector:
    """Test the main detection engine."""

    @pytest.fixture
    def detector(self):
        """Create detector instance for tests."""
        return PhishingDetector()

    def test_initialization(self, detector):
        """Test detector initializes correctly."""
        assert detector is not None
        assert detector.indicators is not None

    def test_parse_raw_email(self, detector):
        """Test parsing raw email text."""
        raw_email = """From: sender@example.com
To: recipient@example.com
Subject: Test Email

This is a test email body."""

        result = detector.analyze_email(raw_email, is_file=False)
        assert result is not None
        assert result.risk_score >= 0
        assert result.risk_score <= 1

    def test_detect_urgency_language(self, detector):
        """Test urgency language detection."""
        phishing_email = """From: security@fake.com
Subject: URGENT: Your account will be suspended!

You must act IMMEDIATELY or your account will be closed within 24 hours!
Click here now: http://fake.com/verify"""

        result = detector.analyze_email(phishing_email, is_file=False)
        assert len(result.content_analysis.urgency_phrases) > 0
        assert result.content_analysis.risk_score > 0

    def test_detect_threat_language(self, detector):
        """Test threat language detection."""
        phishing_email = """From: bank@fake.com
Subject: Account Suspension Notice

Your account has been suspended due to suspicious activity.
Legal action will be taken if you do not respond.
Your account will be terminated permanently."""

        result = detector.analyze_email(phishing_email, is_file=False)
        assert len(result.content_analysis.threat_phrases) > 0

    def test_detect_sensitive_requests(self, detector):
        """Test detection of requests for sensitive information."""
        phishing_email = """From: verify@fake.com
Subject: Verify Your Identity

Please provide:
- Your social security number
- Credit card number
- Bank account details
- Password"""

        result = detector.analyze_email(phishing_email, is_file=False)
        assert len(result.content_analysis.sensitive_requests) > 0

    def test_detect_suspicious_tld(self, detector):
        """Test detection of suspicious TLDs in URLs."""
        phishing_email = """From: support@fake.com
Subject: Verify Account

Click here: http://secure-login.tk/verify"""

        result = detector.analyze_email(phishing_email, is_file=False)

        # Check if URL with suspicious TLD is detected
        suspicious_urls = [u for u in result.url_analyses if u.suspicious_tld]
        assert len(suspicious_urls) > 0

    def test_detect_url_shortener(self, detector):
        """Test detection of URL shorteners."""
        phishing_email = """From: support@fake.com
Subject: Important Update

Click here: http://bit.ly/suspicious-link"""

        result = detector.analyze_email(phishing_email, is_file=False)

        shortened_urls = [u for u in result.url_analyses if u.is_shortened]
        assert len(shortened_urls) > 0

    def test_detect_ip_url(self, detector):
        """Test detection of IP-based URLs."""
        phishing_email = """From: admin@fake.com
Subject: Login Required

Access your account: http://192.168.1.100/login"""

        result = detector.analyze_email(phishing_email, is_file=False)

        ip_urls = [u for u in result.url_analyses if u.is_ip_address]
        assert len(ip_urls) > 0

    def test_detect_free_email_provider(self, detector):
        """Test detection of free email providers."""
        phishing_email = """From: "PayPal Security" <paypal.security@gmail.com>
Subject: Account Alert

Your account needs verification."""

        result = detector.analyze_email(phishing_email, is_file=False)
        assert result.sender_analysis.is_free_email is True
        assert result.sender_analysis.name_email_mismatch is True

    def test_legitimate_email_low_score(self, detector):
        """Test that legitimate-looking emails get low scores."""
        legitimate_email = """From: support@github.com
Subject: [repo/project] New comment on issue #123

@user commented on this issue:

Thanks for the bug report! I've pushed a fix.

View on GitHub:
https://github.com/repo/project/issues/123"""

        result = detector.analyze_email(legitimate_email, is_file=False)
        assert result.risk_level in ['LOW', 'MEDIUM']
        assert result.is_phishing is False

    def test_phishing_email_high_score(self, detector):
        """Test that obvious phishing gets high scores."""
        phishing_email = """From: "PayPal Security" <security@paypa1-secure.tk>
Subject: URGENT: Account Suspended!!!

Your PayPal account has been suspended!

Click here IMMEDIATELY: http://paypa1-secure.tk/verify

Provide your password, social security number, and credit card.

ACT NOW or your account will be PERMANENTLY CLOSED!"""

        result = detector.analyze_email(phishing_email, is_file=False)
        assert result.risk_level in ['HIGH', 'CRITICAL']
        assert result.is_phishing is True
        assert len(result.top_indicators) > 0


class TestSenderAnalysis:
    """Test sender analysis functionality."""

    @pytest.fixture
    def detector(self):
        return PhishingDetector()

    def test_extract_email_address(self, detector):
        """Test email address extraction from From header."""
        email = """From: "John Doe" <john@example.com>
Subject: Test

Body"""

        result = detector.analyze_email(email, is_file=False)
        assert result.sender_analysis.from_address == 'john@example.com'
        assert result.sender_analysis.from_name == 'John Doe'

    def test_detect_domain(self, detector):
        """Test domain extraction."""
        email = """From: user@company.com
Subject: Test

Body"""

        result = detector.analyze_email(email, is_file=False)
        assert result.sender_analysis.domain == 'company.com'


class TestURLAnalysis:
    """Test URL analysis functionality."""

    @pytest.fixture
    def detector(self):
        return PhishingDetector()

    def test_extract_multiple_urls(self, detector):
        """Test extraction of multiple URLs."""
        email = """From: sender@example.com
Subject: Links

Check these:
http://example.com/page1
https://example.org/page2
http://test.net/page3"""

        result = detector.analyze_email(email, is_file=False)
        assert len(result.url_analyses) >= 3


class TestAttachmentAnalysis:
    """Test attachment analysis functionality."""

    @pytest.fixture
    def detector(self):
        return PhishingDetector()

    def test_detect_dangerous_attachment(self, detector):
        """Test detection of dangerous attachments from header info."""
        # Note: We test the analysis logic with sample file headers
        email = """MIME-Version: 1.0
From: sender@example.com
Subject: Invoice
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: text/plain

See attached invoice.

--boundary
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.exe"

fake_content
--boundary--"""

        result = detector.analyze_email(email, is_file=False)

        # Check if dangerous attachment is detected
        dangerous_attachments = [a for a in result.attachment_analyses if a.is_executable]
        assert len(dangerous_attachments) > 0


class TestReportGeneration:
    """Test report generation functionality."""

    @pytest.fixture
    def detector(self):
        return PhishingDetector()

    @pytest.fixture
    def sample_result(self, detector):
        email = """From: attacker@fake.com
Subject: Test Phishing

Urgent! Click here: http://malicious.tk/steal"""

        return detector.analyze_email(email, is_file=False)

    def test_generate_text_report(self, sample_result):
        """Test text report generation."""
        reporter = ReportGenerator()
        report = reporter.generate_text_report(sample_result)

        assert 'PHISHING EMAIL ANALYSIS REPORT' in report
        assert 'VERDICT' in report
        assert 'Risk Level' in report
        assert 'RECOMMENDATIONS' in report

    def test_generate_json_report(self, sample_result):
        """Test JSON report generation."""
        import json

        reporter = ReportGenerator()
        report = reporter.generate_json_report(sample_result)

        # Should be valid JSON
        data = json.loads(report)
        assert 'verdict' in data
        assert 'sender' in data
        assert 'headers' in data
        assert 'content' in data
        assert 'recommendations' in data


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def detector(self):
        return PhishingDetector()

    def test_empty_email(self, detector):
        """Test handling of empty email."""
        result = detector.analyze_email("", is_file=False)
        assert result is not None
        assert result.risk_score >= 0

    def test_minimal_email(self, detector):
        """Test handling of minimal email."""
        email = "Subject: Test"
        result = detector.analyze_email(email, is_file=False)
        assert result is not None

    def test_unicode_content(self, detector):
        """Test handling of Unicode content."""
        email = """From: sender@example.com
Subject: Test with Unicode

Hello! Here's some Unicode: cafe, resume, Beijing
Emojis work too: Check this link"""

        result = detector.analyze_email(email, is_file=False)
        assert result is not None

    def test_malformed_url(self, detector):
        """Test handling of malformed URLs."""
        email = """From: sender@example.com
Subject: Bad URLs

Check: http://
And: https://
And: www."""

        result = detector.analyze_email(email, is_file=False)
        assert result is not None


class TestRiskLevels:
    """Test risk level classification."""

    @pytest.fixture
    def detector(self):
        return PhishingDetector()

    def test_risk_level_low(self, detector):
        """Test LOW risk classification."""
        email = """From: notifications@github.com
Subject: New star on your repository

Someone starred your repo."""

        result = detector.analyze_email(email, is_file=False)
        # This should be low or medium risk
        assert result.risk_level in ['LOW', 'MEDIUM']

    def test_risk_level_critical(self, detector):
        """Test CRITICAL risk classification."""
        email = """From: "Bank Security" <alert@bank-secure.tk>
Subject: URGENT: Your account is SUSPENDED!!!

Your account has been SUSPENDED due to suspicious activity!!!
You MUST verify IMMEDIATELY or face legal action!!!

Click NOW: http://192.168.1.1/verify?user=victim

Provide your:
- Social security number
- Bank account and routing number
- Credit card with CVV
- Password

This is your FINAL WARNING!!!
ACT NOW!!!"""

        result = detector.analyze_email(email, is_file=False)
        assert result.is_phishing is True
        # Should be high or critical
        assert result.risk_level in ['HIGH', 'CRITICAL']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
