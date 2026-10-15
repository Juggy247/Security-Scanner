"""
Unit Tests for Security Scanner
================================
Tests individual functions in isolation.
Most tests do NOT require network or MongoDB.
MongoDB-dependent tests use mocking.

Run with:
    pytest tests/test_units.py -v
    pytest tests/test_units.py -v --tb=short   (shorter error messages)
"""

import pytest
from unittest.mock import patch, MagicMock


# ============================================================
# DOMAIN LENGTH TESTS
# ============================================================

class TestDomainLength:
    """
    Tests for check_domain_length()
    Boundary testing: short, medium, long, very long domains
    """

    def setup_method(self):
        from scanner.domain_checks import check_domain_length
        self.check = check_domain_length

    def test_short_domain_is_safe(self):
        """Short domains like 'google.com' should be low risk"""
        result = self.check('google.com')
        assert result['is_suspicious'] == False
        assert result['risk_level'] == 'low'

    def test_medium_domain_is_not_suspicious(self):
        """Medium length domains should not be flagged"""
        result = self.check('myonlinebanking.com')
        assert result['is_suspicious'] == False

    def test_long_domain_is_suspicious(self):
        """Domains over 30 chars (without TLD) should be flagged"""
        result = self.check('secure-paypal-login-verify-account.com')
        assert result['is_suspicious'] == True
        assert result['risk_level'] in ('high', 'very_high')

    def test_very_long_domain_is_very_high_risk(self):
        """Domains over 40 chars should be very high risk"""
        result = self.check('this-is-an-extremely-long-domain-name-for-phishing.com')
        assert result['is_suspicious'] == True
        assert result['risk_level'] == 'very_high'

    def test_length_excludes_tld(self):
        """Length calculation should exclude the TLD"""
        result = self.check('google.com')
        assert result['length'] == len('google')

    def test_length_excludes_tld_with_subdomain(self):
        """Length calculation should exclude TLD but include subdomain"""
        result = self.check('www.google.com')
        assert result['length'] == len('www.google')

    def test_returns_correct_keys(self):
        """Result should always contain expected keys"""
        result = self.check('example.com')
        assert 'length' in result
        assert 'full_domain_length' in result
        assert 'is_suspicious' in result
        assert 'risk_level' in result


# ============================================================
# HOMOGRAPH ATTACK TESTS
# ============================================================

class TestHomographAttack:
    """
    Tests for check_homograph_attack()
    Detects lookalike characters used in phishing
    """

    def setup_method(self):
        from scanner.domain_checks import check_homograph_attack
        self.check = check_homograph_attack

    def test_clean_domain_not_suspicious(self):
        """Normal domain should not be flagged"""
        result = self.check('google.com')
        assert result['is_suspicious'] == False
        assert result['patterns_found'] == []

    def test_zero_looks_like_o(self):
        """'0' looks like 'o' — common typosquatting"""
        result = self.check('amaz0n.com')
        assert result['is_suspicious'] == True
        assert any('0' in p for p in result['patterns_found'])

    def test_rn_looks_like_m(self):
        """'rn' looks like 'm' — classic homograph"""
        result = self.check('payrnent.com')
        assert result['is_suspicious'] == True
        assert any('rn' in p for p in result['patterns_found'])

    def test_vv_looks_like_w(self):
        """'vv' looks like 'w'"""
        result = self.check('ttvvitter.com')
        assert result['is_suspicious'] == True
        assert any('vv' in p for p in result['patterns_found'])

    def test_one_looks_like_l(self):
        """'1' looks like 'l'"""
        result = self.check('app1e.com')
        assert result['is_suspicious'] == True
        assert any('1' in p for p in result['patterns_found'])

    def test_mixed_cyrillic_latin(self):
        """Mixed Cyrillic and Latin characters are suspicious"""
        result = self.check('gооgle.com')  # Cyrillic 'о' instead of Latin 'o'
        assert result['is_suspicious'] == True
        assert any('Cyrillic' in p for p in result['patterns_found'])

    def test_multiple_patterns_detected(self):
        """Multiple homograph patterns should all be reported"""
        result = self.check('amaz0n-1ogin.com')  # Both '0' and '1'
        assert result['is_suspicious'] == True
        assert len(result['patterns_found']) >= 2

    def test_returns_correct_keys(self):
        """Result should always contain expected keys"""
        result = self.check('example.com')
        assert 'is_suspicious' in result
        assert 'patterns_found' in result
        assert 'domain' in result


# ============================================================
# SUBDOMAIN DEPTH TESTS
# ============================================================

class TestSubdomainDepth:
    """
    Tests for check_subdomain_depth()
    Deep subdomain nesting is a common phishing pattern
    """

    def setup_method(self):
        from scanner.domain_checks import check_subdomain_depth
        self.check = check_subdomain_depth

    def test_simple_domain_not_suspicious(self):
        """Simple domain with no subdomains should be fine"""
        result = self.check('google.com')
        assert result['depth'] == 0
        assert result['is_suspicious'] == False

    def test_www_not_suspicious(self):
        """www subdomain is depth 1 — should not be suspicious"""
        result = self.check('www.google.com')
        assert result['depth'] == 1
        assert result['is_suspicious'] == False

    def test_two_levels_not_suspicious(self):
        """Two subdomain levels should not be suspicious"""
        result = self.check('mail.accounts.google.com')
        assert result['depth'] == 2
        assert result['is_suspicious'] == False

    def test_three_levels_is_suspicious(self):
        """Three or more subdomain levels should be flagged"""
        result = self.check('login.secure.paypal.verify.com')
        assert result['depth'] == 3
        assert result['is_suspicious'] == True

    def test_four_levels_is_suspicious(self):
        """Four subdomain levels — definitely suspicious"""
        result = self.check('a.b.c.d.example.com')
        assert result['depth'] == 4
        assert result['is_suspicious'] == True

    def test_parts_are_correct(self):
        """Parts list should contain all domain components"""
        result = self.check('login.secure.paypal.com')
        assert 'login' in result['parts']
        assert 'secure' in result['parts']
        assert 'paypal' in result['parts']

    def test_returns_correct_keys(self):
        """Result should always contain expected keys"""
        result = self.check('example.com')
        assert 'depth' in result
        assert 'parts' in result
        assert 'is_suspicious' in result
        assert 'full_domain' in result


# ============================================================
# SUSPICIOUS TLD TESTS
# ============================================================

class TestSuspiciousTLD:
    """
    Tests for check_suspicious_tld()
    Uses MongoDB — mocked for isolation
    """

    def setup_method(self):
        from scanner.domain_checks import check_suspicious_tld
        self.check = check_suspicious_tld

    @patch('scanner.domain_checks.get_db_config')
    def test_suspicious_tld_flagged(self, mock_db):
        """Known suspicious TLDs should be flagged"""
        mock_instance = MagicMock()
        mock_instance.get_suspicious_tlds.return_value = ['tk', 'ml', 'cf', 'xyz']
        mock_instance.get_tld_details.return_value = {
            'reason': 'Free TLD commonly used in phishing',
            'risk_level': 'high'
        }
        mock_db.return_value = mock_instance

        result = self.check('paypal-login.tk')
        assert result['is_suspicious'] == True
        assert result['tld'] == 'tk'

    @patch('scanner.domain_checks.get_db_config')
    def test_safe_tld_not_flagged(self, mock_db):
        """Common TLDs like .com should not be flagged"""
        mock_instance = MagicMock()
        mock_instance.get_suspicious_tlds.return_value = ['tk', 'ml', 'cf']
        mock_db.return_value = mock_instance

        result = self.check('google.com')
        assert result['is_suspicious'] == False
        assert result['tld'] == 'com'

    @patch('scanner.domain_checks.get_db_config')
    def test_tld_extracted_correctly(self, mock_db):
        """TLD should be correctly extracted from domain"""
        mock_instance = MagicMock()
        mock_instance.get_suspicious_tlds.return_value = ['xyz']
        mock_db.return_value = mock_instance

        result = self.check('example.xyz')
        assert result['tld'] == 'xyz'

    @patch('scanner.domain_checks.get_db_config')
    def test_db_failure_returns_safe(self, mock_db):
        """If MongoDB fails, should fail safely and not crash"""
        mock_db.side_effect = Exception("MongoDB connection failed")

        result = self.check('example.tk')
        assert 'error' in result
        assert result['is_suspicious'] == False  # fail safe


# ============================================================
# BRAND IMPERSONATION TESTS
# ============================================================

class TestBrandImpersonation:
    """
    Tests for check_brand_impersonation()
    Detects domains pretending to be known brands
    Uses MongoDB — mocked for isolation
    """

    def setup_method(self):
        from scanner.domain_checks import check_brand_impersonation
        self.check = check_brand_impersonation

    @patch('scanner.domain_checks.get_db_config')
    def test_brand_with_suspicious_keyword_flagged(self, mock_db):
        """Brand name + suspicious keyword = impersonation"""
        mock_instance = MagicMock()
        mock_instance.get_brands.return_value = ['paypal', 'google', 'microsoft']
        mock_instance.get_suspicious_keywords.return_value = ['verify', 'secure', 'login', 'account']
        mock_db.return_value = mock_instance

        result = self.check('paypal-verify-account.com')
        assert result['potential_impersonation'] == True
        assert result['suspected_brand'] == 'paypal'
        assert 'verify' in result['suspicious_keywords']

    @patch('scanner.domain_checks.get_db_config')
    def test_brand_without_keyword_not_flagged(self, mock_db):
        """Brand name alone without suspicious keyword should not be flagged"""
        mock_instance = MagicMock()
        mock_instance.get_brands.return_value = ['paypal', 'google']
        mock_instance.get_suspicious_keywords.return_value = ['verify', 'secure', 'login']
        mock_db.return_value = mock_instance

        result = self.check('paypal.com')
        assert result['potential_impersonation'] == False

    @patch('scanner.domain_checks.get_db_config')
    def test_brand_detected_in_subdomain(self, mock_db):
        """Brand name anywhere in domain should be detected"""
        mock_instance = MagicMock()
        mock_instance.get_brands.return_value = ['paypal']
        mock_instance.get_suspicious_keywords.return_value = ['verify', 'secure', 'login']
        mock_db.return_value = mock_instance

        result = self.check('login.secure.paypal.verify.com')
        assert result['potential_impersonation'] == True
        assert result['suspected_brand'] == 'paypal'

    @patch('scanner.domain_checks.get_db_config')
    def test_unknown_brand_not_flagged(self, mock_db):
        """Domain with no known brand should not be flagged"""
        mock_instance = MagicMock()
        mock_instance.get_brands.return_value = ['paypal', 'google']
        mock_instance.get_suspicious_keywords.return_value = ['verify', 'secure']
        mock_db.return_value = mock_instance

        result = self.check('totally-random-site.com')
        assert result['potential_impersonation'] == False

    @patch('scanner.domain_checks.get_db_config')
    def test_multiple_keywords_all_reported(self, mock_db):
        """All matching suspicious keywords should be reported"""
        mock_instance = MagicMock()
        mock_instance.get_brands.return_value = ['microsoft']
        mock_instance.get_suspicious_keywords.return_value = ['verify', 'secure', 'login']
        mock_db.return_value = mock_instance

        result = self.check('microsoft-secure-login-verify.com')
        assert len(result['suspicious_keywords']) == 3

    @patch('scanner.domain_checks.get_db_config')
    def test_db_failure_returns_safe(self, mock_db):
        """If MongoDB fails, should fail safely"""
        mock_db.side_effect = Exception("MongoDB connection failed")

        result = self.check('paypal-verify.com')
        assert result['potential_impersonation'] == False
        assert 'error' in result


# ============================================================
# SECURITY HEADERS TESTS
# ============================================================

class TestSecurityHeaders:
    """
    Tests for check_headers()
    Checks which security headers are present or missing
    """

    def setup_method(self):
        from scanner.security import check_headers
        self.check = check_headers

    def _make_response(self, headers: dict):
        """Helper to create a mock response with given headers"""
        mock_response = MagicMock()
        mock_response.headers = headers
        return mock_response

    def test_all_headers_present(self):
        """When all security headers are present, missing list should be empty"""
        response = self._make_response({
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'self'",
            'Referrer-Policy': 'no-referrer'
        })
        result = self.check(response)
        assert result['missing'] == []
        assert len(result['present']) == 5

    def test_all_headers_missing(self):
        """When no security headers are present, all should be in missing list"""
        response = self._make_response({})
        result = self.check(response)
        assert len(result['missing']) == 5
        assert result['present'] == []

    def test_some_headers_missing(self):
        """Only present headers should be in present list"""
        response = self._make_response({
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Frame-Options': 'DENY',
        })
        result = self.check(response)
        assert len(result['present']) == 2
        assert len(result['missing']) == 3
        assert 'Content-Security-Policy' in result['missing']

    def test_returns_correct_keys(self):
        """Result should always contain present and missing keys"""
        response = self._make_response({})
        result = self.check(response)
        assert 'present' in result
        assert 'missing' in result


# ============================================================
# HTTPS CHECK TESTS
# ============================================================

class TestHTTPS:
    """
    Tests for check_https_final()
    Checks if site enforces HTTPS
    """

    def setup_method(self):
        from scanner.security import check_https_final
        self.check = check_https_final

    def _make_response(self, final_url: str):
        mock_response = MagicMock()
        mock_response.url = final_url
        return mock_response

    def test_https_url_is_enforced(self):
        """HTTPS URL should be marked as enforced"""
        response = self._make_response('https://google.com')
        result = self.check('https://google.com', response)
        assert result['https_enforced'] == True

    def test_http_url_not_enforced(self):
        """HTTP URL that stays HTTP should not be enforced"""
        response = self._make_response('http://example.com')
        result = self.check('http://example.com', response)
        assert result['https_enforced'] == False

    def test_http_redirected_to_https(self):
        """HTTP URL that redirects to HTTPS should be detected"""
        response = self._make_response('https://example.com')
        result = self.check('http://example.com', response)
        assert result['https_enforced'] == True
        assert result['redirected_to_https'] == True

    def test_https_to_https_no_redirect(self):
        """HTTPS URL that stays HTTPS should not be marked as redirected"""
        response = self._make_response('https://example.com')
        result = self.check('https://example.com', response)
        assert result['redirected_to_https'] == False


# ============================================================
# SSRF PROTECTION TESTS
# ============================================================

class TestSSRFProtection:
    """
    Tests for is_safe_url() in app.py
    Ensures scanner cannot be used to scan internal/private resources
    """

    def setup_method(self):
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from app import is_safe_url
        self.check = is_safe_url

    def test_valid_https_url_allowed(self):
        """Normal HTTPS URLs should be allowed"""
        safe, reason = self.check('https://google.com')
        assert safe == True
        assert reason == ""

    def test_valid_http_url_allowed(self):
        """Normal HTTP URLs should be allowed"""
        safe, reason = self.check('http://example.com')
        assert safe == True

    def test_localhost_blocked(self):
        """localhost should be blocked"""
        safe, reason = self.check('http://localhost')
        assert safe == False
        assert 'localhost' in reason.lower() or 'not allowed' in reason.lower()

    def test_127_0_0_1_blocked(self):
        """Loopback IP should be blocked"""
        safe, reason = self.check('http://127.0.0.1')
        assert safe == False

    def test_private_ip_192_blocked(self):
        """Private IP range 192.168.x.x should be blocked"""
        safe, reason = self.check('http://192.168.1.1')
        assert safe == False

    def test_private_ip_10_blocked(self):
        """Private IP range 10.x.x.x should be blocked"""
        safe, reason = self.check('http://10.0.0.1')
        assert safe == False

    def test_private_ip_172_blocked(self):
        """Private IP range 172.16.x.x should be blocked"""
        safe, reason = self.check('http://172.16.0.1')
        assert safe == False

    def test_ftp_scheme_blocked(self):
        """Non HTTP/HTTPS schemes should be blocked"""
        safe, reason = self.check('ftp://example.com')
        assert safe == False
        assert 'http' in reason.lower()

    def test_file_scheme_blocked(self):
        """file:// scheme should be blocked — path traversal risk"""
        safe, reason = self.check('file:///etc/passwd')
        assert safe == False

    def test_ipv6_loopback_blocked(self):
        """IPv6 loopback ::1 should be blocked"""
        safe, reason = self.check('http://[::1]')
        assert safe == False

    def test_empty_hostname_blocked(self):
        """URL with no hostname should be blocked"""
        safe, reason = self.check('http://')
        assert safe == False


# ============================================================
# DOMAIN IN TITLE TESTS
# ============================================================

class TestDomainInTitle:
    """
    Tests for check_domain_in_title()
    Checks if the domain name appears in the page title
    """

    def setup_method(self):
        from scanner.domain_checks import check_domain_in_title
        self.check = check_domain_in_title

    def test_domain_found_in_title(self):
        """Domain name in title should return True"""
        result = self.check('google.com', 'Google - Search Engine')
        assert result['domain_in_title'] == True

    def test_domain_not_in_title(self):
        """Missing domain in title should return False"""
        result = self.check('paypal-verify.com', 'Welcome to PayPal')
        assert result['domain_in_title'] == False

    def test_empty_title_returns_false(self):
        """Empty title should return False with reason"""
        result = self.check('google.com', '')
        assert result['domain_in_title'] == False
        assert 'reason' in result

    def test_none_title_returns_false(self):
        """None title should be handled gracefully"""
        result = self.check('google.com', None)
        assert result['domain_in_title'] == False

    def test_case_insensitive_match(self):
        """Match should be case insensitive"""
        result = self.check('google.com', 'GOOGLE Search')
        assert result['domain_in_title'] == True

    def test_www_subdomain_ignored(self):
        """www prefix should be ignored when checking title"""
        result = self.check('www.google.com', 'Google Search')
        assert result['domain_in_title'] == True


# ============================================================
# LANGUAGE DETECTION TESTS
# ============================================================

class TestLanguageDetection:
    """Tests for dataset_collector.detect_language()."""

    def test_detects_english_with_enough_text(self):
        from dataset_collector import detect_language

        text = (
            "This page explains how to secure a website and protect user accounts "
            "from phishing attacks using modern browser security tools and best practices."
        )

        result = detect_language(text)
        assert result == "en"

    def test_returns_none_for_short_text(self):
        from dataset_collector import detect_language

        result = detect_language("Hello world")
        assert result is None

    def test_returns_none_when_langdetect_cannot_decide(self):
        from dataset_collector import detect_language

        result = detect_language("123 456 789 000")
        assert result is None


class TestEmbeddingComparison:
    """Tests for dataset_collector.compare_page_to_references()."""

    def test_compare_returns_verdict_with_valid_reference_sets(self):
        from dataset_collector import compare_page_to_references

        result = compare_page_to_references(
            "Your account has been suspended. Verify your identity immediately to restore access.",
            ["This is a trusted banking website with account login and secure access to customer services."],
            ["Urgent security alert: login required to prevent account closure and fraudulent activity."]
        )

        assert set(result.keys()) >= {"real_score", "fake_score", "verdict", "confidence"}
        assert result["verdict"] in {"real", "fake"}
        assert result["confidence"] >= 0.0