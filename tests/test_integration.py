"""
Integration Tests for Security Scanner
=======================================
Tests the full scan flow with real network calls and real MongoDB.
These tests are SLOWER than unit tests because they:
- Make real HTTP requests to websites
- Query real MongoDB database
- Test the entire system working together

Run with:
    pytest tests/test_integration.py -v
    pytest tests/test_integration.py -v --timeout=60
    pytest tests/test_integration.py -v -s          (show print statements)

NOTE: These tests require:
    - MongoDB running on localhost:27017
    - Internet connection
    - scanner database seeded with TLDs, brands, keywords
"""

import pytest
import time
from scanner.core import SecurityScanner
from scanner.config import MongoDbConfig

# Fixtures are reusable setup code that pytest injects into tests

@pytest.fixture(scope='module')
def scanner():
    """
    Create one SecurityScanner instance shared across all tests.
    scope='module' means it's created once per file, not per test.
    This saves time — we don't reconnect MongoDB for every test.
    """
    return SecurityScanner(bypass_robots=True)


@pytest.fixture(scope='module')
def db():
    """
    Create one MongoDB connection shared across all tests.
    Automatically closes when all tests in module are done.
    """
    db_instance = MongoDbConfig()
    yield db_instance      # tests run here
    db_instance.close()    # cleanup after all tests



# helper Function

def get_issues_flat(verdict: dict) -> list:
    """Flatten all issues from all severity levels into one list"""
    all_issues = []
    for severity in ['critical', 'high', 'medium', 'low']:
        all_issues.extend(verdict['issues'][severity])
    return all_issues

def get_issue_types(verdict: dict) -> list:
    """Get just the issue type names as a flat list"""
    return [i['type'] for i in get_issues_flat(verdict)]



# LEGITIMATE SITES
# should return SAFE or SAFE (with minor issues)


class TestLegitimateSites:
    """
    Tests against well-known legitimate websites.
    These should NOT be flagged as suspicious.
    """

    @pytest.mark.timeout(30)
    def test_google_is_safe(self, scanner):
        """Google should be SAFE"""
        report = scanner.scan('https://www.google.com')
        verdict = report.get_verdict()

        assert 'SAFE' in verdict['verdict']
        assert verdict['issue_counts']['critical'] == 0
        assert verdict['issue_counts']['high'] == 0

    @pytest.mark.timeout(30)
    def test_github_is_safe(self, scanner):
        """GitHub should be SAFE with no critical or high issues"""
        report = scanner.scan('https://github.com')
        verdict = report.get_verdict()

        assert 'SAFE' in verdict['verdict']
        assert verdict['issue_counts']['critical'] == 0
        assert verdict['issue_counts']['high'] == 0

    @pytest.mark.timeout(30)
    def test_amazon_is_safe(self, scanner):
        """Amazon should be SAFE"""
        report = scanner.scan('https://www.amazon.com')
        verdict = report.get_verdict()

        assert 'SAFE' in verdict['verdict']
        assert verdict['issue_counts']['critical'] == 0
        assert verdict['issue_counts']['high'] == 0

    @pytest.mark.timeout(30)
    def test_legitimate_site_has_valid_ssl(self, scanner):
        """Legitimate sites should have valid SSL"""
        report = scanner.scan('https://github.com')

        assert report.ssl is not None
        assert report.ssl.get('valid') == True

    @pytest.mark.timeout(30)
    def test_legitimate_site_enforces_https(self, scanner):
        """Legitimate sites should enforce HTTPS"""
        report = scanner.scan('https://www.google.com')

        assert report.https is not None
        assert report.https.get('https_enforced') == True

    @pytest.mark.timeout(30)
    def test_legitimate_site_scan_succeeds(self, scanner):
        """Scan of legitimate site should succeed"""
        report = scanner.scan('https://github.com')

        assert report.success == True
        assert report.error is None


# PHISHING PATTERN DETECTION
# should return SUSPICIOUS

class TestPhishingDetection:
    """
    Tests against known phishing URL patterns.
    These are offline domains — scanner should detect via domain checks.
    """

    @pytest.mark.timeout(30)
    def test_paypal_phishing_is_suspicious(self, scanner):
        """Paypal phishing domain should be SUSPICIOUS"""
        report = scanner.scan('http://paypal-secure-verify-account.ml')
        verdict = report.get_verdict()

        assert verdict['verdict'] == 'SUSPICIOUS'

    @pytest.mark.timeout(30)
    def test_paypal_phishing_detects_brand(self, scanner):
        """Paypal phishing domain should trigger brand impersonation"""
        report = scanner.scan('http://paypal-secure-verify-account.ml')
        verdict = report.get_verdict()
        issue_types = get_issue_types(verdict)

        assert 'Potential Brand Impersonation' in issue_types

    @pytest.mark.timeout(30)
    def test_paypal_phishing_detects_suspicious_tld(self, scanner):
        """Paypal phishing domain should trigger suspicious TLD"""
        report = scanner.scan('http://paypal-secure-verify-account.ml')
        verdict = report.get_verdict()
        issue_types = get_issue_types(verdict)

        assert 'Suspicious TLD' in issue_types

    @pytest.mark.timeout(30)
    def test_microsoft_phishing_is_suspicious(self, scanner):
        """Microsoft phishing domain should be SUSPICIOUS"""
        report = scanner.scan('http://microsoft-login-verify.tk')
        verdict = report.get_verdict()

        assert verdict['verdict'] == 'SUSPICIOUS'

    @pytest.mark.timeout(30)
    def test_microsoft_phishing_detects_brand(self, scanner):
        """Microsoft phishing domain should trigger brand impersonation"""
        report = scanner.scan('http://microsoft-login-verify.tk')
        verdict = report.get_verdict()
        issue_types = get_issue_types(verdict)

        assert 'Potential Brand Impersonation' in issue_types

    @pytest.mark.timeout(30)
    def test_phishing_detected_when_offline(self, scanner):
        """Scanner should detect phishing even when site is offline"""
        report = scanner.scan('http://paypal-secure-verify-account.ml')
        verdict = report.get_verdict()

        # Site is offline but should still be detected
        assert report.success == False
        assert verdict['verdict'] == 'SUSPICIOUS'
        assert verdict['total_issues'] > 0


# HOMOGRAPH ATTACK DETECTION

class TestHomographDetection:
    """
    Tests for detecting domains using lookalike characters.
    """

    @pytest.mark.timeout(30)
    def test_typosquat_zero_for_o_detected(self, scanner):
        """Domain using '0' instead of 'o' should be flagged"""
        report = scanner.scan('http://amaz0n-security-alert.cf')
        verdict = report.get_verdict()
        issue_types = get_issue_types(verdict)

        assert 'Homograph Attack' in issue_types

    @pytest.mark.timeout(30)
    def test_typosquat_is_suspicious(self, scanner):
        """Typosquat domain should be SUSPICIOUS overall"""
        report = scanner.scan('http://amaz0n-security-alert.cf')
        verdict = report.get_verdict()

        assert verdict['verdict'] == 'SUSPICIOUS'

    @pytest.mark.timeout(30)
    def test_homograph_plus_suspicious_tld(self, scanner):
        """Homograph attack combined with suspicious TLD should both be detected"""
        report = scanner.scan('http://amaz0n-security-alert.cf')
        verdict = report.get_verdict()
        issue_types = get_issue_types(verdict)

        assert 'Homograph Attack' in issue_types
        assert 'Suspicious TLD' in issue_types

# HTTP ONLY DETECTION

class TestHTTPOnly:
    """
    Tests for sites that don't use HTTPS.
    HTTP-only sites should be flagged as insecure.
    """

    @pytest.mark.timeout(30)
    def test_http_site_flagged(self, scanner):
        """HTTP-only site should have No HTTPS issue"""
        report = scanner.scan('http://example.com')
        verdict = report.get_verdict()
        issue_types = get_issue_types(verdict)

        assert 'No HTTPS' in issue_types

    @pytest.mark.timeout(30)
    def test_http_site_is_suspicious(self, scanner):
        """HTTP-only site should be SUSPICIOUS (critical issue)"""
        report = scanner.scan('http://example.com')
        verdict = report.get_verdict()

        assert verdict['issue_counts']['critical'] > 0
        assert verdict['verdict'] == 'SUSPICIOUS'

    @pytest.mark.timeout(30)
    def test_https_site_not_flagged_for_http(self, scanner):
        """HTTPS site should not have No HTTPS issue"""
        report = scanner.scan('https://github.com')
        verdict = report.get_verdict()
        issue_types = get_issue_types(verdict)

        assert 'No HTTPS' not in issue_types


# DEEP SUBDOMAIN DETECTION

class TestDeepSubdomain:
    """
    Tests for detecting suspicious subdomain nesting.
    """

    @pytest.mark.timeout(30)
    def test_deep_subdomain_flagged(self, scanner):
        """Domain with 3+ subdomain levels should be flagged"""
        report = scanner.scan('https://login.secure.paypal.verify.com')
        verdict = report.get_verdict()
        issue_types = get_issue_types(verdict)

        assert 'Deep Subdomain Nesting' in issue_types

    @pytest.mark.timeout(30)
    def test_deep_subdomain_with_brand_is_suspicious(self, scanner):
        """Deep subdomain + brand impersonation should be SUSPICIOUS"""
        report = scanner.scan('https://login.secure.paypal.verify.com')
        verdict = report.get_verdict()

        assert verdict['verdict'] == 'SUSPICIOUS'

    @pytest.mark.timeout(30)
    def test_deep_subdomain_detects_paypal(self, scanner):
        """Brand impersonation should detect paypal in deep subdomain"""
        report = scanner.scan('https://login.secure.paypal.verify.com')
        verdict = report.get_verdict()

        # Find brand impersonation issue
        all_issues = get_issues_flat(verdict)
        brand_issues = [i for i in all_issues if i['type'] == 'Potential Brand Impersonation']

        assert len(brand_issues) > 0
        assert 'paypal' in brand_issues[0]['description'].lower()



# BLACKLIST DETECTION

class TestBlacklistDetection:
    """
    Tests for MongoDB blacklist lookup.
    Adds a test domain to blacklist, scans it, then cleans up.
    """

    @pytest.fixture(autouse=True)
    def setup_blacklist(self, db):
        """Add test domain before test, remove after"""
        test_domain = 'definitely-evil-test-domain.com'
        db.add_blacklisted_domain(
            domain=test_domain,
            source='test',
            reason='Integration test domain'
        )
        yield test_domain
        # Cleanup after test
        db.delete_blacklisted_domain(test_domain)

    @pytest.mark.timeout(30)
    def test_blacklisted_domain_is_suspicious(self, scanner, setup_blacklist):
        """Blacklisted domain should be SUSPICIOUS"""
        report = scanner.scan(f'http://{setup_blacklist}')
        verdict = report.get_verdict()

        assert verdict['verdict'] == 'SUSPICIOUS'

    @pytest.mark.timeout(30)
    def test_blacklisted_domain_has_critical_issue(self, scanner, setup_blacklist):
        """Blacklisted domain should have a CRITICAL issue"""
        report = scanner.scan(f'http://{setup_blacklist}')
        verdict = report.get_verdict()

        assert verdict['issue_counts']['critical'] > 0

    @pytest.mark.timeout(30)
    def test_blacklist_issue_type_correct(self, scanner, setup_blacklist):
        """Blacklisted domain should show 'Blacklisted Domain' issue type"""
        report = scanner.scan(f'http://{setup_blacklist}')
        verdict = report.get_verdict()
        issue_types = get_issue_types(verdict)

        assert 'Blacklisted Domain' in issue_types

# OFFLINE SITE HANDLING

class TestOfflineSites:
    """
    Tests for how scanner handles unreachable sites.
    Scanner should still run domain checks even when site is offline.
    """

    @pytest.mark.timeout(30)
    def test_offline_site_still_returns_verdict(self, scanner):
        """Offline site should still return a verdict"""
        report = scanner.scan('http://thisdomaindoesnotexist99999abc.com')
        verdict = report.get_verdict()

        assert verdict is not None
        assert 'verdict' in verdict

    @pytest.mark.timeout(30)
    def test_offline_site_runs_domain_checks(self, scanner):
        """Domain checks should run even when site is offline"""
        report = scanner.scan('http://thisdomaindoesnotexist99999abc.com')

        # These domain checks should have run
        assert report.domain_length is not None
        assert report.subdomain_depth is not None
        assert report.homograph is not None

    @pytest.mark.timeout(30)
    def test_offline_suspicious_domain_detected(self, scanner):
        """Offline phishing domain should still be detected"""
        report = scanner.scan('http://paypal-secure-verify-account.ml')

        assert report.success == False  # offline
        verdict = report.get_verdict()
        assert verdict['verdict'] == 'SUSPICIOUS'  # but still detected

    @pytest.mark.timeout(30)
    def test_offline_site_has_offline_issue(self, scanner):
        """Offline site should have Website Offline issue"""
        report = scanner.scan('http://thisdomaindoesnotexist99999abc.com')
        verdict = report.get_verdict()
        issue_types = get_issue_types(verdict)

        assert 'Website Offline or Unreachable' in issue_types

# SCAN REPORT STRUCTURE
# Tests that ScanReport always returns consistent data structure

class TestScanReportStructure:
    """
    Tests that ScanReport always returns consistent,
    well-formed data regardless of what URL is scanned.
    Important for frontend — if keys are missing, UI breaks.
    """

    @pytest.mark.timeout(30)
    def test_verdict_always_has_required_keys(self, scanner):
        """Verdict dict should always contain all required keys"""
        report = scanner.scan('https://github.com')
        verdict = report.get_verdict()

        required_keys = [
            'verdict',
            'verdict_emoji',
            'verdict_message',
            'total_issues',
            'issues',
            'issue_counts'
        ]
        for key in required_keys:
            assert key in verdict, f"Missing key: {key}"

    @pytest.mark.timeout(30)
    def test_issue_counts_always_has_all_severities(self, scanner):
        """issue_counts should always have all four severity levels"""
        report = scanner.scan('https://github.com')
        verdict = report.get_verdict()

        assert 'critical' in verdict['issue_counts']
        assert 'high' in verdict['issue_counts']
        assert 'medium' in verdict['issue_counts']
        assert 'low' in verdict['issue_counts']

    @pytest.mark.timeout(30)
    def test_issues_always_has_all_severities(self, scanner):
        """issues dict should always have all four severity levels"""
        report = scanner.scan('https://github.com')
        verdict = report.get_verdict()

        assert 'critical' in verdict['issues']
        assert 'high' in verdict['issues']
        assert 'medium' in verdict['issues']
        assert 'low' in verdict['issues']

    @pytest.mark.timeout(30)
    def test_total_issues_matches_sum(self, scanner):
        """total_issues should equal sum of all severity counts"""
        report = scanner.scan('https://github.com')
        verdict = report.get_verdict()

        expected_total = sum(verdict['issue_counts'].values())
        assert verdict['total_issues'] == expected_total

    @pytest.mark.timeout(30)
    def test_scan_report_to_dict_has_all_keys(self, scanner):
        """to_dict() should always return all expected keys"""
        report = scanner.scan('https://github.com')
        data = report.to_dict()

        expected_keys = [
            'url', 'success', 'error', 'robots_allowed',
            'robots_bypassed', 'https', 'ssl', 'headers',
            'forms', 'title', 'domain_age', 'blacklist',
            'homograph', 'domain_in_title', 'form_redirects',
            'domain_length', 'suspicious_tld', 'subdomain_depth',
            'brand_impersonation'
        ]
        for key in expected_keys:
            assert key in data, f"Missing key in to_dict(): {key}"

    @pytest.mark.timeout(30)
    def test_verdict_is_valid_value(self, scanner):
        """Verdict should always be one of the expected values"""
        report = scanner.scan('https://github.com')
        verdict = report.get_verdict()

        valid_verdicts = [
            'SAFE',
            'SAFE (with minor issues)',
            'POTENTIALLY SUSPICIOUS',
            'SUSPICIOUS'
        ]
        assert verdict['verdict'] in valid_verdicts

    @pytest.mark.timeout(30)
    def test_invalid_url_handled_gracefully(self, scanner):
        """Invalid URL should return error without crashing"""
        report = scanner.scan('not-a-valid-url')

        assert report.success == False
        assert report.error is not None


# MONGODB CONNECTION

class TestMongoDBIntegration:
    """
    Tests that MongoDB is connected and has data.
    These verify the database layer works correctly.
    """

    def test_mongodb_is_connected(self, db):
        """MongoDB should be reachable"""
        # If fixture created successfully, MongoDB is connected
        assert db is not None

    def test_suspicious_tlds_exist(self, db):
        """Database should have suspicious TLDs seeded"""
        tlds = db.get_suspicious_tlds()
        assert len(tlds) > 0, "No TLDs in database — run seeding script"

    def test_brands_exist(self, db):
        """Database should have brands seeded"""
        brands = db.get_brands()
        assert len(brands) > 0, "No brands in database — run seeding script"

    def test_keywords_exist(self, db):
        """Database should have keywords seeded"""
        keywords = db.get_suspicious_keywords()
        assert len(keywords) > 0, "No keywords in database — run seeding script"

    def test_blacklist_check_returns_bool(self, db):
        """is_blacklisted should return a boolean"""
        result = db.is_blacklisted('google.com')
        assert isinstance(result, bool)

    def test_known_good_domain_not_blacklisted(self, db):
        """google.com should not be in blacklist"""
        result = db.is_blacklisted('google.com')
        assert result == False

    def test_add_and_delete_blacklist(self, db):
        """Should be able to add and remove from blacklist"""
        test_domain = 'test-integration-cleanup.com'

        # Add
        added = db.add_blacklisted_domain(test_domain, reason='test')
        assert added == True

        # Verify it's there
        assert db.is_blacklisted(test_domain) == True

        # Delete
        deleted = db.delete_blacklisted_domain(test_domain)
        assert deleted == True

        # Verify it's gone
        assert db.is_blacklisted(test_domain) == False