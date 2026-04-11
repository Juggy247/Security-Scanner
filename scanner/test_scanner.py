"""
Comprehensive test suite for the Security Scanner
Tests legitimate sites, malicious sites, and edge cases
"""

import sys
import time
from typing import List, Dict
from .core import SecurityScanner
from .domain_checks import close_db_connection

class TestCase:
    def __init__(self, url: str, expected_verdict: str, category: str, notes: str = ""):
        self.url = url
        self.expected_verdict = expected_verdict  # 'SAFE', 'POTENTIALLY SUSPICIOUS', 'SUSPICIOUS'
        self.category = category
        self.notes = notes

class ScannerTester:
    def __init__(self):
        self.scanner = SecurityScanner(bypass_robots=True)
        self.results = []
        
    def run_test(self, test_case: TestCase) -> Dict:
        """Run a single test case"""
        print(f"\n{'='*80}")
        print(f"🧪 Testing: {test_case.url}")
        print(f"   Category: {test_case.category}")
        print(f"   Expected: {test_case.expected_verdict}")
        if test_case.notes:
            print(f"   Notes: {test_case.notes}")
        print(f"{'='*80}\n")
        
        start_time = time.time()
        
        try:
            report = self.scanner.scan(test_case.url)
            verdict_data = report.get_verdict()
            
            elapsed = time.time() - start_time
            
            result = {
                'url': test_case.url,
                'category': test_case.category,
                'expected': test_case.expected_verdict,
                'actual': verdict_data['verdict'],
                'passed': self._check_verdict_match(test_case.expected_verdict, verdict_data['verdict']),
                'success': report.success,
                'elapsed_time': round(elapsed, 2),
                'total_issues': verdict_data['total_issues'],
                'issue_counts': verdict_data['issue_counts'],
                'verdict_message': verdict_data['verdict_message'],
                'error': report.error
            }
            
            self._print_result(result, verdict_data)
            
        except Exception as e:
            elapsed = time.time() - start_time
            result = {
                'url': test_case.url,
                'category': test_case.category,
                'expected': test_case.expected_verdict,
                'actual': 'ERROR',
                'passed': False,
                'success': False,
                'elapsed_time': round(elapsed, 2),
                'error': str(e)
            }
            print(f"❌ EXCEPTION: {str(e)}\n")
        
        self.results.append(result)
        return result
    
    def _check_verdict_match(self, expected: str, actual: str) -> bool:
        """Check if verdict matches expectation (with some flexibility)"""
        # Exact match
        if expected == actual:
            return True
        
        # Allow some flexibility for borderline cases
        if expected == 'POTENTIALLY SUSPICIOUS' and actual in ['SUSPICIOUS', 'SAFE (with minor issues)']:
            return True
        
        if expected == 'SAFE' and actual == 'SAFE (with minor issues)':
            return True
            
        return False
    
    def _print_result(self, result: Dict, verdict_data: Dict):
        """Print detailed result"""
        status = "✅ PASS" if result['passed'] else "❌ FAIL"
        
        print(f"\n{status}")
        print(f"Verdict: {result['actual']}")
        print(f"Message: {result['verdict_message']}")
        print(f"Time: {result['elapsed_time']}s")
        print(f"Total Issues: {result['total_issues']}")
        print(f"  Critical: {result['issue_counts']['critical']}")
        print(f"  High: {result['issue_counts']['high']}")
        print(f"  Medium: {result['issue_counts']['medium']}")
        print(f"  Low: {result['issue_counts']['low']}")
        
        # Print critical and high issues
        if verdict_data['issues']['critical']:
            print(f"\n🚨 Critical Issues:")
            for issue in verdict_data['issues']['critical']:
                print(f"  - {issue['type']}: {issue['description']}")
        
        if verdict_data['issues']['high']:
            print(f"\n⚠️  High Issues:")
            for issue in verdict_data['issues']['high']:
                print(f"  - {issue['type']}: {issue['description']}")
    
    def print_summary(self):
        """Print test summary"""
        print(f"\n\n{'='*80}")
        print("📊 TEST SUMMARY")
        print(f"{'='*80}\n")
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r['passed'])
        failed = total - passed
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed} ✅")
        print(f"Failed: {failed} ❌")
        print(f"Success Rate: {(passed/total*100):.1f}%\n")
        
        # Group by category
        categories = {}
        for result in self.results:
            cat = result['category']
            if cat not in categories:
                categories[cat] = {'passed': 0, 'failed': 0}
            
            if result['passed']:
                categories[cat]['passed'] += 1
            else:
                categories[cat]['failed'] += 1
        
        print("Results by Category:")
        for cat, counts in categories.items():
            total_cat = counts['passed'] + counts['failed']
            print(f"  {cat}: {counts['passed']}/{total_cat} passed")
        
        # Show failures
        if failed > 0:
            print(f"\n❌ Failed Tests:")
            for result in self.results:
                if not result['passed']:
                    print(f"  - {result['url']}")
                    print(f"    Expected: {result['expected']}, Got: {result['actual']}")
                    if result.get('error'):
                        print(f"    Error: {result['error']}")
        
        # Performance stats
        avg_time = sum(r['elapsed_time'] for r in self.results) / total
        max_time = max(r['elapsed_time'] for r in self.results)
        min_time = min(r['elapsed_time'] for r in self.results)
        
        print(f"\n⏱️  Performance:")
        print(f"  Average scan time: {avg_time:.2f}s")
        print(f"  Fastest: {min_time:.2f}s")
        print(f"  Slowest: {max_time:.2f}s")


def get_test_cases() -> List[TestCase]:
    """Define all test cases"""
    
    test_cases = [
        # ============================================
        # LEGITIMATE WEBSITES (Should be SAFE)
        # ============================================
        TestCase(
            url="https://www.google.com",
            expected_verdict="SAFE",
            category="Legitimate - Major Tech",
            notes="Large tech company, should have excellent security"
        ),
        TestCase(
            url="https://github.com",
            expected_verdict="SAFE",
            category="Legitimate - Major Tech",
            notes="Developer platform with strong security"
        ),
        TestCase(
            url="https://www.amazon.com",
            expected_verdict="SAFE",
            category="Legitimate - E-commerce",
            notes="Major e-commerce site"
        ),
        TestCase(
            url="https://www.wikipedia.org",
            expected_verdict="SAFE",
            category="Legitimate - Information",
            notes="Non-profit educational resource"
        ),
        TestCase(
            url="https://www.microsoft.com",
            expected_verdict="SAFE",
            category="Legitimate - Major Tech",
            notes="Major technology company"
        ),
        
        # ============================================
        # SUSPICIOUS/MALICIOUS WEBSITES
        # ============================================
        # Note: These are examples - some may not be active
        TestCase(
            url="http://totallylegitbank-login.tk",
            expected_verdict="SUSPICIOUS",
            category="Suspicious - Fake Banking",
            notes="Free TLD (.tk), HTTP only, suspicious banking keywords"
        ),
        TestCase(
            url="http://paypal-secure-verify-account.ml",
            expected_verdict="SUSPICIOUS",
            category="Suspicious - Phishing",
            notes="Brand impersonation, suspicious TLD, HTTP, suspicious keywords"
        ),
        TestCase(
            url="http://microsоft.com",
            expected_verdict="SUSPICIOUS",
            category="Suspicious - Homograph Attack",
            notes="Uses Cyrillic 'о' instead of Latin 'o' - homograph attack"
        ),
        TestCase(
            url="http://www.very-long-suspicious-domain-name-that-tries-to-look-legitimate.tk",
            expected_verdict="SUSPICIOUS",
            category="Suspicious - Long Domain",
            notes="Excessively long domain name, free TLD, HTTP"
        ),
        TestCase(
            url="http://amaz0n-security-alert.cf",
            expected_verdict="SUSPICIOUS",
            category="Suspicious - Typosquatting",
            notes="Zero instead of 'o', brand impersonation, suspicious TLD"
        ),
        
        # ============================================
        # EDGE CASES
        # ============================================
        TestCase(
            url="https://subdomain.another.level.example.com",
            expected_verdict="POTENTIALLY SUSPICIOUS",
            category="Edge Case - Deep Subdomain",
            notes="Deep subdomain nesting (may not resolve)"
        ),
        TestCase(
            url="https://localhost:8080",
            expected_verdict="SAFE",
            category="Edge Case - Localhost",
            notes="Local development server (will likely fail to connect)"
        ),
        TestCase(
            url="https://192.168.1.1",
            expected_verdict="SAFE",
            category="Edge Case - IP Address",
            notes="Private IP address (will likely timeout)"
        ),
        TestCase(
            url="http://example.com",
            expected_verdict="POTENTIALLY SUSPICIOUS",
            category="Edge Case - HTTP Only",
            notes="No HTTPS enforcement"
        ),
        TestCase(
            url="https://self-signed.badssl.com",
            expected_verdict="POTENTIALLY SUSPICIOUS",
            category="Edge Case - Invalid SSL",
            notes="Self-signed certificate (tests SSL handling)"
        ),
        TestCase(
            url="https://expired.badssl.com",
            expected_verdict="POTENTIALLY SUSPICIOUS",
            category="Edge Case - Expired SSL",
            notes="Expired SSL certificate"
        ),
        TestCase(
            url="https://nonexistentdomainthatdoesnotexist123456.com",
            expected_verdict="SAFE",
            category="Edge Case - Non-existent Domain",
            notes="Domain doesn't exist (DNS failure)"
        ),
        TestCase(
            url="https://httpstat.us/500",
            expected_verdict="SAFE",
            category="Edge Case - HTTP 500",
            notes="Server returns 500 error"
        ),
        TestCase(
            url="https://httpstat.us/404",
            expected_verdict="SAFE",
            category="Edge Case - HTTP 404",
            notes="Page not found"
        ),
        TestCase(
            url="https://example.com:8443",
            expected_verdict="SAFE",
            category="Edge Case - Custom Port",
            notes="Non-standard HTTPS port"
        ),
    ]
    
    return test_cases


def main():
    """Main test execution"""
    print("🔒 Security Scanner Test Suite")
    print("=" * 80)
    print("This will test the scanner against legitimate sites, malicious patterns,")
    print("and edge cases to verify comprehensive coverage.\n")
    
    input("Press Enter to start tests (this may take several minutes)...")
    
    tester = ScannerTester()
    test_cases = get_test_cases()
    
    print(f"\n📋 Running {len(test_cases)} test cases...\n")
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n[{i}/{len(test_cases)}]", end=" ")
        tester.run_test(test_case)
        
        # Small delay between tests to be respectful to servers
        if i < len(test_cases):
            time.sleep(1)
    
    # Print summary
    tester.print_summary()
    
    # Cleanup
    print("\n🧹 Cleaning up...")
    close_db_connection()
    print("✅ Done!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        close_db_connection()
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        close_db_connection()
        sys.exit(1)