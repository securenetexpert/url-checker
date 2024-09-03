import unittest
from url_checker import check_https, check_ssl_certificate, check_phishing_patterns, is_url_safe

class TestUrlChecker(unittest.TestCase):
    def test_check_https(self):
        self.assertTrue(check_https("https://example.com"))
        self.assertFalse(check_https("http://example.com"))

    def test_check_ssl_certificate(self):
        self.assertTrue(check_ssl_certificate("https://www.google.com"))
        self.assertFalse(check_ssl_certificate("https://expired.badssl.com"))

    def test_check_phishing_patterns(self):
        self.assertTrue(check_phishing_patterns("https://secure-login.com"))
        self.assertFalse(check_phishing_patterns("https://example.com"))

    def test_is_url_safe(self):
        self.assertTrue(is_url_safe("https://www.google.com"))
        self.assertFalse(is_url_safe("http://example.com"))
        self.assertFalse(is_url_safe("https://expired.badssl.com"))
        self.assertFalse(is_url_safe("https://secure-login.com"))

if __name__ == "__main__":
    unittest.main()
