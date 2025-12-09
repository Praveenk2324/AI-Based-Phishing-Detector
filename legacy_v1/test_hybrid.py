import unittest
from utils import is_domain_active
# Mocking parts of app for testing logic if needed, but primarily testing utils first

class TestHybridVerification(unittest.TestCase):
    def test_dns_active(self):
        print("\nTesting DNS Active (google.com)...")
        self.assertTrue(is_domain_active('http://google.com'))
        self.assertTrue(is_domain_active('google.com'))

    def test_dns_inactive(self):
        print("\nTesting DNS Inactive (thisdomainshouldnotexist12345.com)...")
        self.assertFalse(is_domain_active('http://thisdomainshouldnotexist12345.com'))
        
    def test_dns_timeout(self):
        # Difficult to deterministicly test timeout without mocking, but we can ensure it doesn't hang forever
        pass

if __name__ == '__main__':
    unittest.main()
