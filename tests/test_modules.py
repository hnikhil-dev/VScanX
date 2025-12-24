"""
Unit tests for VScanX modules
"""

import unittest

from core.request_handler import validate_target
from modules.base_module import BaseModule
from modules.network.port_scanner import PortScanner


class TestBaseModule(unittest.TestCase):
    """Test base module functionality"""

    def setUp(self):
        """Set up test fixtures"""

        class TestModule(BaseModule):
            def run(self, target, **kwargs):
                return {"module": self.name, "target": target}

        self.module = TestModule()

    def test_metadata(self):
        """Test module metadata retrieval"""
        metadata = self.module.get_metadata()
        self.assertIn("name", metadata)
        self.assertIn("description", metadata)
        self.assertIn("version", metadata)

    def test_add_result(self):
        """Test adding results"""
        self.module.add_result("HIGH", "Test finding", "Details")
        results = self.module.get_results()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity"], "HIGH")

    def test_clear_results(self):
        """Test clearing results"""
        self.module.add_result("LOW", "Test")
        self.module.clear_results()
        self.assertEqual(len(self.module.get_results()), 0)


class TestValidation(unittest.TestCase):
    """Test input validation"""

    def test_valid_url(self):
        """Test valid URL validation"""
        self.assertTrue(validate_target("http://example.com"))
        self.assertTrue(validate_target("https://example.com"))

    def test_valid_ip(self):
        """Test valid IP validation"""
        self.assertTrue(validate_target("192.168.1.1"))
        self.assertTrue(validate_target("10.0.0.1"))

    def test_invalid_target(self):
        """Test invalid target validation"""
        self.assertFalse(validate_target("invalid"))
        self.assertFalse(validate_target("999.999.999.999"))
        self.assertFalse(validate_target(""))


class TestPortScanner(unittest.TestCase):
    """Test port scanner module"""

    def setUp(self):
        """Set up test fixtures"""
        self.scanner = PortScanner()

    def test_service_identification(self):
        """Test service identification"""
        self.assertEqual(self.scanner._identify_service(80), "HTTP")
        self.assertEqual(self.scanner._identify_service(443), "HTTPS")
        self.assertEqual(self.scanner._identify_service(99999), "unknown")


if __name__ == "__main__":
    unittest.main()
