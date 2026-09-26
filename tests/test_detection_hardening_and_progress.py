"""
Unit tests for detection hardening (soft-404, CORS, cookies) and terminal progress bar.
"""

from __future__ import annotations

import unittest

from core.cli_reporter import CLIReporter
from core.console import ProgressBar, print_finding, reset_console_state
from core.events.bus import EventBus
from modules.web.dir_enum import DirectoryEnumerator
from modules.web.header_analyzer import HeaderAnalyzer


class FakeResponse:
    def __init__(self, text: str = "OK", status_code: int = 200, headers=None, content=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {}
        self.content = content if content is not None else text.encode("utf-8")


class MockHandler:
    def __init__(self, default_response=None, response_map=None):
        self.default_response = default_response or FakeResponse()
        self.response_map = response_map or {}
        self.requested_urls = []

    def get(self, url, **kwargs):
        self.requested_urls.append(url)
        for pattern, resp in self.response_map.items():
            if pattern in url:
                return resp
        return self.default_response

    async def async_get(self, url, **kwargs):
        return self.get(url, **kwargs)


class TestSoft404Detection(unittest.TestCase):
    def test_soft_404_detected_and_filters_noise(self):
        """Test that soft-404 catch-all 200 responses are detected and filtered out."""
        # Simulated SPA returning "Welcome to React App" (200 OK, 150 bytes) for everything
        spa_response = FakeResponse(
            "Welcome to React App",
            status_code=200,
            content=b"Welcome to React App " * 5,
        )
        handler = MockHandler(default_response=spa_response)
        enumerator = DirectoryEnumerator(max_threads=2, handler=handler)

        result = enumerator.run("http://target.local")

        # Soft 404 profile should be active
        self.assertTrue(enumerator.soft_404_profile.get("active"))
        self.assertEqual(enumerator.soft_404_profile.get("status"), 200)

        # Soft-404 INFO finding should be reported
        soft_404_findings = [f for f in result["findings"] if "Soft-404" in f.get("finding", "")]
        self.assertEqual(len(soft_404_findings), 1)

        # None of the generic probed paths should be flagged as accessible paths
        self.assertEqual(len(result["found_paths"]), 0)

    def test_normal_server_not_soft_404(self):
        """Test standard server returning 404 for missing paths doesn't trigger soft-404."""
        not_found = FakeResponse("Not Found", status_code=404)
        found_admin = FakeResponse("Admin Console", status_code=200, content=b"Admin Panel")
        handler = MockHandler(
            default_response=not_found,
            response_map={"admin/": found_admin},
        )
        enumerator = DirectoryEnumerator(max_threads=2, handler=handler)

        # Direct test on path
        enumerator._detect_soft_404("http://target.local")
        self.assertFalse(enumerator.soft_404_profile.get("active", False))

        enumerator._test_path("http://target.local", "admin/")
        self.assertEqual(len(enumerator.found_paths), 1)
        self.assertEqual(enumerator.found_paths[0]["path"], "admin/")


class TestHeaderAndCookieSecurity(unittest.TestCase):
    def test_cors_wildcard_with_credentials(self):
        """Test CORS with * and credentials=true triggers HIGH finding."""
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        analyzer = HeaderAnalyzer()
        analyzer._analyze_cors(headers)
        findings = analyzer.get_results()

        cors_high = [f for f in findings if f["severity"] == "HIGH" and "Insecure CORS" in f["finding"]]
        self.assertEqual(len(cors_high), 1)

    def test_cors_null_origin(self):
        """Test CORS with origin null triggers MEDIUM finding."""
        headers = {"Access-Control-Allow-Origin": "null"}
        analyzer = HeaderAnalyzer()
        analyzer._analyze_cors(headers)
        findings = analyzer.get_results()

        cors_med = [f for f in findings if f["severity"] == "MEDIUM" and "Null origin" in f["finding"]]
        self.assertEqual(len(cors_med), 1)

    def test_cookie_security_flags(self):
        """Test missing HttpOnly, missing Secure, and weak SameSite on cookies."""

        class MockHeaders(dict):
            def get_list(self, key):
                if key.lower() == "set-cookie":
                    return [
                        "session_id=abc12345; Path=/",
                        "pref=dark; Path=/; SameSite=None",
                    ]
                return []

        response = FakeResponse(headers=MockHeaders())
        analyzer = HeaderAnalyzer()
        analyzer._analyze_cookies(response, is_https=True)
        findings = analyzer.get_results()

        # Should flag missing HttpOnly on session_id (MEDIUM severity because sensitive name)
        http_only_findings = [f for f in findings if "missing HttpOnly" in f["finding"]]
        self.assertTrue(any(f["severity"] == "MEDIUM" for f in http_only_findings))

        # Should flag missing Secure on HTTPS
        secure_findings = [f for f in findings if "missing Secure" in f["finding"]]
        self.assertTrue(len(secure_findings) >= 1)

        # Should flag SameSite=None without Secure
        samesite_findings = [f for f in findings if "Insecure SameSite" in f["finding"]]
        self.assertTrue(len(samesite_findings) >= 1)


class TestProgressBarAndCLI(unittest.TestCase):
    def test_progress_bar_lifecycle(self):
        """Test ProgressBar updates, finish, and clear without exceptions."""
        bar = ProgressBar(total=10, prefix="[*] Test")
        bar.is_tty = False  # Test non-TTY / CI mode
        bar.update(2, "item_2")
        bar.update(5, "item_5")  # 50% milestone
        bar.update(10, "done")
        bar.finish()

        # Test TTY mode
        bar_tty = ProgressBar(total=20, prefix="[*] TTY")
        bar_tty.is_tty = True
        bar_tty.update(10, "halfway")
        bar_tty.clear()
        bar_tty.finish()

    def test_finding_deduplication(self):
        """Test that identical findings are deduplicated by console printer."""
        reset_console_state()
        finding = {
            "module": "XSS Detector",
            "severity": "HIGH",
            "endpoint": "http://example.com/search?q=1",
            "parameter": "q",
            "evidence": {"payload": "<script>alert(1)</script>"},
        }
        # First call prints
        print_finding(finding)
        # Second call with exact duplicate should be silently suppressed
        print_finding(finding)

    def test_cli_reporter_progress_events(self):
        """Test that CLIReporter processes module.progress events."""
        bus = EventBus()
        reporter = CLIReporter(bus)
        # Publish progress event
        bus.publish(
            "module.progress",
            {"module": "Directory Enumerator", "current": 5, "total": 10, "item": "/admin/"},
        )
        self.assertIsNotNone(reporter.active_bar)
        self.assertEqual(reporter.active_bar.current, 5)
        # Module completed should finalize active bar
        bus.publish("module.completed", {"module": "Directory Enumerator", "duration": 1.2})
        self.assertIsNone(reporter.active_bar)


if __name__ == "__main__":
    unittest.main()
