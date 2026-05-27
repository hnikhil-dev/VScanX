from modules.web.auth_bypass_detector import AuthBypassDetector
from modules.web.hpp_detector import HPPDetector
from modules.web.idor_detector import IDORDetector
from modules.web.js_secret_analyzer import JSSecretAnalyzer
from modules.web.open_redirect_prober import OpenRedirectProber
from modules.web.rate_limit_checker import RateLimitChecker
from modules.web.subdomain_recon import SubdomainReconSuite
from modules.web.tech_fingerprinter import TechFingerprinter


def test_rate_limit_analysis_detection():
    checker = RateLimitChecker()
    analysis = checker._analyze([200, 200, 429, 403])
    assert analysis["controls_present"] is True  # nosec: B101 - test assertion
    assert analysis["status_429"] == 1  # nosec: B101 - test assertion


def test_tech_fingerprint_detects_wordpress():
    fingerprinter = TechFingerprinter()
    profile = fingerprinter._build_profile(
        headers={"Server": "nginx", "X-Powered-By": "PHP/8.2"},
        body='<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">',
    )
    assert "nginx" in profile["detected"]["servers"]  # nosec: B101 - test assertion
    assert "wordpress" in profile["detected"]["cms"]  # nosec: B101 - test assertion


def test_idor_candidate_extraction_and_mutation():
    detector = IDORDetector()
    candidates = detector._extract_candidate_params(
        "http://example.local/user?id=42&slug=test&uuid=550e8400-e29b-41d4-a716-446655440000"
    )
    assert candidates["id"] == "42"  # nosec: B101 - test assertion
    assert "uuid" in candidates  # nosec: B101 - test assertion
    assert "43" in detector._mutate("42")  # nosec: B101 - test assertion


def test_hpp_polluted_param_builder():
    detector = HPPDetector()
    polluted = detector._build_polluted_params({"id": ["10"], "q": ["x"]}, "id", "admin")
    assert polluted["id"] == "10&id=admin"  # nosec: B101 - test assertion
    assert polluted["q"] == "x"  # nosec: B101 - test assertion


def test_auth_bypass_status_transition_logic():
    detector = AuthBypassDetector()
    assert detector._is_bypass(403, 200) is True  # nosec: B101 - test assertion
    assert detector._is_bypass(200, 200) is False  # nosec: B101 - test assertion


def test_js_secret_extract_and_detect():
    analyzer = JSSecretAnalyzer()
    js_urls = analyzer._extract_js_urls("http://example.local", "<script src='/static/app.js'></script>")
    assert js_urls == ["http://example.local/static/app.js"]  # nosec: B101
    secrets, endpoints = analyzer._analyze_js_text(
        "http://example.local/static/app.js",
        "const api_key='AKIAAAAAAAAAAAAAAAA'; fetch('/api/users');",
    )
    assert len(secrets) >= 1  # nosec: B101
    assert len(endpoints) >= 1  # nosec: B101


def test_subdomain_domain_extraction():
    recon = SubdomainReconSuite()
    assert recon._extract_domain("https://app.example.com/path") == "app.example.com"  # nosec: B101
    assert recon._extract_domain("127.0.0.1") is None  # nosec: B101


def test_open_redirect_external_location_detection():
    prober = OpenRedirectProber()
    assert prober._is_external_location("https://evil.com/x", "example.com") is True  # nosec: B101
    assert prober._is_external_location("/local", "example.com") is False  # nosec: B101
