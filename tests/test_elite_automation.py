from core.elite.chaining_engine import VulnerabilityChainingEngine
from core.elite.defensive_variants import DefensiveVariantGenerator
from core.elite.oob import OOBManager
from core.elite.poc_generator import PoCGenerator
from core.verify.engine import VerificationEngine


def test_oob_manager_callback_generation():
    mgr = OOBManager(base_url="https://listener.example")
    cb = mgr.make_callback("scan")
    assert cb.startswith("https://listener.example/scan/")  # nosec: B101


def test_chaining_engine_builds_chain():
    engine = VulnerabilityChainingEngine()
    findings = [
        {"module": "Open Redirect Prober", "severity": "HIGH", "description": "Open redirect via parameter 'next'"},
        {"module": "Authentication Bypass Detector", "severity": "HIGH", "description": "Potential auth bypass"},
    ]
    modules = [{"module": "Open Redirect Prober"}, {"module": "Authentication Bypass Detector"}]
    chains = engine.build_chains(findings=findings, modules=modules)
    assert len(chains) >= 1  # nosec: B101


def test_poc_generator_outputs_commands():
    gen = PoCGenerator()
    pocs = gen.generate(
        target="http://example.local/login?next=https://example.org/",
        findings=[{"module": "HTTP Headers Analyzer", "severity": "MEDIUM", "description": "Missing security header: Content-Security-Policy"}],
    )
    assert len(pocs) >= 1  # nosec: B101


def test_defensive_variant_generator_variants():
    gen = DefensiveVariantGenerator()
    variants = gen.generate_variants("http://example.local/path")
    assert isinstance(variants, list)  # nosec: B101


def test_defensive_variant_generator_analyze_strict_flag():
    class DummyResp:
        def __init__(self, status_code: int, content: bytes):
            self.status_code = status_code
            self.content = content

    class DummyHandler:
        def get(self, url: str, allow_redirects: bool = False):
            if url.endswith("/"):
                return DummyResp(301, b"")
            return DummyResp(200, b"x" * 200)

    gen = DefensiveVariantGenerator()
    out = gen.analyze(DummyHandler(), "http://example.local/path", strict=True)
    assert out["strict"] is True  # nosec: B101


def test_verification_engine_similarity_range():
    v = VerificationEngine()
    sim = v.similarity("abc", "abc")
    assert 0.99 <= sim <= 1.0  # nosec: B101

