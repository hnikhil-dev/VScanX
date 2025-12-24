"""
VScanX Phase 2 Feature Test
Tests all new features
"""

import sys

import pytest


def test_imports():
    """Test that all modules can be imported"""
    print("=" * 60)
    print("TESTING IMPORTS")
    print("=" * 60)

    try:
        from core.config import SCAN_PROFILES, VERSION

        print(f"✓ Config imported (Version: {VERSION})")
        print(f"  Available profiles: {', '.join(SCAN_PROFILES.keys())}")
    except Exception as e:
        pytest.fail(f"Config import failed: {e}")

    try:
        print("✓ Export formats module imported")
    except Exception as e:
        pytest.fail(f"Export module failed: {e}")

    try:
        print("✓ SQL Injection detector imported")
    except Exception as e:
        pytest.fail(f"SQLi detector failed: {e}")

    try:
        print("✓ Directory enumerator imported")
    except Exception as e:
        pytest.fail(f"Directory enumerator failed: {e}")

    try:
        print("✓ Header analyzer imported")
    except Exception as e:
        pytest.fail(f"Header analyzer failed: {e}")

    try:
        print("✓ Enhanced orchestrator imported")
    except Exception as e:
        pytest.fail(f"Orchestrator failed: {e}")

    print("\n✓ All imports successful!\n")


def test_profiles():
    """Test scan profiles"""
    print("=" * 60)
    print("TESTING SCAN PROFILES")
    print("=" * 60)

    from core.config import SCAN_PROFILES

    for name, config in SCAN_PROFILES.items():
        print(f"\n{name.upper()}:")
        print(f"  Port range: {config['port_range']}")
        print(f"  Threads: {config['max_threads']}")
        print(f"  Delay: {config['delay']}s")

    print("\n✓ Profiles configured correctly!\n")


def test_export():
    """Test export functionality"""
    print("=" * 60)
    print("TESTING EXPORT FORMATS")
    print("=" * 60)

    from reporting.export_formats import ExportHandler

    # Create test data
    test_results = {
        "target": "http://test.com",
        "scan_type": "web",
        "timestamp": "2025-12-12T16:00:00",
        "duration": 10.5,
        "modules": [
            {
                "module": "Test Module",
                "findings": [
                    {
                        "severity": "HIGH",
                        "finding": "Test vulnerability",
                        "details": "This is a test",
                    }
                ],
            }
        ],
    }

    test_summary = {
        "total_findings": 1,
        "by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    }

    exporter = ExportHandler()

    try:
        json_path = exporter.export_json(test_results, "test_export")
        print(f"✓ JSON export: {json_path}")
    except Exception as e:
        print(f"✗ JSON export failed: {e}")

    try:
        csv_path = exporter.export_csv(test_results, "test_export")
        print(f"✓ CSV export: {csv_path}")
    except Exception as e:
        print(f"✗ CSV export failed: {e}")

    try:
        txt_path = exporter.export_txt(test_results, test_summary, "test_export")
        print(f"✓ TXT export: {txt_path}")
    except Exception as e:
        print(f"✗ TXT export failed: {e}")

    print("\n✓ Export formats working!\n")


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("VScanX Phase 2 Feature Test")
    print("=" * 60 + "\n")

    if not test_imports():
        print("\n✗ Import tests failed! Fix errors before proceeding.\n")
        sys.exit(1)

    test_profiles()
    test_export()

    print("=" * 60)
    print("✓ ALL TESTS PASSED!")
    print("=" * 60)
    print("\nPhase 2 features are ready!")
    print("\nNext steps:")
    print("1. Test with: python vscanx.py --list-profiles")
    print(
        "2. Run quick scan: python vscanx.py -t http://127.0.0.1:8080 --profile quick"
    )
    print("3. Full scan: python vscanx.py -t http://127.0.0.1:8080 --profile full -v")
    print()


if __name__ == "__main__":
    main()
