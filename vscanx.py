#!/usr/bin/env python3
"""
VScanX - Ethical Vulnerability Scanner
Main CLI entry point with Phase 3 enhancements (Authentication + CVE)
"""

import argparse
import logging
import sys
from datetime import datetime

from core.config import DEFAULT_DELAY, SCAN_PROFILES, VERSION
from core.logging_config import setup_logging_with_file
from core.orchestrator import Orchestrator
from reporting.export_formats import ExportHandler
from reporting.report_generator import ReportGenerator

# Global verbose flag
VERBOSE = False


def vprint(message: str):
    """Print only if verbose mode is enabled"""
    if VERBOSE:
        print(message)


def print_banner():
    """Display ASCII banner"""
    banner = (
        "========================================================\n"
        "VScanX - Ethical Vulnerability Scanner\n"
        f"Version {VERSION}\n"
        "Modular Security Testing Framework\n"
        "========================================================"
    )
    print(banner)


def show_legal_warning():
    """Display legal warning"""
    warning = """
⚠️  LEGAL WARNING ⚠️

This tool is designed for AUTHORIZED security testing only.
You must have explicit permission to scan any target system.
Unauthorized scanning may be illegal in your jurisdiction.

By using this tool, you agree to:
  • Only scan systems you own or have written authorization to test
  • Comply with all applicable laws and regulations
  • Accept full responsibility for your actions

The developers assume NO liability for misuse of this tool.
"""
    print(warning)


def list_profiles():
    """Display available scan profiles"""
    print("\n" + "=" * 60)
    print("AVAILABLE SCAN PROFILES")
    print("=" * 60)

    for profile_name, profile_config in SCAN_PROFILES.items():
        print(f"\n{profile_name.upper()}:")
        print(f"  Description: {profile_config['description']}")
        print(
            f"  Port Range: {profile_config['port_range'][0]}-{profile_config['port_range'][1]}"
        )
        print(f"  Threads: {profile_config['max_threads']}")
        print(f"  Delay: {profile_config['delay']}s")

    print("\n" + "=" * 60)


def create_parser():
    """Create and configure argument parser"""
    parser = argparse.ArgumentParser(
        description="VScanX - Ethical Vulnerability Scanner v" + VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scans
  python vscanx.py -t http://example.com -s web
  python vscanx.py -t 192.168.1.1 -s network -p 1-100
  python vscanx.py -t http://example.com -s mixed

  # Using profiles
  python vscanx.py -t http://example.com --profile quick
  python vscanx.py -t http://example.com --profile full -v

  # Authentication
  python vscanx.py -t http://example.com/admin \\
    --login-url http://example.com/login \\
    --username admin --password secret \\
    --success-indicator "Welcome"

  # Multiple export formats
  python vscanx.py -t http://example.com --format json,csv,html

  # List profiles
  python vscanx.py --list-profiles
""",
    )

    # Required arguments
    parser.add_argument("-t", "--target", help="Target URL or IP address")

    # Scan options
    parser.add_argument(
        "-s",
        "--scan-type",
        choices=["web", "network", "mixed"],
        default="mixed",
        help="Type of scan to perform (default: mixed)",
    )

    parser.add_argument(
        "-p", "--ports", help="Port range for network scan (e.g., 1-1024)", default=None
    )

    parser.add_argument(
        "--profile",
        choices=list(SCAN_PROFILES.keys()),
        help="Use predefined scan profile (quick/normal/full/stealth)",
    )

    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available scan profiles and exit",
    )

    # Custom payloads
    parser.add_argument(
        "--xss-payload",
        action="append",
        help="Add custom XSS payload (can be used multiple times)",
    )

    parser.add_argument(
        "--sqli-payload",
        action="append",
        help="Add custom SQL injection payload (can be used multiple times)",
    )

    # Output options
    parser.add_argument(
        "-o",
        "--output",
        help="Output report filename (without extension)",
        default=None,
    )

    parser.add_argument(
        "--format",
        help="Export format(s): html,json,csv,txt (comma-separated)",
        default="html",
    )

    parser.add_argument(
        "--no-report", action="store_true", help="Skip report generation"
    )

    # Verbosity
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    # Threading
    parser.add_argument(
        "--threads",
        type=int,
        help="Number of threads for scanning (default: 10)",
        default=None,
    )
    parser.add_argument(
        "--parallel-modules",
        action="store_true",
        help="Run web modules in parallel (experimental)",
    )

    # Logging / diagnostics
    parser.add_argument(
        "--log-file", type=str, help="Path to write JSONL logs (optional)"
    )
    parser.add_argument(
        "--scan-id", type=str, help="Identifier to correlate logs/artifacts (optional)"
    )
    parser.add_argument(
        "--debug-capture",
        action="store_true",
        help="Capture redacted request/response metadata for debugging",
    )

    # Misc options
    parser.add_argument("--version", action="version", version=f"VScanX {VERSION}")

    parser.add_argument(
        "--skip-warning",
        action="store_true",
        help="Skip legal warning (use with caution)",
    )

    parser.add_argument(
        "--delay",
        type=float,
        help="Delay between requests in seconds (default: 1.0)",
        default=None,
    )

    # Authentication options
    auth_group = parser.add_argument_group("Authentication Options")
    auth_group.add_argument("--login-url", type=str, help="URL of login page/endpoint")
    auth_group.add_argument("--username", type=str, help="Username for authentication")
    auth_group.add_argument("--password", type=str, help="Password for authentication")
    auth_group.add_argument(
        "--auth-data",
        type=str,
        help='Custom auth data as JSON (e.g., {"user":"admin","pass":"secret"})',
    )
    auth_group.add_argument(
        "--bearer-token", type=str, help="Bearer token for API authentication"
    )
    auth_group.add_argument("--api-key", type=str, help="API key for authentication")
    auth_group.add_argument(
        "--api-key-header",
        type=str,
        default="X-API-Key",
        help="Header name for API key (default: X-API-Key)",
    )
    auth_group.add_argument("--session-file", type=str, help="Load session from file")
    auth_group.add_argument(
        "--save-session", type=str, help="Save authenticated session to file"
    )
    auth_group.add_argument(
        "--success-indicator",
        type=str,
        help='String in response indicating successful login (e.g., "Welcome")',
    )

    return parser


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Configure logging early
    setup_logging_with_file(
        logging.DEBUG if args.verbose else logging.INFO, log_path=args.log_file
    )
    log = logging.getLogger("vscanx.cli")

    # List profiles if requested
    if args.list_profiles:
        list_profiles()
        return

    # Validate required arguments
    if not args.target:
        parser.print_help()
        log.error("Target (-t/--target) is required")
        return

    # Set verbosity
    global VERBOSE
    VERBOSE = args.verbose

    # Print banner (user-facing)
    print_banner()

    # Handle authentication setup
    auth_handler = None
    if any([args.login_url, args.bearer_token, args.api_key, args.session_file]):
        log.info("Setting up authentication")

        # Import here to avoid circular dependency
        from core.request_handler import RequestHandler

        # Create authenticated request handler
        auth_handler = RequestHandler(
            delay=args.delay if args.delay else DEFAULT_DELAY,
            debug_capture=args.debug_capture,
        )

        # Load existing session
        if args.session_file:
            if auth_handler.load_session(args.session_file):
                log.info("Session loaded successfully")
            else:
                log.error("Failed to load session")
                return

        # Bearer token authentication
        elif args.bearer_token:
            auth_handler.set_bearer_token(args.bearer_token)

        # API key authentication
        elif args.api_key:
            auth_handler.set_api_key(args.api_key, args.api_key_header)

        # Username/password authentication
        elif args.login_url and (args.username or args.auth_data):
            if args.auth_data:
                # Custom JSON auth data
                import json

                credentials = json.loads(args.auth_data)
            else:
                # Standard username/password
                if not args.password:
                    import getpass

                    args.password = getpass.getpass("Password: ")

                credentials = {"username": args.username, "password": args.password}

            success = auth_handler.login(
                args.login_url, credentials, success_indicator=args.success_indicator
            )

            if not success:
                log.error("Authentication failed. Exiting.")
                return

            # Save session if requested
            if args.save_session:
                auth_handler.save_session(args.save_session)

        log.info("Authentication configured")

    # Apply profile configuration
    profile_config = {}
    if args.profile:
        profile_name = args.profile.lower()
        if profile_name in SCAN_PROFILES:
            log.info("Applying profile: %s", profile_name)
            profile_config = SCAN_PROFILES[profile_name].copy()
            log.info("Profile description: %s", profile_config["description"])

            # Apply profile settings if not overridden by CLI args
            if not args.ports and profile_config.get("port_range"):
                args.ports = f"{profile_config['port_range'][0]}-{profile_config['port_range'][1]}"
                log.info("Port range set to: %s", args.ports)

            if not args.threads:
                args.threads = profile_config.get("max_threads", 10)
                log.info("Threads set to: %s", args.threads)

            if not args.delay:
                args.delay = profile_config.get("delay", 1.0)
                log.info("Delay set to: %ss", args.delay)
        else:
            log.error("Unknown profile: %s", profile_name)
            log.info("Available profiles: %s", ", ".join(SCAN_PROFILES.keys()))
            return

    # Parse port range
    port_range = None
    if args.ports:
        try:
            if "-" in args.ports:
                start, end = map(int, args.ports.split("-"))
                port_range = (start, end)
            else:
                port = int(args.ports)
                port_range = (port, port)
        except ValueError:
            log.error("Invalid port range: %s", args.ports)
            return

    # Set export formats (support comma-separated with spaces)
    export_formats = (
        [fmt.strip().lower() for fmt in args.format.split(",")]
        if args.format
        else ["html"]
    )
    export_formats = [fmt for fmt in export_formats if fmt]
    log.info("Export formats: %s", ", ".join(export_formats))

    # Legal warning
    if not args.skip_warning:
        show_legal_warning()
        response = input("\nDo you have authorization to scan this target? (yes/no): ")
        if response.lower() not in ["yes", "y"]:
            print("[!] Scan aborted. Authorization required.")
            return

    # Create orchestrator with optional authentication
    orchestrator = Orchestrator(
        custom_xss_payloads=args.xss_payload,
        custom_sqli_payloads=args.sqli_payload,
        max_threads=(
            args.threads if args.threads else profile_config.get("max_threads", 10)
        ),
        delay=args.delay if args.delay else profile_config.get("delay", 1.0),
        verbose=VERBOSE,
        auth_handler=auth_handler,
        scan_id=args.scan_id,
        parallel_modules=args.parallel_modules,
        debug_capture=args.debug_capture,
    )

    # Execute scan
    results = orchestrator.execute_scan(
        target=args.target,
        scan_type=args.scan_type,
        port_range=port_range,
        profile_config=profile_config,
    )

    # Generate summary
    summary = orchestrator.get_summary()

    # Sanity checks: ensure findings are present and consistent
    from core.utils import validate_results_summary

    try:
        validate_results_summary(results, summary)
    except Exception as e:
        print(f"[!] Internal error: {e}. Aborting report generation.")
        sys.exit(1)

    # Add metadata to summary for reports (ensure keys exist)
    summary["target"] = summary.get("target", args.target)
    summary["scan_type"] = summary.get("scan_type", args.scan_type).upper()
    summary["start_time"] = summary.get(
        "start_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    summary["duration"] = summary.get("duration", results.get("duration", 0))

    # Display summary
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Total Findings: {summary['total_findings']}")
    print(f"  CRITICAL: {summary['by_severity']['CRITICAL']}")
    print(f"  HIGH:     {summary['by_severity']['HIGH']}")
    print(f"  MEDIUM:   {summary['by_severity']['MEDIUM']}")
    print(f"  LOW:      {summary['by_severity']['LOW']}")
    print(f"  INFO:     {summary['by_severity']['INFO']}")
    if summary.get("authenticated"):
        print("  Authentication: ENABLED")
    print("=" * 60 + "\n")

    # Skip report generation if requested
    if args.no_report:
        print("[*] Skipping report generation (--no-report flag set)")
        print("\n[+] Scan completed successfully!")
        return

    # Generate reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Create a filename that includes sanitized target and scan type
    try:
        from urllib.parse import urlparse

        parsed = urlparse(args.target)
        host_part = parsed.hostname if parsed.hostname else args.target
    except Exception:
        host_part = args.target

    import re

    safe_host = re.sub(r"[^A-Za-z0-9._-]+", "_", str(host_part))
    base_filename = (
        args.output
        if args.output
        else f"vscanx_{safe_host}_{args.scan_type}_{timestamp}"
    )

    print(f"[*] Generating reports with base name: {base_filename}")

    generator = ReportGenerator()
    exporter = ExportHandler()

    # Single pass over requested formats, ensure each runs exactly once
    for fmt in dict.fromkeys(export_formats):  # preserve order, unique
        fmt = fmt.lower()
        try:
            if fmt == "html":
                html_path = generator.generate_html_report(
                    results, summary, base_filename
                )
                print(f"[+] HTML report: {html_path}")
            elif fmt == "pdf":
                pdf_path = generator.generate_pdf_report(
                    results, summary, base_filename
                )
                if pdf_path:
                    print(f"[+] PDF report: {pdf_path}")
            elif fmt == "json":
                json_path = exporter.export_json(results, base_filename)
                print(f"[+] JSON report: {json_path}")
            elif fmt == "csv":
                csv_path = exporter.export_csv(results, base_filename)
                print(f"[+] CSV report: {csv_path}")
            elif fmt == "txt":
                txt_path = exporter.export_txt(results, summary, base_filename)
                print(f"[+] TXT report: {txt_path}")
            else:
                print(f"[!] Unknown format: {fmt}")
        except Exception as e:
            print(f"[!] Error generating {fmt.upper()} report: {e}")

    # Emit metrics artifact (optional)
    try:
        from pathlib import Path

        metrics_path = Path("reports") / f"{base_filename}_metrics.json"
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        import json

        with open(metrics_path, "w", encoding="utf-8") as mf:
            json.dump(
                {"scan_id": args.scan_id, "metrics": orchestrator.metrics.to_dict()},
                mf,
                indent=2,
            )
        log.info("Metrics artifact written", extra={"path": str(metrics_path)})
    except Exception as e:
        log.error("Failed to write metrics artifact: %s", e)

    print("\n[+] Scan completed successfully!")


if __name__ == "__main__":
    main()
