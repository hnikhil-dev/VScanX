#!/usr/bin/env python3
"""
VScanX - Ethical Vulnerability Scanner
Main CLI entry point with Phase 3 enhancements (Authentication + CVE)
"""

import argparse
import logging
import os
import sys
import warnings
from datetime import datetime

# Silence noisy third-party python warnings (e.g. from scapy/cryptography)
warnings.filterwarnings("ignore")

from core.config import (
    DEFAULT_DELAY,
    DEFENSIVE_VARIANTS_DEFAULT_ENABLED,
    ELITE_AUTOMATION_DEFAULT_ENABLED,
    SCAN_PROFILES,
    VERSION,
)
from core.logging_config import setup_logging_with_file
from core.console import print_banner, print_legal_warning, print_summary, DIM, RESET
from core.cli_reporter import CLIReporter
from core.orchestrator import Orchestrator
from reporting.export_formats import ExportHandler
from reporting.report_generator import ReportGenerator

# Global verbose flag
VERBOSE = False


def vprint(message: str):
    """Print only if verbose mode is enabled"""
    if VERBOSE:
        print(message)


def show_legal_warning():
    """Display legal warning"""
    print_legal_warning()


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

    parser.add_argument(
        "-s",
        "--scan-type",
        choices=["web", "network", "mixed", "web3", "agentic"],
        default="mixed",
        help="Type of scan to perform (default: mixed)",
    )

    parser.add_argument(
        "--rpc-url",
        help="RPC URL for Web3 smart contract scanning (e.g. Infura/Alchemy or local network)",
        default=None,
    )
    parser.add_argument(
        "--contract",
        help="Target smart contract address to scan",
        default=None,
    )
    parser.add_argument(
        "--abi",
        help="Path to smart contract ABI JSON file (optional)",
        default=None,
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
        "--only",
        type=str,
        help="Comma-separated list of modules to run exclusively (e.g. sqli, xss, dir)",
        default=None,
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume scan state (crawler inventory and artifacts) using --scan-id",
    )
    parser.add_argument(
        "--replay",
        action="store_true",
        help="Replay a previous scan from --state-dir using --scan-id (no scanning; reports only).",
    )
    parser.add_argument(
        "--replay-verify",
        action="store_true",
        help="Replay verification only for a saved scan (requires --scan-id). Updates verification_state/confidence from reproduction contracts.",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Diff two saved scans (requires --scan-id and --scan-id2). Writes a JSON diff report.",
    )
    parser.add_argument(
        "--scan-id2",
        type=str,
        help="Second scan identifier for --diff (compares --scan-id → --scan-id2).",
    )
    parser.add_argument(
        "--state-dir",
        type=str,
        default=".vscanx_state",
        help="Directory for persistent scan state (default: .vscanx_state)",
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
    parser.add_argument(
        "--strict-events",
        action="store_true",
        help="Fail fast on invalid internal event payloads (recommended for CI/dev only).",
    )

    elite_group = parser.add_argument_group("Elite Automation (Phase 5)")
    elite_group.add_argument(
        "--elite",
        action="store_true",
        default=ELITE_AUTOMATION_DEFAULT_ENABLED,
        help="Enable elite automation layer (chaining + PoC + OOB provisioning)",
    )
    elite_group.add_argument(
        "--defensive-variants",
        action="store_true",
        default=DEFENSIVE_VARIANTS_DEFAULT_ENABLED,
        help="Enable defensive URL normalization variant checks (reports inconsistencies only)",
    )
    elite_group.add_argument(
        "--defensive-variants-nonstrict",
        action="store_true",
        default=False,
        help="Use non-strict variant checks (includes large content deltas; higher sensitivity)",
    )
    elite_group.add_argument(
        "--oob-base-url",
        type=str,
        default="",
        help="Base URL for OOB callbacks (optional, e.g. https://<your-listener>)",
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

    # Diff mode: compare two saved scans and write diff JSON (no scanning).
    if args.diff:
        if not args.scan_id or not args.scan_id2:
            log.error("--diff requires --scan-id and --scan-id2")
            return
        from core.state.store import ScanStateStore
        from core.state.diff import diff_scan_results

        store = ScanStateStore(root_dir=str(args.state_dir))
        a = store.load(str(args.scan_id), "results")
        b = store.load(str(args.scan_id2), "results")
        if not a:
            log.error("No saved scan results found for scan_id=%s", args.scan_id)
            return
        if not b:
            log.error("No saved scan results found for scan_id=%s", args.scan_id2)
            return

        out = diff_scan_results(a, b)
        outname = args.output or f"diff_{args.scan_id}_to_{args.scan_id2}"
        os.makedirs("reports", exist_ok=True)
        outpath = os.path.abspath(os.path.join("reports", f"{outname}.diff.json"))
        with open(outpath, "w", encoding="utf-8") as f:
            import json

            json.dump(out, f, indent=2, ensure_ascii=False)

        c = out.get("counts", {})
        log.info(
            "Diff complete: new=%s resolved=%s changed=%s unchanged=%s",
            c.get("new"),
            c.get("resolved"),
            c.get("changed"),
            c.get("unchanged"),
        )
        print(f"[+] Diff report written: {outpath}")
        return

    # Replay mode: load prior scan and regenerate reports without scanning.
    if args.replay:
        if not args.scan_id:
            log.error("--replay requires --scan-id")
            return
        from core.state.store import ScanStateStore

        store = ScanStateStore(root_dir=str(args.state_dir))
        loaded = store.load(str(args.scan_id), "results")
        if not loaded:
            log.error("No saved scan results found for scan_id=%s", args.scan_id)
            return
        # Minimal summary for reporting if absent.
        summary = {
            "target": loaded.get("target", "N/A"),
            "scan_type": str(loaded.get("scan_type", "mixed")).upper(),
            "start_time": loaded.get("start_time", ""),
            "duration": loaded.get("duration", 0),
            "total_findings": len(loaded.get("findings", []) or []),
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        }
        for f in loaded.get("findings", []) or []:
            sev = str(f.get("severity", "INFO")).upper()
            if sev in summary["by_severity"]:
                summary["by_severity"][sev] += 1

        # Write reports using existing exporters
        outname = args.output or f"replay_{args.scan_id}"
        gen = ReportGenerator(output_dir="reports")
        exporter = ExportHandler()

        export_formats = (
            [fmt.strip().lower() for fmt in args.format.split(",")]
            if args.format
            else ["html"]
        )
        export_formats = [fmt for fmt in export_formats if fmt]

        if args.no_report:
            log.info("Replay loaded successfully (no-report requested)")
            return

        base = outname
        if "html" in export_formats:
            gen.generate_html_report(loaded, summary, base)
        if "json" in export_formats:
            exporter.export_json(loaded, base)
        if "csv" in export_formats:
            exporter.export_csv(loaded, base)
        if "txt" in export_formats:
            exporter.export_txt(loaded, summary, base)
        log.info("Replay report generation complete")
        return

    # Replay-verify mode: rerun verification only from reproduction contracts.
    if args.replay_verify:
        if not args.scan_id:
            log.error("--replay-verify requires --scan-id")
            return
        from core.state.store import ScanStateStore
        from core.state.reverify import reverify_results
        from core.request_handler import RequestHandler

        store = ScanStateStore(root_dir=str(args.state_dir))
        loaded = store.load(str(args.scan_id), "results")
        if not loaded:
            log.error("No saved scan results found for scan_id=%s", args.scan_id)
            return

        # Optional auth context for verification-only replay (tokens/session supported).
        handler = None
        if any([args.login_url, args.bearer_token, args.api_key, args.session_file]):
            handler = RequestHandler(
                delay=args.delay if args.delay else DEFAULT_DELAY,
                debug_capture=args.debug_capture,
            )
            if args.session_file:
                if not handler.load_session(args.session_file):
                    log.error("Failed to load session")
                    return
            elif args.bearer_token:
                handler.set_bearer_token(args.bearer_token)
            elif args.api_key:
                handler.set_api_key(args.api_key, args.api_key_header)
        else:
            handler = RequestHandler(delay=args.delay if args.delay else DEFAULT_DELAY)

        updated, st = reverify_results(loaded, handler)
        # Persist as a separate key to keep the original scan intact
        store.save(str(args.scan_id), "results_reverify", updated)

        outname = args.output or f"reverify_{args.scan_id}"
        # Minimal summary for reporting
        summary = {
            "target": updated.get("target", "N/A"),
            "scan_type": str(updated.get("scan_type", "mixed")).upper(),
            "start_time": updated.get("start_time", ""),
            "duration": updated.get("duration", 0),
            "total_findings": len(updated.get("findings", []) or []),
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        }
        for f in updated.get("findings", []) or []:
            sev = str(f.get("severity", "INFO")).upper()
            if sev in summary["by_severity"]:
                summary["by_severity"][sev] += 1

        if args.no_report:
            log.info("Replay-verify complete: %s", st)
            return

        gen = ReportGenerator(output_dir="reports")
        exporter = ExportHandler()
        export_formats = (
            [fmt.strip().lower() for fmt in args.format.split(",")]
            if args.format
            else ["html"]
        )
        export_formats = [fmt for fmt in export_formats if fmt]

        if "html" in export_formats:
            gen.generate_html_report(updated, summary, outname)
        if "json" in export_formats:
            exporter.export_json(updated, outname)
        if "csv" in export_formats:
            exporter.export_csv(updated, outname)
        if "txt" in export_formats:
            exporter.export_txt(updated, summary, outname)

        log.info("Replay-verify report generation complete: %s", st)
        return

    # Validate required arguments for live scans
    if not args.target:
        parser.print_help()
        log.error("Target (-t/--target) is required (or use --replay)")
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

    # Apply --only module filter
    if args.only:
        only_modules = [m.strip().lower() for m in args.only.split(",")]
        # Disable all checks
        for key in ["check_directories", "check_headers", "check_cve", 
                    "check_rate_limit", "check_tech_fingerprint", "check_idor",
                    "check_auth_bypass", "check_hpp", "check_js_secrets",
                    "check_subdomain_recon", "check_open_redirect", "check_xss", "check_sqli",
                    "check_crypto_tls", "check_cmd_injection", "check_error_handling"]:
            profile_config[key] = False
        
        # Turn off selective scanning so it doesn't arbitrarily skip explicitly requested modules
        profile_config["selective_scanning"] = False
        
        # Enable specified ones
        module_map = {
            "dir": "check_directories", "dir_enum": "check_directories",
            "headers": "check_headers", "cve": "check_cve",
            "rate_limit": "check_rate_limit", "tech": "check_tech_fingerprint",
            "idor": "check_idor", "auth": "check_auth_bypass", "hpp": "check_hpp",
            "secrets": "check_js_secrets", "subdomain": "check_subdomain_recon",
            "redirect": "check_open_redirect", "sqli": "check_sqli", "xss": "check_xss",
            "sql": "check_sqli", "sqlinjection": "check_sqli",
            "crypto": "check_crypto_tls", "tls": "check_crypto_tls",
            "cmd_injection": "check_cmd_injection", "cmd": "check_cmd_injection",
            "error_handling": "check_error_handling", "error": "check_error_handling"
        }
        for mod in only_modules:
            if mod in module_map:
                profile_config[module_map[mod]] = True
                log.info("Enabled module exclusively: %s", module_map[mod])
            else:
                log.warning("Unknown module in --only: %s", mod)

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
        elite_automation=bool(args.elite),
        oob_base_url=str(args.oob_base_url or ""),
        defensive_variants=bool(args.defensive_variants),
        defensive_variants_strict=not bool(args.defensive_variants_nonstrict),
        state_dir=str(args.state_dir),
        resume=bool(args.resume),
        strict_events=bool(
            args.strict_events
            or os.environ.get("VSCANX_STRICT_EVENTS", "").strip().lower() in ["1", "true", "yes", "y"]
        ),
        rpc_url=args.rpc_url,
        contract=args.contract,
        abi=args.abi,
    )

    # Initialize CLI reporter to catch and style output events
    reporter = CLIReporter(orchestrator.event_bus)

    # Trigger scan.started event
    try:
        orchestrator.event_bus.publish(
            "scan.started",
            {
                "target": args.target,
                "scan_type": args.scan_type,
                "threads": args.threads if args.threads else profile_config.get("max_threads", 10),
                "delay": args.delay if args.delay else profile_config.get("delay", 1.0),
                "profile_name": args.profile,
                "profile_desc": profile_config.get("description"),
            }
        )
    except Exception:
        pass

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

    # Skip report generation if requested
    if args.no_report:
        print_summary(summary, [])
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

    print(f"\n{DIM}[*] Generating reports with base name: {base_filename}{RESET}")

    generator = ReportGenerator()
    exporter = ExportHandler()
    generated_reports = []

    # Single pass over requested formats, ensure each runs exactly once
    for fmt in dict.fromkeys(export_formats):  # preserve order, unique
        fmt = fmt.lower()
        try:
            if fmt == "html":
                html_path = generator.generate_html_report(
                    results, summary, base_filename
                )
                generated_reports.append(html_path)
            elif fmt == "pdf":
                pdf_path = generator.generate_pdf_report(
                    results, summary, base_filename
                )
                if pdf_path:
                    generated_reports.append(pdf_path)
            elif fmt == "json":
                json_path = exporter.export_json(results, base_filename)
                generated_reports.append(json_path)
            elif fmt == "csv":
                csv_path = exporter.export_csv(results, base_filename)
                generated_reports.append(csv_path)
            elif fmt == "txt":
                txt_path = exporter.export_txt(results, summary, base_filename)
                generated_reports.append(txt_path)
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

    # Display beautifully styled summary and report list
    print_summary(summary, generated_reports)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        from core.console import RED, BOLD, RESET
        print(f"\n{RED}{BOLD}[!] Scan aborted by user (Ctrl+C). Exiting...{RESET}\n")
        sys.exit(130)
