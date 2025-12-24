"""
VScanX Orchestrator (Phase 3 - With Authentication)
Central coordinator for managing scan workflows with CVE checking and authentication
"""

import logging
import platform
import threading
import time
from datetime import datetime
from typing import Any, Dict, List

from core.metrics import MetricsCollector
from core.request_handler import validate_target
from modules.web.cve_checker import CVEChecker
from modules.web.dir_enum import DirectoryEnumerator
from modules.web.header_analyzer import HeaderAnalyzer
from modules.web.sqli_detector import SQLiDetector

# Web vulnerability modules (imported at module level)
from modules.web.xss_detector import XSSDetector

logger = logging.getLogger("vscanx.orchestrator")

# Prefer socket scanner on Windows, Scapy on Linux/Mac
IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    try:
        from modules.network.socket_scanner import SocketPortScanner as PortScanner

        SCAPY_AVAILABLE = False
        logger.info("Using socket-based port scanner (Windows optimized)")
    except ImportError:
        try:
            from modules.network.port_scanner import PortScanner

            SCAPY_AVAILABLE = True
            logger.info("Using Scapy-based port scanner")
        except Exception:
            logger.error("No port scanner module available")
            PortScanner = None
else:
    try:
        from modules.network.port_scanner import PortScanner

        SCAPY_AVAILABLE = True
        logger.info("Using Scapy-based port scanner")
    except Exception:
        try:
            from modules.network.socket_scanner import SocketPortScanner as PortScanner

            SCAPY_AVAILABLE = False
            logger.info("Using socket-based port scanner")
        except ImportError:
            logger.error("No port scanner module available")
            PortScanner = None


class Orchestrator:
    """
    Central orchestrator that coordinates all scanning modules
    Manages workflow, aggregates results, handles errors, and supports authentication
    """

    def __init__(
        self,
        custom_xss_payloads: List[str] = None,
        custom_sqli_payloads: List[str] = None,
        max_threads: int = 10,
        delay: float = None,
        verbose: bool = False,
        auth_handler=None,
        scan_id: str = None,
        parallel_modules: bool = False,
        debug_capture: bool = False,
    ):
        """
        Initialize orchestrator with available modules and optional authentication

        Args:
            custom_xss_payloads: Custom XSS payloads
            custom_sqli_payloads: Custom SQLi payloads
            max_threads: Maximum threads for scanning
            delay: Delay between requests
            verbose: Enable verbose output
            auth_handler: Authenticated RequestHandler (optional)
        """
        self.modules = {}
        self.verbose = verbose
        self.max_threads = max_threads
        self.delay = delay
        self.auth_handler = auth_handler
        self.scan_id = scan_id
        self.parallel_modules = parallel_modules
        self.debug_capture = debug_capture
        self._log_extra = {"scan_id": scan_id} if scan_id else {}
        # Thread-safety for adding module results
        self._lock = threading.Lock()
        logger.debug(
            "Orchestrator initialized (auth=%s, max_threads=%d)",
            bool(auth_handler),
            max_threads,
        )

        # Add port scanner if available
        if PortScanner is not None:
            self.modules["port_scan"] = PortScanner(max_threads=max_threads)
        else:
            logger.warning("Port scanning module not available")

        # Add web vulnerability modules with optional authentication
        if auth_handler:
            logger.info("Using authenticated session for web scans")
            self.modules["xss_detect"] = XSSDetector(
                custom_payloads=custom_xss_payloads, handler=auth_handler
            )
            self.modules["sqli_detect"] = SQLiDetector(
                custom_payloads=custom_sqli_payloads, handler=auth_handler
            )
            self.modules["dir_enum"] = DirectoryEnumerator(
                max_threads=max(5, max_threads // 2), handler=auth_handler
            )
            self.modules["header_analyzer"] = HeaderAnalyzer(handler=auth_handler)
            self.modules["cve_checker"] = CVEChecker(handler=auth_handler)
        else:
            # Use default handlers
            from core.request_handler import RequestHandler

            default_handler = RequestHandler(delay=delay, debug_capture=debug_capture)
            self.modules["xss_detect"] = XSSDetector(
                custom_payloads=custom_xss_payloads, handler=default_handler
            )
            self.modules["sqli_detect"] = SQLiDetector(
                custom_payloads=custom_sqli_payloads, handler=default_handler
            )
            self.modules["dir_enum"] = DirectoryEnumerator(
                max_threads=max(5, max_threads // 2), handler=default_handler
            )
            self.modules["header_analyzer"] = HeaderAnalyzer(handler=default_handler)
            self.modules["cve_checker"] = CVEChecker(handler=default_handler)

        self.results = {}
        self.start_time = None
        self.end_time = None
        # Centralized scan result model
        from core.scan_model import Finding, ScanResult

        self._ScanResult = ScanResult
        self._Finding = Finding
        self.scan_result = ScanResult()
        self.metrics = MetricsCollector()

    def execute_scan(
        self,
        target: str,
        scan_type: str = "mixed",
        port_range: tuple = None,
        profile_config: Dict = None,
    ) -> Dict[str, Any]:
        """
        Execute scan based on type

        Args:
            target: Target URL or IP
            scan_type: 'web', 'network', or 'mixed'
            port_range: Port range for network scan (optional)
            profile_config: Profile configuration (optional)

        Returns:
            Aggregated scan results
        """
        log_extra = {"target": target, "scan_type": scan_type, **self._log_extra}
        logger.info("start_scan", extra=log_extra)
        if profile_config:
            logger.info("profile_applied", extra={"profile": True, **self._log_extra})
        if self.auth_handler and self.auth_handler.is_authenticated():
            logger.info("auth_enabled", extra={"target": target, **self._log_extra})

        # Initialize timing and scan_result
        start_timestamp = time.time()
        self.start_time = start_timestamp
        self.scan_result = self._ScanResult(
            target=target,
            scan_type=scan_type,
            authenticated=(
                self.auth_handler.is_authenticated() if self.auth_handler else False
            ),
            start_time=datetime.now().isoformat(),
            findings=[],
            modules=[],
            errors=[],
        )
        self.results = self.scan_result.to_dict()  # keep backward compatibility

        # Validate target
        if not validate_target(target):
            logger.error("invalid_target", extra={"target": target, **self._log_extra})
            self.scan_result.errors.append("Invalid target format")
            self.results = self.scan_result.to_dict()
            return self.results

        # Execute scans based on type
        if scan_type in ["network", "mixed"]:
            if "port_scan" in self.modules:
                self._execute_network_scan(target, port_range)
            else:
                logger.warning("Network scanning not available")

        if scan_type in ["web", "mixed"]:
            self._execute_web_scans(target, profile_config)

        # Finalize timing
        self.end_time = time.time()
        duration = round(self.end_time - start_timestamp, 2)
        self.scan_result.duration = duration
        self.metrics.observe_duration("scan_total_seconds", duration)
        self.results = self.scan_result.to_dict()

        # Schema validation for safety before returning
        try:
            from core.utils import validate_scan_result_schema

            validate_scan_result_schema(self.results)
        except Exception as exc:
            logger.error("scan_result_schema_invalid", extra={"error": str(exc)})
            self.scan_result.errors.append(str(exc))
            self.results = self.scan_result.to_dict()

        logger.info(
            "scan_completed",
            extra={
                "target": target,
                "duration": self.scan_result.duration,
                "scan_type": scan_type,
                "metrics": self.metrics.to_dict(),
            },
        )

        return self.results

    def _add_module_result(self, result: dict) -> None:
        """Thread-safe normalization and addition of a module result into the central ScanResult."""
        if not isinstance(result, dict):
            logger.warning("Ignoring non-dict module result: %r", result)
            return

        module_name = result.get("module", "Unknown")
        start_time_iso = result.get("start_time", datetime.now().isoformat())
        end_time_iso = result.get("end_time", datetime.now().isoformat())
        duration = result.get("duration")

        module_meta = {
            "module": module_name,
            "start_time": start_time_iso,
            "end_time": end_time_iso,
        }
        if duration is not None:
            try:
                module_meta["duration"] = float(duration)
                self.metrics.observe_duration(
                    f"module.{module_name}.seconds", float(duration)
                )
            except (TypeError, ValueError):
                logger.warning("invalid_module_duration", extra={"module": module_name})
        if "error" in result:
            module_meta["error"] = result.get("error")
            self.metrics.incr(f"module.{module_name}.errors")

        findings = result.get("findings", [])
        if not isinstance(findings, list):
            logger.error("module_findings_not_list", extra={"module": module_name})
            self.scan_result.errors.append(
                f"Module {module_name} returned invalid findings"
            )
            return

        # Build a module-specific findings list (ensure keys exist and are safe to render)
        module_findings = []
        for f in findings:
            try:
                # Normalize severity and description
                description = (
                    f.get("finding") or f.get("description") or f.get("details") or ""
                )
                severity = (f.get("severity") or "INFO").upper()
                if severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    severity = "INFO"

                # Build a safe, explicit dict for template consumption
                normalized = {
                    "finding": str(f.get("finding", "")),
                    "severity": severity,
                    "details": str(f.get("details", "")),
                    "parameter": str(f.get("parameter", "")),
                    "evidence": str(f.get("evidence", f.get("details", ""))),
                    "remediation": str(f.get("remediation", "")),
                }

                module_findings.append(normalized)

                # Also append to the central ScanResult as a Finding dataclass
                finding_obj = self._Finding(
                    module=module_name,
                    severity=severity,
                    description=description,
                    parameter=f.get("parameter", ""),
                    evidence=f.get("details", ""),
                    remediation=f.get("remediation", ""),
                )
                self.scan_result.findings.append(finding_obj)
                self.metrics.incr(f"findings.{severity}")
            except Exception as e:
                logger.exception(
                    "Failed to normalize finding from %s: %s", module_name, e
                )
                self.scan_result.errors.append(
                    f"Normalization error in module {module_name}: {e}"
                )

        # Attach normalized findings back to the module metadata for per-module rendering in templates
        module_meta["findings"] = module_findings

        with self._lock:
            self.scan_result.modules.append(module_meta)

    def _execute_network_scan(self, target: str, port_range: tuple = None) -> None:
        """
        Execute network-based scans

        Args:
            target: IP address or URL
            port_range: Port range to scan
        """
        logger.info("Executing Network Scan Module")
        logger.debug("%s", "=" * 60)

        try:
            # Extract IP from URL if needed
            if target.startswith(("http://", "https://")):
                import socket
                from urllib.parse import urlparse

                parsed = urlparse(target)

                # Extract hostname without port
                hostname = (
                    parsed.hostname if parsed.hostname else parsed.netloc.split(":")[0]
                )

                try:
                    target_ip = socket.gethostbyname(hostname)
                    print(f"[*] Resolved {hostname} to {target_ip}")
                except socket.gaierror:
                    print(f"[!] Failed to resolve {hostname}")
                    self._add_module_result(
                        {
                            "module": "Port Scanner",
                            "error": f"Failed to resolve hostname: {hostname}",
                        }
                    )
                    return
            else:
                target_ip = target

            # Run port scanner
            scanner = self.modules["port_scan"]
            module_start = time.time()
            if port_range:
                result = scanner.run(
                    target_ip, port_range=port_range, verbose=self.verbose
                )
            else:
                result = scanner.run(target_ip, verbose=self.verbose)
            module_end = time.time()
            result.setdefault("module", "Port Scanner")
            result.setdefault(
                "start_time", datetime.fromtimestamp(module_start).isoformat()
            )
            result.setdefault(
                "end_time", datetime.fromtimestamp(module_end).isoformat()
            )
            result.setdefault("duration", round(module_end - module_start, 3))
            self._add_module_result(result)

        except Exception as e:
            logger.exception("Network scan error: %s", e)
            self._add_module_result({"module": "Port Scanner", "error": str(e)})

    def _execute_web_scans(self, target: str, profile_config: Dict = None) -> None:
        """
        Execute all web-based scans

        Args:
            target: Target URL
            profile_config: Profile configuration
        """
        logger.info("Executing Web Scan Modules")
        logger.debug("%s", "=" * 60)

        # Ensure target has scheme
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        # Determine which modules to run based on profile
        run_dir_enum = True
        run_headers = True
        run_cve_check = True

        if profile_config:
            run_dir_enum = profile_config.get("check_directories", True)
            run_headers = profile_config.get("check_headers", True)
            run_cve_check = profile_config.get("check_cve", True)

        tasks = []

        def run_module(module_key: str, label: str):
            try:
                runner = self.modules[module_key]
                module_start = time.time()
                result = runner.run(target, verbose=self.verbose)
                module_end = time.time()
                result.setdefault("module", label)
                result.setdefault(
                    "start_time", datetime.fromtimestamp(module_start).isoformat()
                )
                result.setdefault(
                    "end_time", datetime.fromtimestamp(module_end).isoformat()
                )
                result.setdefault("duration", round(module_end - module_start, 3))
                self._add_module_result(result)
            except Exception as e:
                logger.exception("%s error: %s", label, e, extra=self._log_extra)
                self._add_module_result({"module": label, "error": str(e)})

        if run_headers:
            logger.info("Running HTTP Headers Analyzer", extra=self._log_extra)
            tasks.append(("header_analyzer", "HTTP Headers Analyzer"))
        if run_cve_check:
            logger.info("Running CVE Database Checker", extra=self._log_extra)
            tasks.append(("cve_checker", "CVE Database Checker"))

        logger.info("Running XSS Detector", extra=self._log_extra)
        tasks.append(("xss_detect", "XSS Detector"))

        logger.info("Running SQL Injection Detector", extra=self._log_extra)
        tasks.append(("sqli_detect", "SQL Injection Detector"))

        if run_dir_enum:
            logger.info("Running Directory Enumerator", extra=self._log_extra)
            tasks.append(("dir_enum", "Directory Enumerator"))

        if self.parallel_modules and len(tasks) > 1:
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(len(tasks), self.max_threads)
            ) as executor:
                futures = [
                    executor.submit(run_module, key, label) for key, label in tasks
                ]
                for f in futures:
                    f.result()
        else:
            for key, label in tasks:
                run_module(key, label)

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate summary statistics from results

        Returns:
            Summary dictionary with counts and statistics
        """
        summary = {
            "total_findings": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "modules_run": len(self.scan_result.modules),
            "by_module": {},
            "authenticated": self.scan_result.authenticated,
            "target": self.scan_result.target,
            "scan_type": self.scan_result.scan_type,
            "start_time": self.scan_result.start_time,
            "duration": self.scan_result.duration,
        }

        # Count per-module findings and severity
        # Count findings from centralized list to avoid module mismatch
        for finding in self.scan_result.findings:
            summary["total_findings"] += 1
            summary["by_module"][finding.module] = (
                summary["by_module"].get(finding.module, 0) + 1
            )
            severity = getattr(finding, "severity", "INFO")
            if severity in summary["by_severity"]:
                summary["by_severity"][severity] += 1

        return summary
