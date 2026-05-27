"""
VScanX Orchestrator (Phase 3 - With Authentication)
Central coordinator for managing scan workflows with CVE checking and authentication
"""

import logging
import platform
import threading
import asyncio
import time
from datetime import datetime
from typing import Any, Dict, List

from core.metrics import MetricsCollector
from core.request_handler import validate_target
from core.state.store import ScanStateStore
from core.plugins.manager import PluginManager

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
        elite_automation: bool = False,
        oob_base_url: str = "",
        defensive_variants: bool = False,
        defensive_variants_strict: bool = True,
        state_dir: str = ".vscanx_state",
        resume: bool = False,
        strict_events: bool = False,
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
        self.elite_automation = elite_automation
        self.oob_base_url = oob_base_url
        self.defensive_variants = defensive_variants
        self.defensive_variants_strict = defensive_variants_strict
        self.state_store = ScanStateStore(root_dir=state_dir)
        self.resume = resume
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

        # Dynamic module discovery + instantiation (plugin architecture)
        from core.request_handler import RequestHandler

        shared_handler = auth_handler or RequestHandler(
            delay=delay,
            debug_capture=debug_capture,
            max_concurrency=max_threads,
            request_quota=None,
        )
        pm = PluginManager()
        specs = pm.discover()
        # Payload overrides keyed by normalized module name
        payload_overrides = {
            "xss_detector": custom_xss_payloads,
            "sql_injection_detector": custom_sqli_payloads,
        }
        instances = pm.instantiate(
            specs=specs,
            handler=shared_handler,
            max_threads=max_threads,
            custom_payloads=payload_overrides,
        )
        # Keep stable legacy keys for orchestrator scheduling
        # Map by known module names to expected keys
        name_to_key = {getattr(m, "name", ""): k for k, m in instances.items()}
        legacy_map = {
            "XSS Detector": "xss_detect",
            "SQL Injection Detector": "sqli_detect",
            "Directory Enumerator": "dir_enum",
            "HTTP Headers Analyzer": "header_analyzer",
            "CVE Database Checker": "cve_checker",
            "Rate Limit Checker": "rate_limit_checker",
            "Tech Stack Fingerprinter": "tech_fingerprinter",
            "IDOR Detector": "idor_detector",
            "Authentication Bypass Detector": "auth_bypass_detector",
            "HTTP Parameter Pollution Detector": "hpp_detector",
            "JS Secret Analyzer": "js_secret_analyzer",
            "Subdomain Recon Suite": "subdomain_recon",
            "Open Redirect Prober": "open_redirect_prober",
        }
        for friendly_name, legacy_key in legacy_map.items():
            key = name_to_key.get(friendly_name)
            if key and key in instances:
                self.modules[legacy_key] = instances[key]

        self.results = {}
        self.start_time = None
        self.end_time = None
        # Centralized scan result model
        from core.scan_model import Finding, ScanResult

        self._ScanResult = ScanResult
        self._Finding = Finding
        self.scan_result = ScanResult()
        self.metrics = MetricsCollector()
        # Internal pub/sub for scan lifecycle events (used to build an internal scan graph)
        from core.events.bus import EventBus

        self.event_bus = EventBus(strict=bool(strict_events))
        # Default confidence/verification enrichment for findings.
        # This keeps unified schema consistent even when modules don't provide all fields.
        def _default_finding_enricher(_event_type: str, payload: Any) -> Dict[str, Any]:
            try:
                if not isinstance(payload, dict):
                    return {}
                normalized = payload.get("normalized", {})
                if not isinstance(normalized, dict):
                    return {}

                # Only fill missing/empty confidence. Verified can remain None if unknown.
                conf = normalized.get("confidence", "")
                if not conf:
                    severity = (normalized.get("severity") or "INFO").upper()
                    # Coarse prior confidence model until modules provide verifier evidence.
                    if severity == "CRITICAL":
                        conf = "HIGH"
                    elif severity == "HIGH":
                        conf = "MEDIUM"
                    elif severity == "MEDIUM":
                        conf = "LOW"
                    else:
                        conf = "LOW"
                    normalized["confidence"] = conf

                verified = normalized.get("verified", None)
                if verified is None and conf == "HIGH":
                    # If something is marked HIGH confidence, assume it is verified unless explicitly unverified.
                    normalized["verified"] = True

                # Canonical verification state for downstream chaining/correlation.
                if normalized.get("verified") is True:
                    normalized["verification_state"] = "VERIFIED"
                elif normalized.get("verified") is False:
                    normalized["verification_state"] = "REJECTED"
                elif normalized.get("confidence", "") in ["HIGH", "MEDIUM"]:
                    normalized["verification_state"] = "CANDIDATE"
                else:
                    normalized["verification_state"] = "UNVERIFIED"

                # Ensure required unified keys exist for consistent rendering.
                normalized.setdefault("confidence", "")
                normalized.setdefault("verified", normalized.get("verified", None))
                normalized.setdefault("enrichment_history", [])
                normalized["enrichment_history"].append(
                    {
                        "stage": "default_finding_enricher",
                        "ts": datetime.now().isoformat(),
                        "confidence": normalized.get("confidence", ""),
                        "verification_state": normalized.get("verification_state", ""),
                    }
                )
                payload["normalized"] = normalized
                return {"normalized": normalized}
            except Exception:
                return {}

        self.event_bus.subscribe("finding.normalization", _default_finding_enricher)

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
        return asyncio.run(
            self.execute_scan_async(
                target=target,
                scan_type=scan_type,
                port_range=port_range,
                profile_config=profile_config,
            )
        )

    async def execute_scan_async(
        self,
        target: str,
        scan_type: str = "mixed",
        port_range: tuple = None,
        profile_config: Dict = None,
    ) -> Dict[str, Any]:
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
        # Apply traffic budget (quota) now that profile_config is available
        try:
            rq = profile_config.get("request_quota") if profile_config else None
            if rq is not None:
                # shared handler is used by web modules
                if self.auth_handler:
                    self.auth_handler.set_request_quota(int(rq))
                else:
                    # use handler from any web module that exists
                    for mk in ["header_analyzer", "xss_detect", "sqli_detect"]:
                        mod = self.modules.get(mk)
                        h = getattr(mod, "handler", None)
                        if h and hasattr(h, "set_request_quota"):
                            h.set_request_quota(int(rq))
                            break
        except Exception:
            pass
        if scan_type in ["network", "mixed"]:
            if "port_scan" in self.modules:
                await asyncio.to_thread(self._execute_network_scan, target, port_range)
            else:
                logger.warning("Network scanning not available")

        if scan_type in ["web", "mixed"]:
            await self._execute_web_scans_async(target, profile_config)

        # Phase 5: Elite automation post-processing (opt-in)
        if self.elite_automation:
            await asyncio.to_thread(self._run_elite_automation, target)

        # Internal scan graph module (events captured by EventBus)
        try:
            event_log = [
                {"type": e.type, "ts": e.ts, "payload": e.payload}
                for e in self.event_bus.get_event_log()
            ]
            # Summarize skip reasons from module.completed errors.
            skip_reasons: Dict[str, int] = {}
            for e in event_log:
                if e.get("type") != "module.completed":
                    continue
                payload = e.get("payload") or {}
                if not isinstance(payload, dict):
                    continue
                err = str(payload.get("error") or "")
                if err.startswith("skipped:"):
                    reason = err.split("skipped:", 1)[1].strip() or "unknown"
                    skip_reasons[reason] = skip_reasons.get(reason, 0) + 1

            # Grab shared handler telemetry if available
            handler_stats: Dict[str, Any] = {}
            try:
                h = self.auth_handler
                if not h:
                    for mk in ["header_analyzer", "xss_detect", "sqli_detect", "idor_detector"]:
                        mod = self.modules.get(mk)
                        cand = getattr(mod, "handler", None)
                        if cand:
                            h = cand
                            break
                if h and hasattr(h, "get_stats"):
                    handler_stats = h.get_stats()  # type: ignore[assignment]
            except Exception:
                handler_stats = {}

            self._add_module_result(
                {
                    "module": "Internal Scan Graph",
                    "findings": [],
                    "artifacts": {
                        "event_log": event_log,
                        "events": len(event_log),
                        "published_events": getattr(self.event_bus, "published_events", None),
                        "invalid_events": getattr(self.event_bus, "invalid_events", None),
                        "strict": getattr(self.event_bus, "strict", None),
                        "skip_reasons": skip_reasons,
                        "request_handler_stats": handler_stats,
                    },
                }
            )
        except Exception:
            pass

        # Finalize timing
        self.end_time = time.time()
        duration = round(self.end_time - start_timestamp, 2)
        self.scan_result.duration = duration
        self.metrics.observe_duration("scan_total_seconds", duration)
        self.results = self.scan_result.to_dict()

        # Persist full scan result for replay/report regeneration workflows.
        try:
            if self.scan_id:
                self.state_store.save(self.scan_id, "results", self.results)
        except Exception:
            pass

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

    def _run_elite_automation(self, target: str) -> None:
        from core.elite.chaining_engine import VulnerabilityChainingEngine
        from core.elite.defensive_variants import DefensiveVariantGenerator
        from core.elite.oob import OOBManager
        from core.elite.poc_generator import PoCGenerator

        findings = self.scan_result.to_dict().get("findings", [])
        modules = list(self.scan_result.modules)

        # OOB hooks (provision only)
        oob = OOBManager(base_url=self.oob_base_url)
        oob_callback = oob.make_callback("vscanx") if oob.enabled() else ""
        self._add_module_result(
            {
                "module": "OOB Hooks",
                "findings": [],
                "artifacts": {"enabled": oob.enabled(), "callback_url": oob_callback},
            }
        )

        # Chaining engine
        engine = VulnerabilityChainingEngine()
        chains = engine.build_chains(findings=findings, modules=modules)
        for c in chains:
            self.scan_result.findings.append(
                self._Finding(
                    module="Vulnerability Chaining Engine",
                    severity=c.severity,
                    description=c.title,
                    evidence={"summary": c.narrative, "details": c.narrative, "raw": c.narrative},
                    verification_state="CANDIDATE",
                    remediation="Review supporting findings and validate end-to-end authorization boundaries.",
                )
            )
        self._add_module_result(
            {
                "module": "Vulnerability Chaining Engine",
                "findings": [
                    {"severity": c.severity, "finding": c.title, "details": c.narrative}
                    for c in chains
                ],
                "artifacts": {
                    "chain_count": len(chains),
                    "supporting_modules": sorted(
                        {m for c in chains for m in c.supporting_modules}
                    ),
                },
            }
        )

        # PoC generator (safe commands)
        poc_gen = PoCGenerator()
        pocs = poc_gen.generate(target=target, findings=findings)
        self._add_module_result(
            {
                "module": "PoC Generator",
                "findings": [
                    {
                        "severity": p.severity,
                        "finding": p.title,
                        "details": p.command,
                        "evidence": p.notes,
                    }
                    for p in pocs
                ],
                "artifacts": {"poc_count": len(pocs)},
            }
        )

        # Defensive URL normalization variants (optional, separate switch)
        if self.defensive_variants:
            gen = DefensiveVariantGenerator()
            analysis = gen.analyze(
                handler=self.auth_handler or self.modules["header_analyzer"].handler,
                target=target,
                strict=bool(self.defensive_variants_strict),
            )
            if analysis.get("inconsistencies", 0) > 0:
                self._add_module_result(
                    {
                        "module": "Defensive Variant Generator",
                        "findings": [
                            {
                                "severity": "MEDIUM",
                                "finding": "Inconsistent URL normalization behavior",
                                "details": f"Baseline {analysis.get('baseline')} vs variants {analysis.get('variants')}",
                                "remediation": "Ensure consistent canonicalization and routing across normalization variants.",
                            }
                        ],
                        "artifacts": analysis,
                    }
                )
            else:
                self._add_module_result(
                    {
                        "module": "Defensive Variant Generator",
                        "findings": [
                            {
                                "severity": "INFO",
                                "finding": "No URL normalization inconsistencies detected",
                                "details": f"Tested {analysis.get('tested', 0)} variants",
                            }
                        ],
                        "artifacts": analysis,
                    }
                )

    def _add_module_result(self, result: Dict[str, Any]) -> None:
        """Process and store a module's execution result"""
        with self._lock:
            # Fallback for synthetic modules that didn't provide timestamps
            if "start_time" not in result:
                result["start_time"] = datetime.now().isoformat()
            if "end_time" not in result:
                result["end_time"] = datetime.now().isoformat()
            if "duration" not in result:
                try:
                    start = datetime.fromisoformat(result["start_time"])
                    end = datetime.fromisoformat(result["end_time"])
                    result["duration"] = (end - start).total_seconds()
                except Exception:
                    result["duration"] = 0.0
            
            if "modules" not in self.results:
                self.results["modules"] = []
            self.results["modules"].append(result)

        module_name = result.get("module", "Unknown")
        start_time_iso = result.get("start_time", datetime.now().isoformat())
        end_time_iso = result.get("end_time", datetime.now().isoformat())
        duration = result.get("duration", 0.0)

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
        if "artifacts" in result and isinstance(result.get("artifacts"), dict):
            module_meta["artifacts"] = result.get("artifacts")

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
                    "finding_id": str(f.get("finding_id", "")),
                    "finding": str(f.get("finding", "")),
                    "severity": severity,
                    "details": str(f.get("details", "")),
                    "parameter": str(f.get("parameter", "")),
                    "evidence": {
                        "summary": str(f.get("evidence", f.get("details", ""))),
                        "details": str(f.get("details", "")),
                        "raw": f.get("evidence", f.get("details", "")),
                    },
                    "remediation": str(f.get("remediation", "")),
                    "confidence": str(f.get("confidence", "")) if f.get("confidence") is not None else "",
                    "verified": f.get("verified", None),
                    "verification_state": str(f.get("verification_state", "UNVERIFIED")),
                    "verification": f.get("verification", {}) or {},
                    "reproduction": f.get("reproduction", {}) or {},
                    "endpoint": str(result.get("target", "")),
                    "tags": f.get("tags", []) or [],
                    "timestamp": str(f.get("timestamp", datetime.now().isoformat())),
                    "enrichment_history": f.get("enrichment_history", []) or [],
                }

                # Allow event subscribers (verifiers/enrichers) to adjust confidence/verified.
                try:
                    enriched = self.event_bus.publish(
                        "finding.normalization",
                        {"module": module_name, "normalized": normalized, "raw": f},
                    )
                    if isinstance(enriched, dict):
                        normalized = enriched.get("normalized", normalized) or normalized
                except Exception:
                    pass

                module_findings.append(normalized)

                # Also append to the central ScanResult as a Finding dataclass
                finding_obj = self._Finding(
                    module=module_name,
                    severity=severity,
                    description=description,
                    finding_id=str(normalized.get("finding_id", "")),
                    endpoint=str(normalized.get("endpoint", "")),
                    parameter=str(normalized.get("parameter", "")),
                    evidence=normalized.get("evidence", {}) or {},
                    confidence=str(normalized.get("confidence", "")) if normalized.get("confidence") is not None else "",
                    verified=normalized.get("verified", None),
                    verification_state=str(normalized.get("verification_state", "UNVERIFIED")),
                    verification=normalized.get("verification", {}) or {},
                    reproduction=normalized.get("reproduction", {}) or {},
                    tags=normalized.get("tags", []) or [],
                    timestamp=str(normalized.get("timestamp", datetime.now().isoformat())),
                    enrichment_history=normalized.get("enrichment_history", []) or [],
                    remediation=str(normalized.get("remediation", "")),
                )
                self.scan_result.findings.append(finding_obj)
                self.metrics.incr(f"findings.{severity}")
                # Emit internal events for scan-graph reconstruction.
                try:
                    self.event_bus.publish(
                        "finding.added",
                        {
                            "finding_id": finding_obj.finding_id,
                            "module": module_name,
                            "severity": severity,
                            "description": description,
                            "endpoint": finding_obj.endpoint,
                            "parameter": finding_obj.parameter,
                            "confidence": finding_obj.confidence,
                            "verified": finding_obj.verified,
                            "verification_state": finding_obj.verification_state,
                            "verification": finding_obj.verification,
                            "timestamp": finding_obj.timestamp,
                        },
                    )
                except Exception:
                    pass
                try:
                    if finding_obj.verification:
                        self.event_bus.publish(
                            "verification.completed",
                            {
                                "module": module_name,
                                "finding_id": finding_obj.finding_id,
                                "state": finding_obj.verification_state,
                                "confidence": finding_obj.confidence,
                                "verified": finding_obj.verified,
                                "notes": finding_obj.verification.get("notes", ""),
                                "metrics": finding_obj.verification,
                            },
                        )
                except Exception:
                    pass
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
        try:
            self.event_bus.publish(
                "module.completed",
                {"module": module_name, "duration": duration, "error": module_meta.get("error")},
            )
        except Exception:
            pass

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
            try:
                self.event_bus.publish("module.started", {"module": "Port Scanner"})
            except Exception:
                pass
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
            # Attach module spec into artifacts (if present) for UI/reporting.
            try:
                spec = scanner.get_metadata()
                if isinstance(result.get("artifacts"), dict):
                    result["artifacts"].setdefault("module_spec", spec)
                else:
                    result["artifacts"] = {"module_spec": spec}
            except Exception:
                pass
            self._add_module_result(result)

        except Exception as e:
            logger.exception("Network scan error: %s", e)
            self._add_module_result({"module": "Port Scanner", "error": str(e)})

    async def _execute_web_scans_async(
        self, target: str, profile_config: Dict = None
    ) -> None:
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
        run_rate_limit = True
        run_tech_fingerprint = True
        run_idor = True
        run_auth_bypass = True
        run_hpp = True
        run_js_secrets = True
        run_subdomain_recon = True
        run_open_redirect = True
        dir_enum_recursive = False
        run_crawler = True
        crawl_max_urls = 60
        crawl_max_depth = 2
        selective_scanning = True
        module_budget = 9999

        if profile_config:
            run_dir_enum = profile_config.get("check_directories", True)
            run_headers = profile_config.get("check_headers", True)
            run_cve_check = profile_config.get("check_cve", True)
            run_rate_limit = profile_config.get("check_rate_limit", True)
            run_tech_fingerprint = profile_config.get("check_tech_fingerprint", True)
            run_idor = profile_config.get("check_idor", True)
            run_auth_bypass = profile_config.get("check_auth_bypass", True)
            run_hpp = profile_config.get("check_hpp", True)
            run_js_secrets = profile_config.get("check_js_secrets", True)
            run_subdomain_recon = profile_config.get("check_subdomain_recon", True)
            run_open_redirect = profile_config.get("check_open_redirect", True)
            dir_enum_recursive = profile_config.get("dir_enum_recursive", False)
            run_crawler = profile_config.get("crawl_enabled", True)
            crawl_max_urls = int(profile_config.get("crawl_max_urls", 60))
            crawl_max_depth = int(profile_config.get("crawl_max_depth", 2))
            selective_scanning = profile_config.get("selective_scanning", True)
            module_budget = int(profile_config.get("module_budget", 9999))
            run_xss = profile_config.get("check_xss", True)
            run_sqli = profile_config.get("check_sqli", True)
        else:
            run_xss = True
            run_sqli = True

        tasks = []
        remaining_budget = max(0, module_budget)

        def capability_allows(module_key: str) -> tuple[bool, str]:
            runner = self.modules.get(module_key)
            if not runner:
                return False, "missing_module"
            try:
                md = runner.get_metadata() if hasattr(runner, "get_metadata") else {}
            except Exception:
                md = {}
            auth_req = str(md.get("required_auth_state", "any")).lower()
            is_auth = bool(self.auth_handler and self.auth_handler.is_authenticated())
            if auth_req == "authenticated" and not is_auth:
                return False, "auth_required"
            if auth_req == "unauthenticated" and is_auth:
                return False, "requires_unauthenticated_context"
            # Tech compatibility gate: if a module explicitly declares compatible stacks,
            # run only when tech fingerprinting produced at least one signal.
            techs = md.get("compatible_tech_stacks", []) or []
            if techs and module_key != "tech_fingerprinter":
                if not detected_tech_profile.get("has_signals"):
                    return False, "no_tech_signals"
            return True, ""

        def schedule_if_allowed(module_key: str, label: str) -> None:
            nonlocal remaining_budget
            allowed, reason = capability_allows(module_key)
            if not allowed:
                self.event_bus.publish(
                    "module.completed",
                    {"module": label, "error": f"skipped:{reason}"},
                )
                return
            runner = self.modules.get(module_key)
            cost = 1
            try:
                md = runner.get_metadata() if runner and hasattr(runner, "get_metadata") else {}
                cost = max(1, int(md.get("request_cost", 1)))
            except Exception:
                cost = 1
            if cost > remaining_budget:
                self.event_bus.publish(
                    "module.completed",
                    {"module": label, "error": "skipped:budget_exhausted"},
                )
                return
            remaining_budget -= cost
            tasks.append((module_key, label))

        async def run_module(module_key: str, label: str):
            try:
                try:
                    self.event_bus.publish("module.started", {"module": label})
                except Exception:
                    pass
                runner = self.modules[module_key]
                module_start = time.time()
                if hasattr(runner, "run_async"):
                    if module_key == "dir_enum":
                        result = await runner.run_async(
                            target, verbose=self.verbose, recursive=dir_enum_recursive
                        )
                    else:
                        result = await runner.run_async(target, verbose=self.verbose)
                else:
                    result = await asyncio.to_thread(runner.run, target, self.verbose)
                module_end = time.time()
                result.setdefault("module", label)
                result.setdefault(
                    "start_time", datetime.fromtimestamp(module_start).isoformat()
                )
                result.setdefault(
                    "end_time", datetime.fromtimestamp(module_end).isoformat()
                )
                result.setdefault("duration", round(module_end - module_start, 3))
                # Attach module spec/requirements into artifacts for UI/reporting.
                try:
                    spec = runner.get_metadata()
                    if isinstance(result.get("artifacts"), dict):
                        result["artifacts"].setdefault("module_spec", spec)
                    else:
                        result["artifacts"] = {"module_spec": spec}
                except Exception:
                    pass
                self._add_module_result(result)
            except Exception as e:
                logger.exception("%s error: %s", label, e, extra=self._log_extra)
                self._add_module_result({"module": label, "error": str(e)})

        detected_tech_profile: Dict[str, Any] = {}
        if run_tech_fingerprint:
            logger.info("Running Tech Stack Fingerprinter", extra=self._log_extra)
            await run_module("tech_fingerprinter", "Tech Stack Fingerprinter")
            for module_meta in self.scan_result.modules:
                if module_meta.get("module") == "Tech Stack Fingerprinter":
                    if module_meta.get("findings"):
                        detected_tech_profile["has_signals"] = True
                    break

        skip_xss = False
        skip_sqli = False
        skip_idor = False
        skip_hpp = False
        skip_subdomain_recon = False
        skip_open_redirect = False
        if selective_scanning:
            import ipaddress
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(target)
            has_query_params = bool(parse_qs(parsed.query))
            hostname = parsed.hostname or ""
            if not has_query_params:
                skip_xss = True
                skip_sqli = True
                skip_idor = True
                skip_hpp = True
                skip_open_redirect = True
                logger.info(
                    "selective_scan_skip_param_modules",
                    extra={"reason": "no_query_params", **self._log_extra},
                )
            try:
                ipaddress.ip_address(hostname)
                skip_subdomain_recon = True
            except ValueError:
                if not hostname or "." not in hostname:
                    skip_subdomain_recon = True

        # Authenticated crawler (foundational): build URL inventory for better coverage
        crawl_artifacts: Dict[str, Any] = {}
        if run_crawler:
            cached = (
                self.state_store.load(self.scan_id or "default", "crawl")
                if self.resume
                else None
            )
            if cached:
                crawl_artifacts = cached
            else:
                from core.crawl.crawler import AuthenticatedCrawler, CrawlConfig

                crawler = AuthenticatedCrawler(handler=self.auth_handler or self.modules["header_analyzer"].handler)
                crawl_artifacts = await crawler.crawl(
                    target,
                    CrawlConfig(max_urls=crawl_max_urls, max_depth=crawl_max_depth),
                )
                # Persist crawl results for resume workflows
                self.state_store.save(self.scan_id or "default", "crawl", crawl_artifacts)

            self._add_module_result(
                {
                    "module": "Authenticated Crawler",
                    "findings": [
                        {
                            "severity": "INFO",
                            "finding": "Crawl completed",
                            "details": f"Visited {crawl_artifacts.get('visited_count', 0)} URLs",
                        }
                    ],
                    "artifacts": {
                        "visited_count": crawl_artifacts.get("visited_count", 0),
                        "param_urls": len(crawl_artifacts.get("param_urls", []) or []),
                        "forms": len(crawl_artifacts.get("forms", []) or []),
                        "scripts": len(crawl_artifacts.get("scripts", []) or []),
                        "api_endpoints": len(crawl_artifacts.get("api_endpoints", []) or []),
                        "spa_routes": len(crawl_artifacts.get("spa_routes", []) or []),
                        "param_names": len(crawl_artifacts.get("param_names", []) or []),
                    },
                }
            )

            # Publish inventory summary to the scan graph/event bus.
            try:
                self.event_bus.publish(
                    "crawl.inventory_ready",
                    {
                        "visited_count": crawl_artifacts.get("visited_count", 0),
                        "param_urls_count": len(crawl_artifacts.get("param_urls", []) or []),
                        "param_names_count": len(crawl_artifacts.get("param_names", []) or []),
                        "api_endpoints_count": len(crawl_artifacts.get("api_endpoints", []) or []),
                        "spa_routes_count": len(crawl_artifacts.get("spa_routes", []) or []),
                        # Samples only (keeps event log from exploding).
                        "param_urls_sample": list((crawl_artifacts.get("param_urls") or []))[:10],
                        "api_endpoints_sample": list((crawl_artifacts.get("api_endpoints") or []))[:10],
                        "spa_routes_sample": list((crawl_artifacts.get("spa_routes") or []))[:10],
                    },
                )
            except Exception:
                pass

        # Better crawl intelligence: selective parameter-based module scheduling
        # should depend on discovered param-bearing URLs, not only the start URL.
        if selective_scanning:
            has_param_targets = bool(crawl_artifacts.get("param_urls"))
            if not has_param_targets:
                skip_xss = True
                skip_sqli = True
                skip_idor = True
                skip_hpp = True
                skip_open_redirect = True
            else:
                skip_xss = False
                skip_sqli = False
                skip_idor = False
                skip_hpp = False
                skip_open_redirect = False

        if run_headers:
            logger.info("Running HTTP Headers Analyzer", extra=self._log_extra)
            schedule_if_allowed("header_analyzer", "HTTP Headers Analyzer")
        if run_cve_check:
            logger.info("Running CVE Database Checker", extra=self._log_extra)
            schedule_if_allowed("cve_checker", "CVE Database Checker")

        logger.info("Running XSS Detector", extra=self._log_extra)
        if run_xss and not skip_xss:
            schedule_if_allowed("xss_detect", "XSS Detector")

        logger.info("Running SQL Injection Detector", extra=self._log_extra)
        if run_sqli and not skip_sqli:
            schedule_if_allowed("sqli_detect", "SQL Injection Detector")

        if run_rate_limit:
            logger.info("Running Rate Limit Checker", extra=self._log_extra)
            schedule_if_allowed("rate_limit_checker", "Rate Limit Checker")
        if run_auth_bypass:
            logger.info("Running Authentication Bypass Detector", extra=self._log_extra)
            schedule_if_allowed("auth_bypass_detector", "Authentication Bypass Detector")
        if run_idor and not skip_idor:
            logger.info("Running IDOR Detector", extra=self._log_extra)
            schedule_if_allowed("idor_detector", "IDOR Detector")
        if run_hpp and not skip_hpp:
            logger.info("Running HPP Detector", extra=self._log_extra)
            schedule_if_allowed("hpp_detector", "HTTP Parameter Pollution Detector")
        if run_js_secrets:
            logger.info("Running JS Secret Analyzer", extra=self._log_extra)
            schedule_if_allowed("js_secret_analyzer", "JS Secret Analyzer")
        if run_subdomain_recon and not skip_subdomain_recon:
            logger.info("Running Subdomain Recon Suite", extra=self._log_extra)
            schedule_if_allowed("subdomain_recon", "Subdomain Recon Suite")
        if run_open_redirect and not skip_open_redirect:
            logger.info("Running Open Redirect Prober", extra=self._log_extra)
            schedule_if_allowed("open_redirect_prober", "Open Redirect Prober")

        if run_dir_enum:
            logger.info("Running Directory Enumerator", extra=self._log_extra)
            schedule_if_allowed("dir_enum", "Directory Enumerator")

        # Parameter-based modules should run on discovered param URLs, not just the start URL
        param_targets = list((crawl_artifacts.get("param_urls") or []))[:25]
        if param_targets:
            # Expand tasks by injecting per-URL runs for specific modules
            param_module_keys = {"xss_detect", "sqli_detect", "idor_detector", "hpp_detector", "open_redirect_prober"}
            expanded = []
            for key, label in tasks:
                if key in param_module_keys:
                    for u in param_targets:
                        expanded.append((key, f"{label} @ {u}", u))
                else:
                    expanded.append((key, label, target))
            tasks_with_targets = expanded
        else:
            tasks_with_targets = [(k, l, target) for k, l in tasks]

        async def run_module_with_target(module_key: str, label: str, module_target: str):
            nonlocal target
            saved = target
            target = module_target
            try:
                await run_module(module_key, label)
            finally:
                target = saved

        if self.parallel_modules and len(tasks_with_targets) > 1:
            await asyncio.gather(
                *(run_module_with_target(k, l, t) for k, l, t in tasks_with_targets)
            )
        else:
            for key, label, t in tasks_with_targets:
                await run_module_with_target(key, label, t)

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
