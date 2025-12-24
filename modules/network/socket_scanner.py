"""
VScanX Socket-Based Port Scanner (Multi-threaded)
Alternative port scanner using Python sockets with threading
"""

import concurrent.futures
import logging
import socket
from typing import Any, Dict

from core.config import DEFAULT_PORT_RANGE, PORT_SCAN_TIMEOUT
from modules.base_module import BaseModule


class SocketPortScanner(BaseModule):
    """
    Socket-based TCP port scanner with multi-threading
    Works on Windows without Npcap/Scapy
    """

    def __init__(self, max_threads: int = 10):
        super().__init__()
        self.name = "Socket Port Scanner"
        self.description = "TCP port scanning using Python sockets (multi-threaded)"
        self.version = "2.0.0"
        self.open_ports = []
        self.max_threads = max_threads

    def run(
        self,
        target: str,
        port_range: tuple = DEFAULT_PORT_RANGE,
        verbose: bool = False,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Execute port scan on target

        Args:
            target: IP address or hostname to scan
            port_range: Tuple of (start_port, end_port)
            verbose: Enable verbose output

        Returns:
            Dictionary with scan results
        """
        logger = logging.getLogger("vscanx.module.socket_scanner")
        self.clear_results()
        self.open_ports = []
        self.verbose = verbose

        logger.info(
            "socket_scan_start",
            extra={
                "target": target,
                "range": f"{port_range[0]}-{port_range[1]}",
                "threads": self.max_threads,
            },
        )

        start_port, end_port = port_range

        # Resolve hostname to IP if needed
        try:
            resolved_ip = socket.gethostbyname(target)
            if resolved_ip != target:
                logger.info(
                    "socket_scan_resolved", extra={"target": target, "ip": resolved_ip}
                )
            target_ip = resolved_ip
        except socket.gaierror:
            logger.error("socket_scan_resolve_failed", extra={"target": target})
            self.add_result(
                severity="INFO",
                finding="DNS resolution failed",
                details=f"Could not resolve hostname: {target}",
            )
            return {
                "module": self.name,
                "target": target,
                "open_ports": [],
                "findings": self.get_results(),
            }

        # Scan ports using thread pool
        total_ports = end_port - start_port + 1
        scanned = 0

        logger = logging.getLogger("vscanx.module.socket_scanner")

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_threads
        ) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self._scan_port, target_ip, port): port
                for port in range(start_port, end_port + 1)
            }

            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                scanned += 1

                # Progress indicator
                if scanned % 50 == 0 or scanned == total_ports:
                    logger.info(
                        "port_scan_progress",
                        extra={"scanned": scanned, "total": total_ports},
                    )

                try:
                    is_open = future.result()
                    if is_open:
                        self.open_ports.append(port)
                        service = self._identify_service(port)
                        banner = self._grab_banner(target_ip, port)

                        details = f"TCP port {port} is open and responding"
                        if banner:
                            details += f"\nBanner: {banner}"

                        self.add_result(
                            severity="INFO",
                            finding=f"Open port: {port}/{service}",
                            details=details,
                        )
                        logger.info(
                            "port_open", extra={"port": port, "service": service}
                        )
                except Exception as e:
                    if self.verbose:
                        logger.exception("Error scanning port %s: %s", port, e)

        # Sort open ports
        self.open_ports.sort()

        if not self.open_ports:
            logger.info("port_scan_none", extra={"range": f"{start_port}-{end_port}"})
        else:
            logger.info("port_scan_found", extra={"count": len(self.open_ports)})

        return {
            "module": self.name,
            "target": target,
            "open_ports": self.open_ports,
            "findings": self.get_results(),
        }

    def _scan_port(self, target: str, port: int) -> bool:
        """
        Scan a single port using TCP socket

        Args:
            target: IP address
            port: Port number

        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_SCAN_TIMEOUT)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _grab_banner(self, target: str, port: int) -> str:
        """
        Attempt to grab service banner

        Args:
            target: IP address
            port: Port number

        Returns:
            Banner string or empty string
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner[:100] if banner else ""
        except Exception:
            return ""

    def _identify_service(self, port: int) -> str:
        """
        Identify common service on port

        Args:
            port: Port number

        Returns:
            Service name or 'unknown'
        """
        common_services = {
            20: "FTP-Data",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "MS-RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MS-SQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8000: "HTTP-Alt",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
        }
        return common_services.get(port, "unknown")
