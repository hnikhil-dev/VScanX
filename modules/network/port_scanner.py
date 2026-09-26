"""
VScanX Port Scanner Module
Safe TCP port scanning using Scapy
"""

import logging
from typing import Any, Dict

from core.config import DEFAULT_PORT_RANGE, PORT_SCAN_TIMEOUT
from modules.base_module import BaseModule


def _get_scapy():
    """Lazily import Scapy to avoid startup overhead on Windows."""
    try:
        from scapy.all import IP, TCP, conf, sr1

        conf.verb = 0
        return IP, TCP, sr1
    except Exception:
        return None, None, None


class PortScanner(BaseModule):
    """
    TCP port scanner module
    Identifies open ports and attempts basic service detection
    """

    def __init__(self, max_threads: int = 10):
        super().__init__()
        self.name = "Port Scanner"
        self.description = "TCP port scanning and service detection"
        self.version = "1.0.0"
        self.open_ports = []
        self.max_threads = max_threads

    def run(self, target: str, port_range: tuple = DEFAULT_PORT_RANGE, **kwargs) -> Dict[str, Any]:
        """
        Execute port scan on target

        Args:
            target: IP address to scan
            port_range: Tuple of (start_port, end_port)

        Returns:
            Dictionary with scan results
        """
        logger = logging.getLogger("vscanx.module.port_scanner")
        self.clear_results()
        self.open_ports = []

        IP, TCP, sr1 = _get_scapy()
        if IP is None:
            logger.warning("Scapy is not available for PortScanner")
            self.add_result(
                severity="INFO",
                finding="Scapy Not Available",
                details="Scapy is not installed or raw packet creation is not supported on this platform.",
            )
            return {
                "module": self.name,
                "target": target,
                "open_ports": [],
                "findings": self.get_results(),
            }

        # Normalize port range (supports tuple, list, set, or single int)
        if isinstance(port_range, (list, set)):
            ports_to_scan = sorted(list(port_range))
            range_str = f"{len(ports_to_scan)} ports"
        elif isinstance(port_range, tuple) and len(port_range) == 2:
            start_port, end_port = port_range
            ports_to_scan = list(range(start_port, end_port + 1))
            range_str = f"{start_port}-{end_port}"
        elif isinstance(port_range, int):
            ports_to_scan = [port_range]
            range_str = str(port_range)
        else:
            ports_to_scan = list(range(DEFAULT_PORT_RANGE[0], DEFAULT_PORT_RANGE[1] + 1))
            range_str = f"{DEFAULT_PORT_RANGE[0]}-{DEFAULT_PORT_RANGE[1]}"

        logger.info(
            "port_scan_start",
            extra={"target": target, "range": range_str},
        )

        for port in ports_to_scan:
            if self._scan_port(target, port, IP, TCP, sr1):
                self.open_ports.append(port)
                service = self._identify_service(port)
                self.add_result(
                    severity="INFO",
                    finding=f"Open port: {port}/{service}",
                    details=f"TCP port {port} is open and responding",
                )
                logger.info("port_open", extra={"port": port, "service": service})

        if not self.open_ports:
            logger.info("port_scan_none", extra={"range": range_str})

        return {
            "module": self.name,
            "target": target,
            "open_ports": self.open_ports,
            "findings": self.get_results(),
        }

    def _scan_port(self, target: str, port: int, IP=None, TCP=None, sr1=None) -> bool:
        """
        Scan a single port using TCP SYN

        Args:
            target: IP address
            port: Port number

        Returns:
            True if port is open, False otherwise
        """
        if IP is None or TCP is None or sr1 is None:
            IP, TCP, sr1 = _get_scapy()
            if IP is None:
                return False
        try:
            # Create SYN packet
            packet = IP(dst=target) / TCP(dport=port, flags="S")

            # Send packet and wait for response
            response = sr1(packet, timeout=PORT_SCAN_TIMEOUT, verbose=0)

            # Check for SYN-ACK response
            if response and response.haslayer(TCP):
                if response[TCP].flags == "SA":  # SYN-ACK
                    # Send RST to close connection gracefully
                    rst_packet = IP(dst=target) / TCP(dport=port, flags="R")
                    sr1(rst_packet, timeout=1, verbose=0)
                    return True

            return False
        except Exception:
            # Silently handle errors for individual ports
            return False

    def _identify_service(self, port: int) -> str:
        """
        Identify common service on port

        Args:
            port: Port number

        Returns:
            Service name or 'unknown'
        """
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
        }

        return common_services.get(port, "unknown")
