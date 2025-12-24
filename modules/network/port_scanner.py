"""
VScanX Port Scanner Module
Safe TCP port scanning using Scapy
"""

import logging
from typing import Any, Dict

from scapy.all import IP, TCP, conf, sr1

from core.config import DEFAULT_PORT_RANGE, PORT_SCAN_TIMEOUT
from modules.base_module import BaseModule

# Disable Scapy verbose output
conf.verb = 0


class PortScanner(BaseModule):
    """
    TCP port scanner module
    Identifies open ports and attempts basic service detection
    """

    def __init__(self):
        super().__init__()
        self.name = "Port Scanner"
        self.description = "TCP port scanning and service detection"
        self.version = "1.0.0"
        self.open_ports = []

    def run(
        self, target: str, port_range: tuple = DEFAULT_PORT_RANGE, **kwargs
    ) -> Dict[str, Any]:
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

        logger.info(
            "port_scan_start",
            extra={"target": target, "range": f"{port_range[0]}-{port_range[1]}"},
        )

        start_port, end_port = port_range

        for port in range(start_port, end_port + 1):
            if self._scan_port(target, port):
                self.open_ports.append(port)
                service = self._identify_service(port)
                self.add_result(
                    severity="INFO",
                    finding=f"Open port: {port}/{service}",
                    details=f"TCP port {port} is open and responding",
                )
                logger.info("port_open", extra={"port": port, "service": service})

        if not self.open_ports:
            logger.info("port_scan_none", extra={"range": f"{start_port}-{end_port}"})

        return {
            "module": self.name,
            "target": target,
            "open_ports": self.open_ports,
            "findings": self.get_results(),
        }

    def _scan_port(self, target: str, port: int) -> bool:
        """
        Scan a single port using TCP SYN

        Args:
            target: IP address
            port: Port number

        Returns:
            True if port is open, False otherwise
        """
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
