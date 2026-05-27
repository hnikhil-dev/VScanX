"""
ANSI terminal styling and visual presentation utilities for VScanX.
No external dependencies (like rich/colorama), purely native escape sequences.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime

# ANSI Color and Formatting Codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def init_console() -> None:
    """Initialize virtual terminal sequence support for Windows."""
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            # Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            # Fallback
            os.system("color")


def print_banner() -> None:
    """Display the beautiful retro red hacker-style banner."""
    init_console()
    banner = f"""{RED}{BOLD}
██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗
██║   ██║██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝
██║   ██║███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝
╚██╗ ██╔╝╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗
 ╚████╔╝ ███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗
  ╚═══╝  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
                 {WHITE}Ethical Vulnerability Scanner{RESET}{RED}{BOLD}
                   Version 2.1.0 (Elite Suite)
========================================================{RESET}"""
    try:
        # Test if stdout can handle unicode block characters
        "█".encode(sys.stdout.encoding or "ascii")
        print(banner)
    except Exception:
        # Fallback to highly-compatible robust ASCII banner
        ascii_banner = f"""{RED}{BOLD}
__      __  _____                             __   __
\\ \\    / / / ____|                            \\ \\ / /
 \\ \\  / / | (___     ___    __ _   _ __        \\ V /
  \\ \\/ /   \\___ \\   / __|  / _` | | '_ \\        > <
   \\  /    ____) | | (__  | (_| | | | | |      / . \\
    \\/    |_____/   \\___|  \\__,_| |_| |_|     /_/ \\_\\

                 {WHITE}Ethical Vulnerability Scanner{RESET}{RED}{BOLD}
                   Version 2.1.0 (Elite Suite)
========================================================{RESET}"""
        print(ascii_banner)


def print_legal_warning() -> None:
    """Display standard legal usage warning."""
    warning = f"""
{YELLOW}{BOLD}[!] LEGAL WARNING [!]{RESET}

This tool is designed for {BOLD}AUTHORIZED{RESET} security testing only.
You must have explicit permission to scan any target system.
Unauthorized scanning may be illegal in your jurisdiction.

By using this tool, you agree to:
  * Only scan systems you own or have written authorization to test
  * Comply with all applicable laws and regulations
  * Accept full responsibility for your actions

The developers assume NO liability for misuse of this tool.
"""
    print(warning)


def print_scan_started(
    target: str, scan_type: str, profile_name: str | None, profile_desc: str | None, threads: int, delay: float
) -> None:
    """Print the structured scan metadata header block."""
    p_name = profile_name.upper() if profile_name else "CUSTOM"
    p_desc = f" ({profile_desc})" if profile_desc else ""

    print(f"\n{CYAN}{BOLD}[*] SCAN INITIALIZED{RESET}")
    print(f"    {BOLD}Target    :{RESET} {target}")
    print(f"    {BOLD}Scan Type :{RESET} {scan_type.upper()}")
    print(f"    {BOLD}Profile   :{RESET} {p_name}{p_desc}")
    print(f"    {BOLD}Threads   :{RESET} {threads}")
    print(f"    {BOLD}Delay     :{RESET} {delay}s")
    print(f"    {BOLD}Started At:{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{DIM}--------------------------------------------------------{RESET}\n")


def print_checking(module_name: str) -> None:
    """Print green high-level checking notification."""
    print(f"{GREEN}[*] Checking:{RESET} {module_name}")


def print_completed(module_name: str, duration: float, error: str | None = None) -> None:
    """Print completed module notification."""
    if error:
        if error.startswith("skipped:"):
            reason = error.split("skipped:", 1)[1]
            print(f"{YELLOW}[-] Skipped:{RESET} {module_name} (Reason: {reason})")
        else:
            print(f"{RED}[!] Failed:{RESET} {module_name} (Error: {error})")
    else:
        print(f"{DIM}[+] Completed:{RESET} {module_name} in {duration}s")


def print_finding(finding: dict) -> None:
    """Print the stylized red vulnerability alert block."""
    severity = str(finding.get("severity", "UNKNOWN")).upper()

    # Silence generic INFO level status events from displaying as scary Vulnerability alerts
    if severity == "INFO":
        return

    module = finding.get("module", "UNKNOWN")
    endpoint = finding.get("endpoint", "UNKNOWN")
    parameter = finding.get("parameter", "")
    evidence = finding.get("evidence")
    description = finding.get("description", "")

    # Clean fallback for empty endpoint/URL
    if not endpoint or str(endpoint).strip() in ("", "None", "N/A"):
        endpoint = "N/A"

    payload_str = "N/A"

    # Check if a specific parameter is highlighted
    if parameter and str(parameter).strip() not in ("", "None", "N/A"):
        payload_str = f"Parameter: {parameter}"

    # Check for evidence details or proof-of-concept payloads
    if evidence:
        if isinstance(evidence, dict):
            if "payload" in evidence and evidence["payload"]:
                payload_str = f"{evidence['payload']}"
            elif "trigger" in evidence and evidence["trigger"]:
                payload_str = f"Trigger: {evidence['trigger']}"
            elif "vector" in evidence and evidence["vector"]:
                payload_str = f"Vector: {evidence['vector']}"
            else:
                payload_str = ", ".join(f"{k}: {v}" for k, v in evidence.items() if v)
        else:
            payload_str = str(evidence)

    # Include description if parameter/evidence is not detailed
    if payload_str == "N/A" and description:
        payload_str = description

    # Style block matching Photoshop layout
    print(f"{RED}{BOLD}[!] Vulnerability Found{RESET}")
    print(f"    {BOLD}Type    :{RESET} {severity} {module}")
    print(f"    {BOLD}URL     :{RESET} {endpoint}")
    print(f"    {BOLD}Payload :{RESET} {payload_str}\n")


def print_summary(summary: dict, report_paths: list[str]) -> None:
    """Print scan completion summary."""
    print(f"\n{CYAN}{BOLD}" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60 + f"{RESET}")
    print(f"Total Findings: {summary.get('total_findings', 0)}")
    by_sev = summary.get("by_severity", {})
    print(f"  {RED}{BOLD}CRITICAL: {by_sev.get('CRITICAL', 0)}{RESET}")
    print(f"  {RED}HIGH:     {by_sev.get('HIGH', 0)}{RESET}")
    print(f"  {YELLOW}MEDIUM:   {by_sev.get('MEDIUM', 0)}{RESET}")
    print(f"  {GREEN}LOW:      {by_sev.get('LOW', 0)}{RESET}")
    print(f"  {WHITE}INFO:     {by_sev.get('INFO', 0)}{RESET}")
    if summary.get("authenticated"):
        print(f"  {CYAN}Authentication: ENABLED{RESET}")
    print(f"{CYAN}{BOLD}" + "=" * 60 + f"{RESET}")

    if report_paths:
        print(f"\n{GREEN}{BOLD}[+] Reports Generated:{RESET}")
        for path in report_paths:
            print(f"  * {path}")
    print(f"\n{GREEN}{BOLD}[+] Scan completed successfully!{RESET}\n")
