"""
VScanX Quick Fix Script
Fixes common Windows issues
"""

import os


def check_structure():
    """Verify project structure"""
    print("[*] Checking project structure...")

    required_dirs = [
        "core",
        "modules",
        "modules/network",
        "modules/web",
        "reporting",
        "reporting/templates",
        "reports",
    ]

    for dir_path in required_dirs:
        if not os.path.exists(dir_path):
            print(f"[!] Missing directory: {dir_path}")
            os.makedirs(dir_path, exist_ok=True)
            print(f"[+] Created: {dir_path}")
        else:
            print(f"[✓] Found: {dir_path}")

    # Check for report template
    template_file = "reporting/templates/report.html"
    if os.path.exists(template_file):
        print(f"[✓] Template file exists: {template_file}")
    else:
        print(f"[!] Missing template file: {template_file}")
        print("[!] Please ensure report.html is in reporting/templates/")


def check_scapy():
    """Check Scapy installation"""
    print("\n[*] Checking Scapy/Npcap...")
    try:
        from scapy.all import conf

        print("[✓] Scapy imported successfully")
        print(f"[*] Available interfaces: {len(conf.ifaces)}")
        if len(conf.ifaces) > 0:
            print("[✓] Npcap appears to be working")
        else:
            print("[!] No network interfaces found - Npcap may not be installed")
            print("[*] Download Npcap from: https://npcap.com/#download")
    except Exception as e:
        print(f"[!] Scapy error: {e}")
        print("[*] Socket-based scanner will be used instead")


def main():
    print("VScanX Fix Issues Script\n")
    check_structure()
    check_scapy()
    print("\n[+] Checks complete!")


if __name__ == "__main__":
    main()
