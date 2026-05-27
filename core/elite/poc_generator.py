from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class PoC:
    title: str
    severity: str
    command: str
    notes: str = ""


class PoCGenerator:
    """
    Generates safe, reproducible validation commands (primarily curl) for authorized testing.
    This does not generate exploit code or weaponized payloads.
    """

    def generate(self, target: str, findings: List[Dict[str, Any]]) -> List[PoC]:
        pocs: List[PoC] = []
        for f in findings:
            module = str(f.get("module", ""))
            sev = str(f.get("severity", "INFO"))
            desc = str(f.get("description", ""))
            param = str(f.get("parameter", ""))
            evidence = str(f.get("evidence", ""))

            if "Open Redirect" in module or "open redirect" in desc.lower():
                pocs.append(
                    PoC(
                        title="Validate open redirect behavior",
                        severity=sev,
                        command=f"curl -s -I \"{target}\" | sed -n '1,20p'",
                        notes="Confirm 3xx and Location points off-host (no redirects followed).",
                    )
                )
            elif "HTTP Headers Analyzer" in module and "Missing security header" in desc:
                pocs.append(
                    PoC(
                        title="Validate missing security headers",
                        severity=sev,
                        command=f'curl -s -I "{target}"',
                        notes="Review response headers and verify required security headers.",
                    )
                )
            elif "JS Secret Analyzer" in module and "Potential secret" in desc:
                pocs.append(
                    PoC(
                        title="Validate JS secret exposure",
                        severity=sev,
                        command=f'curl -s "{target}" | head -n 50',
                        notes="Locate referenced JS assets and inspect for the matched secret pattern.",
                    )
                )
            elif "Rate Limit Checker" in module:
                pocs.append(
                    PoC(
                        title="Validate rate limiting",
                        severity=sev,
                        command=f'for i in $(seq 1 12); do curl -s -o /dev/null -w "%{{http_code}}\\n" "{target}"; done',
                        notes="Look for 429 responses under burst traffic.",
                    )
                )
            elif "IDOR Detector" in module:
                pocs.append(
                    PoC(
                        title="Validate IDOR parameter mutation",
                        severity=sev,
                        command=f'curl -s -i "{target}" | head -n 40',
                        notes=f"Review object-level authorization for parameter '{param}'. Evidence: {evidence[:100]}",
                    )
                )

        # De-duplicate by command+title
        uniq: Dict[str, PoC] = {}
        for p in pocs:
            uniq[p.title + "|" + p.command] = p
        return list(uniq.values())[:25]
