from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class Chain:
    title: str
    severity: str
    narrative: str
    supporting_modules: List[str]


class VulnerabilityChainingEngine:
    """
    Correlates independent findings into higher-impact narratives.
    Output is intentionally descriptive (for reports/triage) and does not execute exploits.
    """

    def build_chains(self, findings: List[Dict[str, Any]], modules: List[Dict[str, Any]]) -> List[Chain]:
        modules_present = {m.get("module", "") for m in modules}
        text = " ".join(
            [
                str(f.get("module", "")) + " " + str(f.get("description", "")) + " " + str(f.get("evidence", ""))
                for f in findings
            ]
        ).lower()

        chains: List[Chain] = []

        if "open redirect prober" in {m.lower() for m in modules_present} and "authentication bypass detector" in {
            m.lower() for m in modules_present
        }:
            if "open redirect" in text and "auth bypass" in text:
                chains.append(
                    Chain(
                        title="Redirect-assisted auth flow abuse",
                        severity="HIGH",
                        narrative=(
                            "Open Redirect + auth bypass indicators can combine into phishing-assisted session theft "
                            "or redirect-based OAuth misrouting, depending on the app’s login/redirect flow."
                        ),
                        supporting_modules=["Open Redirect Prober", "Authentication Bypass Detector"],
                    )
                )

        if "js secret analyzer" in {m.lower() for m in modules_present} and "http headers analyzer" in {
            m.lower() for m in modules_present
        }:
            if "potential secret in javascript" in text and "missing security header: content-security-policy" in text:
                chains.append(
                    Chain(
                        title="Client-side secret exposure amplified by weak CSP",
                        severity="CRITICAL",
                        narrative=(
                            "Exposed secrets/endpoints in JS combined with weak/missing CSP increases likelihood of "
                            "XSS-based credential exfiltration or API abuse."
                        ),
                        supporting_modules=["JS Secret Analyzer", "HTTP Headers Analyzer"],
                    )
                )

        if "directory enumerator" in {m.lower() for m in modules_present} and "tech stack fingerprinter" in {
            m.lower() for m in modules_present
        }:
            if "accessible path" in text and ("wordpress" in text or "laravel" in text or "django" in text):
                chains.append(
                    Chain(
                        title="Exposed paths + identifiable stack increases attack surface",
                        severity="MEDIUM",
                        narrative=(
                            "Interesting directories/files combined with stack identification can accelerate "
                            "version-specific exploitation if patching and access control are weak."
                        ),
                        supporting_modules=["Directory Enumerator", "Tech Stack Fingerprinter"],
                    )
                )

        # De-duplicate by title
        uniq: Dict[str, Chain] = {c.title: c for c in chains}
        return list(uniq.values())

