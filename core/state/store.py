from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class ScanStateStore:
    root_dir: str = ".vscanx_state"

    def _path(self, scan_id: str) -> Path:
        safe = "".join(c for c in (scan_id or "default") if c.isalnum() or c in "-_")[:64]
        return Path(self.root_dir) / safe

    def load(self, scan_id: str, key: str) -> Optional[Dict[str, Any]]:
        p = self._path(scan_id) / f"{key}.json"
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None

    def save(self, scan_id: str, key: str, data: Dict[str, Any]) -> str:
        base = self._path(scan_id)
        base.mkdir(parents=True, exist_ok=True)
        p = base / f"{key}.json"
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return str(p)
