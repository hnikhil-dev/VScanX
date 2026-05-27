from __future__ import annotations

import importlib
import inspect
import pkgutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from modules.base_module import BaseModule


@dataclass
class ModuleSpec:
    key: str
    cls: Type[BaseModule]
    name: str
    version: str
    description: str
    origin: str


class PluginManager:
    """
    Discovers and loads modules dynamically.

    - Built-ins: `modules.web.*` and `modules.network.*`
    - Optional external plugins: `plugins/*.py` at repo root (simple, explicit convention)
    """

    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = plugins_dir

    def discover(self) -> List[ModuleSpec]:
        specs: List[ModuleSpec] = []
        specs.extend(self._discover_package("modules.web"))
        specs.extend(self._discover_package("modules.network"))
        specs.extend(self._discover_package("modules.web3"))
        specs.extend(self._discover_package("modules.agentic"))
        specs.extend(self._discover_plugins_dir(self.plugins_dir))

        # Dedup by key, prefer built-in over external if collision
        uniq: Dict[str, ModuleSpec] = {}
        for s in specs:
            if s.key not in uniq:
                uniq[s.key] = s
        return list(uniq.values())

    def instantiate(
        self,
        specs: List[ModuleSpec],
        handler=None,
        max_threads: int = 10,
        custom_payloads: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, BaseModule]:
        instances: Dict[str, BaseModule] = {}
        custom_payloads = custom_payloads or {}
        for s in specs:
            kwargs = {}
            # Common DI patterns supported by built-in modules
            sig = inspect.signature(s.cls.__init__)
            if "handler" in sig.parameters:
                kwargs["handler"] = handler
            if "max_threads" in sig.parameters:
                kwargs["max_threads"] = max(2, int(max_threads // 2))
            if "custom_payloads" in sig.parameters:
                # Payload overrides by key
                if s.key in custom_payloads:
                    kwargs["custom_payloads"] = custom_payloads[s.key]

            try:
                instances[s.key] = s.cls(**kwargs)  # type: ignore[arg-type]
            except Exception:
                # Skip broken plugin gracefully
                continue
        return instances

    def _discover_package(self, pkg_name: str) -> List[ModuleSpec]:
        specs: List[ModuleSpec] = []
        try:
            pkg = importlib.import_module(pkg_name)
        except Exception:
            return specs

        for _, mod_name, is_pkg in pkgutil.iter_modules(getattr(pkg, "__path__", [])):
            if is_pkg:
                continue
            full = f"{pkg_name}.{mod_name}"
            try:
                m = importlib.import_module(full)
            except Exception:
                continue
            specs.extend(self._extract_module_specs(m, origin=full))
        return specs

    def _discover_plugins_dir(self, plugins_dir: str) -> List[ModuleSpec]:
        specs: List[ModuleSpec] = []
        root = Path(plugins_dir)
        if not root.exists() or not root.is_dir():
            return specs
        for py in root.glob("*.py"):
            if py.name.startswith("_"):
                continue
            # Import as a module via file path by temporarily adding parent to sys.path
            try:
                module_name = f"plugins.{py.stem}"
                spec = importlib.util.spec_from_file_location(module_name, str(py))
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
                    specs.extend(self._extract_module_specs(mod, origin=str(py)))
            except Exception:
                continue
        return specs

    def _extract_module_specs(self, module, origin: str) -> List[ModuleSpec]:
        specs: List[ModuleSpec] = []
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj is BaseModule:
                continue
            if not issubclass(obj, BaseModule):
                continue
            try:
                inst = obj()  # best-effort metadata extraction
                name = getattr(inst, "name", obj.__name__)
                version = getattr(inst, "version", "0.0.0")
                desc = getattr(inst, "description", "")
            except Exception:
                name = obj.__name__
                version = "0.0.0"
                desc = ""
            key = self._key_from_name(name)
            specs.append(ModuleSpec(key=key, cls=obj, name=name, version=version, description=desc, origin=origin))
        return specs

    def _key_from_name(self, name: str) -> str:
        key = "".join(c.lower() if c.isalnum() else "_" for c in (name or "")).strip("_")
        while "__" in key:
            key = key.replace("__", "_")
        return key or "module"
