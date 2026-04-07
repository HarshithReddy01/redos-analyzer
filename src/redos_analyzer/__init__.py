from __future__ import annotations

import importlib.util
from pathlib import Path

__version__ = "1.0.0"

_root_module_path = Path(__file__).resolve().parents[2] / "redos_analyzer.py"
if not _root_module_path.exists():
    raise ImportError(f"Expected root module not found: {_root_module_path}")

_spec = importlib.util.spec_from_file_location("_redos_analyzer_root", _root_module_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Unable to load module spec from {_root_module_path}")

_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

ReDoSWarning = _mod.ReDoSWarning
analyze = _mod.analyze
classify_exploitability = _mod.classify_exploitability
suggest_fix = _mod.suggest_fix
verify_fix = _mod.verify_fix
confirm_finding = _mod.confirm_finding
analyze_report = _mod.analyze_report

__all__ = [
    "ReDoSWarning",
    "analyze",
    "classify_exploitability",
    "suggest_fix",
    "verify_fix",
    "confirm_finding",
    "analyze_report",
]
