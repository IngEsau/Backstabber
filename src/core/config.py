from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except Exception:
    yaml = None  # type: ignore


class ConfigError(ValueError):
    pass


class ConfigStore:
    _instance: Optional["ConfigStore"] = None

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "ConfigStore":
        if cls._instance is not None:
            return cls._instance
        path = Path(path or Path.cwd() / "config.yaml")
        if yaml is None:
            raise ConfigError("PyYAML is required to load configuration")
        if not path.exists():
            raise ConfigError(f"Configuration file not found: {path}")
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        if not isinstance(raw, dict):
            raise ConfigError("Configuration file root must be a mapping")
        cls.validate(raw)
        cls._instance = ConfigStore(raw)
        return cls._instance

    @classmethod
    def validate(cls, raw: Dict[str, Any]) -> None:
        if not isinstance(raw, dict):
            raise ConfigError("Configuration must be a dictionary")
        if "app" not in raw or not isinstance(raw["app"], dict):
            raise ConfigError("Missing or invalid 'app' section")
        if "network" in raw and not isinstance(raw["network"], dict):
            raise ConfigError("'network' section must be a mapping")
        if "security" in raw and not isinstance(raw["security"], dict):
            raise ConfigError("'security' section must be a mapping")
        if "paths" in raw and not isinstance(raw["paths"], dict):
            raise ConfigError("'paths' section must be a mapping")
        if "logging" in raw and not isinstance(raw["logging"], dict):
            raise ConfigError("'logging' section must be a mapping")
        sec = raw.get("security", {})
        if not isinstance(sec.get("max_scan_targets", 0), int):
            raise ConfigError("'security.max_scan_targets' must be an integer")
        if not isinstance(sec.get("rate_limit", 0), int):
            raise ConfigError("'security.rate_limit' must be an integer")
        if not isinstance(sec.get("restore_on_exit", True), bool):
            raise ConfigError("'security.restore_on_exit' must be a boolean")
        allowed_ranges = sec.get("allowed_ranges", [])
        if allowed_ranges is not None and not isinstance(allowed_ranges, list):
            raise ConfigError("'security.allowed_ranges' must be a list of CIDR strings")
        excluded_targets = sec.get("excluded_targets", [])
        if excluded_targets is not None and not isinstance(excluded_targets, list):
            raise ConfigError("'security.excluded_targets' must be a list")

    @property
    def security(self) -> Dict[str, Any]:
        return dict(self.raw.get("security", {}))

    @property
    def network(self) -> Dict[str, Any]:
        return dict(self.raw.get("network", {}))

    @property
    def logging(self) -> Dict[str, Any]:
        return dict(self.raw.get("logging", {}))

    @property
    def paths(self) -> Dict[str, Any]:
        return dict(self.raw.get("paths", {}))

    @property
    def max_scan_targets(self) -> int:
        return int(self.security.get("max_scan_targets", 1000))

    @property
    def rate_limit(self) -> int:
        return int(self.security.get("rate_limit", 100))

    @property
    def restore_on_exit(self) -> bool:
        return bool(self.security.get("restore_on_exit", True))

    @property
    def allowed_ranges(self) -> List[str]:
        raw = self.security.get("allowed_ranges")
        if isinstance(raw, list):
            return [str(r) for r in raw if isinstance(r, str)]
        return []

    @property
    def excluded_targets(self) -> List[str]:
        raw = self.security.get("excluded_targets")
        if isinstance(raw, list):
            return [str(r) for r in raw if isinstance(r, str)]
        return []

    def dump(self) -> str:
        return json.dumps(self.raw, indent=2)


def get_config_store(path: Optional[Path] = None) -> ConfigStore:
    return ConfigStore.load(path=path)
