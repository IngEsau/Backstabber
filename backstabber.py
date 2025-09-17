#!/usr/bin/env python3
"""
Backstabber Toolkit - Bootstrap / initializer script

This script loads configuration (YAML), validates environment and dependencies,
prepares runtime directories/logging, and launches the main application entrypoint.

It tries several import strategies and falls back to running a subprocess
that executes the target module in a robust environment (helpful for GUI modules
that rely on a particular sys.path layout).
"""
from __future__ import annotations

import argparse
import importlib
import logging
import os
import re
import runpy
import shlex
import shutil
import subprocess
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except Exception:
    yaml = None  # type: ignore

# ---------------------------
# Helpers
# ---------------------------
def is_running_as_root() -> bool:
    if os.name == "nt":
        try:
            import ctypes  # type: ignore
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.geteuid() == 0

def parse_package_name(spec: str) -> str:
    """Return the base package token from a pip-style requirement string."""
    return re.split(r"[<>=!~\[\]]", spec, maxsplit=1)[0].strip()

def importable(spec: str) -> bool:
    """
    Robust check whether the requirement string corresponds to an importable module.

    It tries several candidate module names and also some common known mappings.
    """
    import importlib.util

    raw = parse_package_name(spec)
    candidates = [raw, raw.lower(), raw.replace("-", "_"), raw.lower().replace("-", "_")]

    # Common special cases mapping pip name -> import name
    mappings = {
        "pyyaml": "yaml",
        "python3-nmap": "nmap3",
        "python-nmap": "nmap",
        "python3_nmap": "nmap3",
        "pyqt5": "PyQt5",
    }
    mapped = mappings.get(raw.lower())
    if mapped:
        candidates.append(mapped)

    seen = set()
    for c in candidates:
        if not c or c in seen:
            continue
        seen.add(c)
        try:
            if importlib.util.find_spec(c) is not None:
                return True
        except Exception:
            pass
        try:
            __import__(c)
            return True
        except Exception:
            pass
    return False

def system_tool_available(name: str) -> bool:
    return shutil.which(name) is not None

# ---------------------------
# Config dataclass
# ---------------------------
@dataclass
class InitializerConfig:
    raw: Dict[str, Any]

    @property
    def app_entry(self) -> str:
        return str(self.raw.get("app", {}).get("main_module", "main"))

    @property
    def required_packages(self) -> List[str]:
        return list(self.raw.get("dependencies", {}).get("required_packages", []))

    @property
    def system_tools(self) -> List[str]:
        return list(self.raw.get("dependencies", {}).get("system_tools", []))

    @property
    def paths(self) -> Dict[str, str]:
        return dict(self.raw.get("paths", {}))

    @property
    def logging(self) -> Dict[str, Any]:
        return dict(self.raw.get("logging", {}))

    @property
    def security(self) -> Dict[str, Any]:
        return dict(self.raw.get("security", {}))

# ---------------------------
# Main initializer
# ---------------------------
class BackstabberInitializer:
    def __init__(self, config_path: Path = Path("config.yaml")):
        self.config_path = Path(config_path)
        self.config = InitializerConfig(raw={})
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("backstabber.init")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            ch = logging.StreamHandler()
            ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            logger.addHandler(ch)
        return logger

    def load_config(self) -> bool:
        if yaml is None:
            self.logger.error("PyYAML is not installed; please install pyyaml to use YAML configuration.")
            return False
        if not self.config_path.exists():
            self.logger.error("Configuration file not found: %s", self.config_path)
            return False
        try:
            with self.config_path.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            if not isinstance(raw, dict):
                self.logger.error("Configuration file root must be a mapping (dictionary).")
                return False
            self.config = InitializerConfig(raw=raw)
            self.logger.info("Configuration loaded from %s", self.config_path)
            return True
        except Exception:
            self.logger.exception("Failed to load/parse configuration")
            return False

    def validate_config(self) -> bool:
        raw = self.config.raw
        # minimal validation
        if "app" not in raw:
            self.logger.error("Missing 'app' section in configuration.")
            return False
        # optional python version check
        spec = self.config.raw.get("dependencies", {}).get("python_version", "")
        if isinstance(spec, str) and spec.startswith(">="):
            try:
                min_major, min_minor = map(int, spec[2:].split(".")[:2])
                if sys.version_info[:2] < (min_major, min_minor):
                    self.logger.error("Python %d.%d+ required by config; current %s", min_major, min_minor, ".".join(map(str, sys.version_info[:2])))
                    return False
            except Exception:
                pass
        self.logger.info("Configuration validated.")
        return True

    def check_dependencies(self, warn_only: bool = True) -> bool:
        ok = True
        missing_pkgs = []
        for pkg in self.config.required_packages:
            if not importable(pkg):
                missing_pkgs.append(pkg)
        if missing_pkgs:
            msg = "Missing Python packages: " + ", ".join(missing_pkgs)
            if warn_only:
                self.logger.warning("%s (continuing because warn_only=True)", msg)
            else:
                self.logger.error(msg)
                ok = False
        else:
            self.logger.info("All Python package dependencies appear importable.")
        missing_tools = [t for t in self.config.system_tools if not system_tool_available(t)]
        if missing_tools:
            msg = "Missing system tools: " + ", ".join(missing_tools)
            if warn_only:
                self.logger.warning("%s (continuing because warn_only=True)", msg)
            else:
                self.logger.error(msg)
                ok = False
        else:
            if self.config.system_tools:
                self.logger.info("All required system tools available.")
        return ok

    def setup_environment(self) -> bool:
        try:
            paths = self.config.paths or {}
            defaults = {"logs": "logs", "temp": "temp", "output": "output"}
            for key, default in defaults.items():
                d = Path(paths.get(key, default)).expanduser().resolve()
                d.mkdir(parents=True, exist_ok=True)
                self.logger.debug("Ensured directory: %s", d)
            log_cfg = self.config.logging or {}
            level = getattr(logging, str(log_cfg.get("level", "INFO")).upper(), logging.INFO)
            log_format = log_cfg.get("format", "%(asctime)s %(levelname)s %(name)s: %(message)s")
            root = logging.getLogger()
            root.setLevel(level)
            for h in list(root.handlers):
                root.removeHandler(h)
            sh = logging.StreamHandler()
            sh.setFormatter(logging.Formatter(log_format))
            root.addHandler(sh)
            # rotating file handler optional
            try:
                from logging.handlers import RotatingFileHandler
                logfile = Path(paths.get("logs", "logs")) / "backstabber.log"
                fh = RotatingFileHandler(logfile, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
                fh.setFormatter(logging.Formatter(log_format))
                fh.setLevel(level)
                root.addHandler(fh)
            except Exception:
                self.logger.debug("Could not install rotating file handler")
            self.logger.info("Runtime environment prepared.")
            return True
        except Exception:
            self.logger.exception("Failed to prepare runtime environment.")
            return False

    def check_permissions(self) -> bool:
        sec = self.config.security or {}
        require_root = bool(sec.get("require_root", False))
        if require_root and not is_running_as_root():
            self.logger.warning("Config requests root; consider running with elevated privileges.")
        allowed_ifaces = sec.get("allowed_interfaces", [])
        if allowed_ifaces:
            try:
                import netifaces  # optional
                available = netifaces.interfaces()
                present = [i for i in allowed_ifaces if i in available]
                if not present:
                    self.logger.warning("None of the configured allowed interfaces are present: %s", allowed_ifaces)
                else:
                    self.logger.info("Allowed interfaces present: %s", present)
            except Exception:
                self.logger.warning("netifaces not installed; skipping interface checks.")
        return True

    def launch_application(self) -> bool:
        """
        Launch the configured application entrypoint.

        Strategy:
        1. Try importing configured module(s) and invoking `main()` when present.
        2. If import/call fails, or if the configured module is not present,
            fall back to executing 'src/main.py' as a subprocess (this mirrors
            running `python3 src/main.py` directly which we have verified works).
        """
        entry = str(self.config.app_entry)
        self.logger.info("Launching application entry: %s", entry)

        project_root = Path.cwd()
        src_dir = project_root / "src"

        # Ensure both project root and src are in sys.path to maximize import success
        try:
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
                self.logger.debug("Inserted project root to sys.path: %s", project_root)
            if src_dir.exists() and str(src_dir) not in sys.path:
                sys.path.insert(0, str(src_dir))
                self.logger.debug("Inserted src/ to sys.path: %s", src_dir)
        except Exception:
            self.logger.debug("Could not modify sys.path; continuing with best-effort import attempts.")

        # 1) Try importing variants and calling main()
        candidates = [entry]
        if entry.startswith("src."):
            candidates.append(entry[len("src."):])  # try "main" if "src.main" given
        else:
            candidates.append(f"src.{entry}")

        for mod_name in candidates:
            try:
                self.logger.debug("Attempting to import module '%s'...", mod_name)
                module = importlib.import_module(mod_name)
                self.logger.info("Imported module '%s' successfully.", mod_name)
                if hasattr(module, "main"):
                    maybe_main = getattr(module, "main")
                    if callable(maybe_main):
                        self.logger.info("Calling main() from module '%s'...", mod_name)
                        try:
                            maybe_main()
                            return True
                        except Exception:
                            self.logger.exception("Exception while running main() in module '%s'", mod_name)
                            # don't return yet; we'll try fallback
                    else:
                        self.logger.warning("Module '%s' has attribute 'main' but it is not callable.", mod_name)
                else:
                    self.logger.debug("Module '%s' does not expose main().", mod_name)
            except Exception:
                self.logger.debug("Import attempt for '%s' failed: %s", mod_name, traceback.format_exc())

        # 2) Fallback: run src/main.py directly (this mirrors running `python3 src/main.py`)
        main_py = src_dir / "main.py"
        if main_py.exists():
            self.logger.info("Falling back to executing %s as a subprocess.", main_py)
            python_exe = sys.executable or "python3"
            cmd = [python_exe, str(main_py)]
            self.logger.debug("Subprocess command: %s", " ".join(cmd))
            try:
                # Run it, stream output to our console
                proc = subprocess.Popen(cmd, cwd=str(project_root))
                proc.communicate()
                rc = proc.returncode
                if rc == 0:
                    self.logger.info("Subprocess finished successfully (exit code 0).")
                    return True
                else:
                    self.logger.error("Subprocess exited with code %d.", rc)
                    return False
            except Exception:
                self.logger.exception("Failed to spawn subprocess for %s", main_py)
                return False
        else:
            self.logger.error("Fallback entry file %s not found; cannot launch application.", main_py)
            return False


    def create_requirements_file(self, output: Path = Path("requirements.txt")) -> bool:
        pkgs = self.config.required_packages
        if not pkgs:
            self.logger.warning("No required_packages defined in configuration.")
            return False
        try:
            with output.open("w", encoding="utf-8") as fh:
                for p in pkgs:
                    fh.write(f"{p}\n")
            self.logger.info("Wrote requirements.txt to %s", output.resolve())
            return True
        except Exception:
            self.logger.exception("Failed to write requirements.txt")
            return False

    def run(self, warn_only_deps: bool = True) -> bool:
        self.logger.info("=== Backstabber: initialization started ===")
        if not self.load_config():
            self.logger.error("Aborting: failed to load config.")
            return False
        if not self.validate_config():
            self.logger.error("Aborting: config validation failed.")
            return False
        deps_ok = self.check_dependencies(warn_only=warn_only_deps)
        if not deps_ok and not warn_only_deps:
            self.logger.error("Aborting due to missing dependencies (strict mode).")
            return False
        if not self.setup_environment():
            self.logger.error("Aborting: environment setup failed.")
            return False
        self.check_permissions()
        self.logger.info("Initialization complete. Launching application.")
        return self.launch_application()

# ---------------------------
# CLI
# ---------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="backstabber", description="Backstabber initializer")
    p.add_argument("-c", "--config", default="config.yaml", help="Path to YAML config")
    p.add_argument("--create-requirements", action="store_true", help="Write requirements.txt from config")
    p.add_argument("--check-deps", action="store_true", help="Only check dependencies (strict)")
    p.add_argument("--strict-deps", action="store_true", help="Fail startup if deps are missing")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return p

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    root_logger = logging.getLogger()
    if args.verbose:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(logging.INFO)

    initializer = BackstabberInitializer(config_path=Path(args.config))

    # Load config early so we can act on create-requirements or check-deps
    if not initializer.load_config():
        print("Failed to load configuration. Aborting.", file=sys.stderr)
        return 2

    if args.create_requirements:
        ok = initializer.create_requirements_file()
        return 0 if ok else 3

    if args.check_deps:
        ok = initializer.check_dependencies(warn_only=False)
        print("Dependencies ok" if ok else "Missing dependencies")
        return 0 if ok else 4

    strict_env = os.environ.get("BACKSTABBER_STRICT_DEPS", "0") in ("1", "true", "True")
    strict_mode = args.strict_deps or strict_env

    success = initializer.run(warn_only_deps=not strict_mode)
    return 0 if success else 1

if __name__ == "__main__":
    raise SystemExit(main())