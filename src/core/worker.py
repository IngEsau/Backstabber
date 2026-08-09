from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .control_plane import ControlPlane, ControlPlaneError


class JobWorker:
    def __init__(self, control_plane: Optional[ControlPlane] = None):
        self.control_plane = control_plane or ControlPlane()

    def run_once(self) -> Optional[Dict[str, Any]]:
        job = self.control_plane.claim_next_job()
        if job is None:
            return None

        execution = self.control_plane.start_execution(job)
        try:
            result = self._dispatch(job)
        except Exception as exc:
            failed = self.control_plane.fail_execution(execution["id"], str(exc))
            return {"job": self.control_plane.get_job(job["id"]), "execution": failed}

        finished = self.control_plane.finish_execution(execution["id"], result)
        return {"job": self.control_plane.get_job(job["id"]), "execution": finished}

    def run_forever(self, poll_seconds: float = 2.0) -> None:
        while True:
            processed = self.run_once()
            if processed is None:
                time.sleep(poll_seconds)

    def _dispatch(self, job: Dict[str, Any]) -> Dict[str, Any]:
        operation = job["operation"]
        payload = job["payload"]
        if operation == "network.scan":
            return self._run_network_scan(payload)
        if operation == "packet.capture":
            raise ControlPlaneError("packet.capture handler is not implemented in the durable worker yet")
        if operation == "arp.spoof":
            raise ControlPlaneError("arp.spoof handler is not implemented in the durable worker yet")
        raise ControlPlaneError(f"unsupported operation: {operation}")

    def _run_network_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        from .scanner_adapter import get_default_scanner

        target = payload["target"]
        ports = payload["ports"]
        extra_args = "-Pn" if payload.get("skip_host_discovery") else ""
        scanner = get_default_scanner(prefer="subprocess")
        result = scanner.scan(target, ports=ports, extra_args=extra_args)
        hosts = result.get("hosts", []) if isinstance(result, dict) else []
        return {
            "target": target,
            "ports": ports,
            "hosts": hosts,
            "host_count": len(hosts),
            "backend": scanner.__class__.__name__,
        }
