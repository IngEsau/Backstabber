from __future__ import annotations

import json
import mimetypes
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

from core.control_plane import ControlPlane, ControlPlaneError
from core.persistence import Database


class BackstabberAPIHandler(BaseHTTPRequestHandler):
    server_version = "BackstabberControlPlane/1.0"
    control_plane: ControlPlane
    static_root: Path

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_common_headers("application/json")
        self.end_headers()

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)

            if path == "/health":
                self._json({"status": "ok"})
                return
            if path == "/api/overview":
                self._json(self.control_plane.overview())
                return
            if path == "/api/engagements":
                self._json(self.control_plane.list_engagements())
                return
            if path.startswith("/api/engagements/") and path.endswith("/assets"):
                engagement_id = self._path_part(path, 2)
                self._json(self.control_plane.list_assets(engagement_id))
                return
            if path.startswith("/api/engagements/"):
                engagement_id = self._path_part(path, 2)
                self._json(self.control_plane.get_engagement(engagement_id))
                return
            if path == "/api/jobs":
                status = query.get("status", [None])[0]
                self._json(self.control_plane.list_jobs(status=status))
                return
            if path == "/api/approvals":
                status = query.get("status", [None])[0]
                self._json(self.control_plane.list_approvals(status=status))
                return
            if path == "/api/executions":
                engagement_id = query.get("engagement_id", [None])[0]
                self._json(self.control_plane.list_executions(engagement_id=engagement_id))
                return
            if path == "/api/audit":
                limit = int(query.get("limit", ["100"])[0])
                self._json(self.control_plane.list_audit(limit=limit))
                return

            self._static(parsed.path)
        except ControlPlaneError as exc:
            self._json_error(str(exc), HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            self._json_error(str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        try:
            path = (urlparse(self.path).path.rstrip("/") or "/")
            body = self._read_json()
            actor = str(body.get("actor") or "api")

            if path == "/api/engagements":
                self._json(
                    self.control_plane.create_engagement(
                        name=str(body.get("name") or ""),
                        description=str(body.get("description") or ""),
                        scope_cidrs=body.get("scope_cidrs") or [],
                        actor=actor,
                        approval_required=bool(body.get("approval_required", True)),
                    ),
                    HTTPStatus.CREATED,
                )
                return

            if path.startswith("/api/engagements/") and path.endswith("/assets"):
                engagement_id = self._path_part(path, 2)
                self._json(
                    self.control_plane.add_asset(
                        engagement_id=engagement_id,
                        address=str(body.get("address") or ""),
                        hostname=body.get("hostname"),
                        tags=body.get("tags") or [],
                        notes=str(body.get("notes") or ""),
                        actor=actor,
                    ),
                    HTTPStatus.CREATED,
                )
                return

            if path == "/api/jobs/dry-run":
                plan = self.control_plane.build_plan(
                    engagement_id=str(body.get("engagement_id") or ""),
                    operation=str(body.get("operation") or ""),
                    payload=self._payload(body),
                    dry_run=True,
                )
                execution = self.control_plane.record_dry_run(
                    engagement_id=str(body.get("engagement_id") or ""),
                    operation=str(body.get("operation") or ""),
                    payload=plan["payload"],
                    plan=plan,
                    actor=actor,
                )
                self._json({"plan": plan, "execution": execution})
                return

            if path == "/api/jobs":
                self._json(
                    self.control_plane.enqueue_job(
                        engagement_id=str(body.get("engagement_id") or ""),
                        operation=str(body.get("operation") or ""),
                        payload=self._payload(body),
                        actor=actor,
                        dry_run=False,
                    ),
                    HTTPStatus.CREATED,
                )
                return

            if path.startswith("/api/approvals/") and path.endswith("/approve"):
                approval_id = self._path_part(path, 2)
                self._json(self.control_plane.approve_job(approval_id, actor=actor))
                return

            if path.startswith("/api/approvals/") and path.endswith("/reject"):
                approval_id = self._path_part(path, 2)
                self._json(
                    self.control_plane.reject_job(
                        approval_id,
                        actor=actor,
                        reason=str(body.get("reason") or ""),
                    )
                )
                return

            self._json_error("not found", HTTPStatus.NOT_FOUND)
        except json.JSONDecodeError as exc:
            self._json_error(f"invalid JSON: {exc}", HTTPStatus.BAD_REQUEST)
        except ControlPlaneError as exc:
            self._json_error(str(exc), HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            self._json_error(str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _payload(self, body: Dict[str, Any]) -> Dict[str, Any]:
        payload = body.get("payload")
        if isinstance(payload, dict):
            return payload
        out: Dict[str, Any] = {}
        for key in (
            "target",
            "ports",
            "iface",
            "bpf_filter",
            "duration_seconds",
            "target_ip",
            "gateway_ip",
        ):
            if key in body:
                out[key] = body[key]
        return out

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length == 0:
            return {}
        data = self.rfile.read(length).decode("utf-8")
        body = json.loads(data)
        if not isinstance(body, dict):
            raise ControlPlaneError("request body must be a JSON object")
        return body

    def _path_part(self, path: str, index: int) -> str:
        parts = [unquote(part) for part in path.split("/") if part]
        try:
            return parts[index]
        except IndexError as exc:
            raise ControlPlaneError("invalid resource path") from exc

    def _json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(value, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self._send_common_headers("application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _json_error(self, message: str, status: HTTPStatus) -> None:
        self._json({"error": message}, status)

    def _static(self, request_path: str) -> None:
        path = unquote(request_path)
        if path in ("", "/"):
            path = "/index.html"
        if path.startswith("/api/"):
            self._json_error("not found", HTTPStatus.NOT_FOUND)
            return

        if path.startswith("/assets/"):
            root = _resource_root("assets").resolve()
            candidate = (root / path.removeprefix("/assets/")).resolve()
        else:
            root = self.static_root.resolve()
            candidate = (self.static_root / path.lstrip("/")).resolve()
        if not candidate.is_relative_to(root) or not candidate.exists() or candidate.is_dir():
            self._json_error("not found", HTTPStatus.NOT_FOUND)
            return

        content_type = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
        raw = candidate.read_bytes()
        self.send_response(HTTPStatus.OK)
        self._send_common_headers(content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_common_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Cache-Control", "no-store")


def run_api(host: str = "127.0.0.1", port: int = 8765, db_path: Optional[Path] = None) -> None:
    handler = BackstabberAPIHandler
    handler.control_plane = ControlPlane(db=Database(db_path))
    handler.static_root = _resource_root("frontend")
    httpd = ThreadingHTTPServer((host, int(port)), handler)
    print(f"Backstabber API listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nBackstabber API stopped")
    finally:
        httpd.server_close()


def _resource_root(name: str) -> Path:
    local = Path.cwd() / name
    if local.exists():
        return local
    installed = Path(sys.prefix) / "share" / "backstabber-toolkit" / name
    return installed


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="backstabber-api")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db")
    args = parser.parse_args()
    run_api(host=args.host, port=args.port, db_path=Path(args.db).expanduser() if args.db else None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
