from __future__ import annotations

import ipaddress
import shlex
import shutil
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from .persistence import Database, decode_json, encode_json, new_id, utc_now
from .scanner_adapter import build_nmap_command
from .scope_policy import ScopePolicy, ScopePolicyError


class ControlPlaneError(ValueError):
    pass


@dataclass(frozen=True)
class OperationSpec:
    name: str
    summary: str
    approval_required: bool
    mutating: bool


OPERATIONS: Dict[str, OperationSpec] = {
    "network.scan": OperationSpec(
        name="network.scan",
        summary="Discover hosts and scan TCP ports inside an approved engagement scope.",
        approval_required=True,
        mutating=False,
    ),
    "packet.capture": OperationSpec(
        name="packet.capture",
        summary="Capture packets on a selected interface for a bounded duration.",
        approval_required=True,
        mutating=False,
    ),
    "arp.spoof": OperationSpec(
        name="arp.spoof",
        summary="Start an ARP spoofing workflow between a target and gateway.",
        approval_required=True,
        mutating=True,
    ),
}


def parse_ports(port_text: str) -> List[int]:
    ports: set[int] = set()
    text = (port_text or "").strip()
    if not text:
        raise ControlPlaneError("ports is required")

    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise ControlPlaneError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    invalid = [p for p in ports if p < 1 or p > 65535]
    if invalid:
        raise ControlPlaneError(f"invalid TCP port(s): {invalid[:5]}")
    if not ports:
        raise ControlPlaneError("ports is required")
    return sorted(ports)


def normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    for key in ("scope_cidrs", "tags", "payload", "params", "result", "metadata"):
        if key in out:
            fallback: Any = [] if key in ("scope_cidrs", "tags") else {}
            out[key] = decode_json(out.get(key), fallback)
    for key in ("approval_required", "dry_run"):
        if key in out:
            out[key] = bool(out[key])
    return out


class ControlPlane:
    def __init__(self, db: Optional[Database] = None, scope_policy: Optional[ScopePolicy] = None):
        self.db = db or Database()
        self.scope_policy = scope_policy or ScopePolicy()

    def create_engagement(
        self,
        name: str,
        scope_cidrs: Iterable[str],
        description: str = "",
        actor: str = "local",
        approval_required: bool = True,
    ) -> Dict[str, Any]:
        clean_name = name.strip()
        if not clean_name:
            raise ControlPlaneError("engagement name is required")

        scopes = self._normalize_scopes(scope_cidrs)
        now = utc_now()
        engagement_id = new_id()
        self.db.execute(
            """
            INSERT INTO engagements
                (id, name, description, scope_cidrs, status, approval_required, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
            """,
            (
                engagement_id,
                clean_name,
                description.strip(),
                encode_json(scopes),
                1 if approval_required else 0,
                now,
                now,
            ),
        )
        self.db.audit(actor, "engagement.created", "engagement", engagement_id, {"scope_cidrs": scopes})
        return self.get_engagement(engagement_id)

    def list_engagements(self) -> List[Dict[str, Any]]:
        rows = self.db.fetch_all("SELECT * FROM engagements ORDER BY created_at DESC")
        return [normalize_row(row) for row in rows]

    def get_engagement(self, engagement_id: str) -> Dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM engagements WHERE id = ?", (engagement_id,))
        if not row:
            raise ControlPlaneError(f"engagement not found: {engagement_id}")
        return normalize_row(row)

    def add_asset(
        self,
        engagement_id: str,
        address: str,
        hostname: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        notes: str = "",
        actor: str = "local",
    ) -> Dict[str, Any]:
        engagement = self.get_engagement(engagement_id)
        ip_address = self._parse_ip_address(address)
        self._ensure_address_in_engagement(ip_address, engagement)
        now = utc_now()
        asset_id = new_id()
        clean_tags = sorted({tag.strip() for tag in (tags or []) if tag and tag.strip()})
        self.db.execute(
            """
            INSERT INTO assets
                (id, engagement_id, address, hostname, tags, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, address) DO UPDATE SET
                hostname=excluded.hostname,
                tags=excluded.tags,
                notes=excluded.notes,
                updated_at=excluded.updated_at
            """,
            (
                asset_id,
                engagement_id,
                str(ip_address),
                hostname.strip() if hostname else None,
                encode_json(clean_tags),
                notes.strip(),
                now,
                now,
            ),
        )
        row = self.db.fetch_one(
            "SELECT * FROM assets WHERE engagement_id = ? AND address = ?",
            (engagement_id, str(ip_address)),
        )
        assert row is not None
        asset = normalize_row(row)
        self.db.audit(actor, "asset.upserted", "asset", asset["id"], {"engagement_id": engagement_id})
        return asset

    def list_assets(self, engagement_id: str) -> List[Dict[str, Any]]:
        self.get_engagement(engagement_id)
        rows = self.db.fetch_all(
            "SELECT * FROM assets WHERE engagement_id = ? ORDER BY address",
            (engagement_id,),
        )
        return [normalize_row(row) for row in rows]

    def build_plan(
        self,
        engagement_id: str,
        operation: str,
        payload: Dict[str, Any],
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        engagement = self.get_engagement(engagement_id)
        spec = self._operation_spec(operation)
        normalized_payload = self._normalize_payload(operation, payload, engagement)
        requires_approval = bool(spec.approval_required and engagement["approval_required"] and not dry_run)
        actions = self._actions_for(operation, normalized_payload)
        return {
            "engagement_id": engagement_id,
            "operation": operation,
            "summary": spec.summary,
            "dry_run": bool(dry_run),
            "requires_approval": requires_approval,
            "mutating": spec.mutating,
            "payload": normalized_payload,
            "actions": actions,
            "writes": [
                "jobs row" if not dry_run else "no job will be created",
                "executions row when a queued job starts",
                "audit_log event",
            ],
        }

    def enqueue_job(
        self,
        engagement_id: str,
        operation: str,
        payload: Dict[str, Any],
        actor: str = "local",
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        if dry_run:
            plan = self.build_plan(engagement_id, operation, payload, dry_run=True)
            execution = self.record_dry_run(engagement_id, operation, plan["payload"], plan, actor=actor)
            return {"plan": plan, "execution": execution}

        plan = self.build_plan(engagement_id, operation, payload, dry_run=False)
        status = "waiting_approval" if plan["requires_approval"] else "queued"
        now = utc_now()
        job_id = new_id()
        self.db.execute(
            """
            INSERT INTO jobs
                (id, engagement_id, operation, payload, status, dry_run, run_after, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
            """,
            (
                job_id,
                engagement_id,
                operation,
                encode_json(plan["payload"]),
                status,
                now,
                now,
                now,
            ),
        )
        approval = None
        if plan["requires_approval"]:
            approval_id = new_id()
            self.db.execute(
                """
                INSERT INTO approvals
                    (id, engagement_id, job_id, action, status, reason, requested_by, requested_at)
                VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
                """,
                (approval_id, engagement_id, job_id, operation, "active operation requires approval", actor, now),
            )
            self.db.execute("UPDATE jobs SET approval_id = ? WHERE id = ?", (approval_id, job_id))
            approval = self.get_approval(approval_id)

        self.db.audit(
            actor,
            "job.enqueued",
            "job",
            job_id,
            {"operation": operation, "status": status, "requires_approval": plan["requires_approval"]},
        )
        return {"job": self.get_job(job_id), "approval": approval, "plan": plan}

    def record_dry_run(
        self,
        engagement_id: str,
        operation: str,
        payload: Dict[str, Any],
        plan: Dict[str, Any],
        actor: str = "local",
    ) -> Dict[str, Any]:
        now = utc_now()
        execution_id = new_id()
        self.db.execute(
            """
            INSERT INTO executions
                (id, engagement_id, operation, status, dry_run, requested_by, requested_at,
                 started_at, completed_at, params, result)
            VALUES (?, ?, ?, 'dry_run', 1, ?, ?, ?, ?, ?, ?)
            """,
            (
                execution_id,
                engagement_id,
                operation,
                actor,
                now,
                now,
                now,
                encode_json(payload),
                encode_json(plan),
            ),
        )
        self.db.audit(actor, "execution.dry_run", "execution", execution_id, {"operation": operation})
        return self.get_execution(execution_id)

    def list_jobs(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if status:
            rows = self.db.fetch_all("SELECT * FROM jobs WHERE status = ? ORDER BY created_at DESC", (status,))
        else:
            rows = self.db.fetch_all("SELECT * FROM jobs ORDER BY created_at DESC")
        return [normalize_row(row) for row in rows]

    def get_job(self, job_id: str) -> Dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not row:
            raise ControlPlaneError(f"job not found: {job_id}")
        return normalize_row(row)

    def get_approval(self, approval_id: str) -> Dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        if not row:
            raise ControlPlaneError(f"approval not found: {approval_id}")
        return normalize_row(row)

    def list_approvals(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if status:
            rows = self.db.fetch_all(
                "SELECT * FROM approvals WHERE status = ? ORDER BY requested_at DESC",
                (status,),
            )
        else:
            rows = self.db.fetch_all("SELECT * FROM approvals ORDER BY requested_at DESC")
        return [normalize_row(row) for row in rows]

    def approve_job(self, approval_id: str, actor: str = "local") -> Dict[str, Any]:
        approval = self.get_approval(approval_id)
        if approval["status"] != "pending":
            raise ControlPlaneError(f"approval is not pending: {approval_id}")
        now = utc_now()
        self.db.execute(
            """
            UPDATE approvals
            SET status = 'approved', decided_by = ?, decided_at = ?
            WHERE id = ?
            """,
            (actor, now, approval_id),
        )
        self.db.execute(
            """
            UPDATE jobs
            SET status = 'queued', updated_at = ?
            WHERE id = ? AND status = 'waiting_approval'
            """,
            (now, approval["job_id"]),
        )
        self.db.audit(actor, "approval.approved", "approval", approval_id, {"job_id": approval["job_id"]})
        return {"approval": self.get_approval(approval_id), "job": self.get_job(approval["job_id"])}

    def reject_job(self, approval_id: str, actor: str = "local", reason: str = "") -> Dict[str, Any]:
        approval = self.get_approval(approval_id)
        if approval["status"] != "pending":
            raise ControlPlaneError(f"approval is not pending: {approval_id}")
        now = utc_now()
        self.db.execute(
            """
            UPDATE approvals
            SET status = 'rejected', decided_by = ?, decided_at = ?, reason = ?
            WHERE id = ?
            """,
            (actor, now, reason.strip() or approval.get("reason", ""), approval_id),
        )
        self.db.execute(
            "UPDATE jobs SET status = 'rejected', updated_at = ? WHERE id = ?",
            (now, approval["job_id"]),
        )
        self.db.audit(actor, "approval.rejected", "approval", approval_id, {"job_id": approval["job_id"]})
        return {"approval": self.get_approval(approval_id), "job": self.get_job(approval["job_id"])}

    def requeue_job(self, job_id: str, actor: str = "local", reason: str = "") -> Dict[str, Any]:
        job = self.get_job(job_id)
        if job["status"] not in {"running", "failed"}:
            raise ControlPlaneError(f"job must be running or failed to requeue: {job_id}")

        now = utc_now()
        note = reason.strip() or "operator requested requeue"
        running_executions = self.db.fetch_all(
            "SELECT id FROM executions WHERE job_id = ? AND status = 'running'",
            (job_id,),
        )
        for execution in running_executions:
            self.db.execute(
                """
                UPDATE executions
                SET status = 'failed', completed_at = ?, error = ?
                WHERE id = ?
                """,
                (now, f"requeued: {note}", execution["id"]),
            )

        self.db.execute(
            """
            UPDATE jobs
            SET status = 'queued', last_error = NULL, updated_at = ?
            WHERE id = ?
            """,
            (now, job_id),
        )
        self.db.audit(
            actor,
            "job.requeued",
            "job",
            job_id,
            {"reason": note, "previous_status": job["status"], "executions_closed": len(running_executions)},
        )
        return self.get_job(job_id)

    def claim_next_job(self) -> Optional[Dict[str, Any]]:
        now = utc_now()
        cur = self.db.conn.execute(
            """
            SELECT id FROM jobs
            WHERE status = 'queued' AND (run_after IS NULL OR run_after <= ?)
            ORDER BY created_at ASC
            LIMIT 1
            """,
            (now,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        job_id = row["id"]
        self.db.conn.execute(
            """
            UPDATE jobs
            SET status = 'running', attempts = attempts + 1, updated_at = ?
            WHERE id = ? AND status = 'queued'
            """,
            (now, job_id),
        )
        self.db.conn.commit()
        job = self.get_job(job_id)
        self.db.audit("worker", "job.claimed", "job", job_id, {"operation": job["operation"]})
        return job

    def start_execution(self, job: Dict[str, Any], actor: str = "worker") -> Dict[str, Any]:
        now = utc_now()
        execution_id = new_id()
        self.db.execute(
            """
            INSERT INTO executions
                (id, engagement_id, job_id, operation, status, dry_run, requested_by,
                 requested_at, started_at, params)
            VALUES (?, ?, ?, ?, 'running', ?, ?, ?, ?, ?)
            """,
            (
                execution_id,
                job["engagement_id"],
                job["id"],
                job["operation"],
                1 if job.get("dry_run") else 0,
                actor,
                now,
                now,
                encode_json(job["payload"]),
            ),
        )
        self.db.audit(actor, "execution.started", "execution", execution_id, {"job_id": job["id"]})
        return self.get_execution(execution_id)

    def finish_execution(self, execution_id: str, result: Dict[str, Any], actor: str = "worker") -> Dict[str, Any]:
        now = utc_now()
        execution = self.get_execution(execution_id)
        self.db.execute(
            """
            UPDATE executions
            SET status = 'succeeded', completed_at = ?, result = ?, error = NULL
            WHERE id = ?
            """,
            (now, encode_json(result), execution_id),
        )
        if execution.get("job_id"):
            self.db.execute(
                "UPDATE jobs SET status = 'succeeded', last_error = NULL, updated_at = ? WHERE id = ?",
                (now, execution["job_id"]),
            )
        self.db.audit(actor, "execution.succeeded", "execution", execution_id, {"job_id": execution.get("job_id")})
        return self.get_execution(execution_id)

    def fail_execution(self, execution_id: str, error: str, actor: str = "worker") -> Dict[str, Any]:
        now = utc_now()
        execution = self.get_execution(execution_id)
        self.db.execute(
            """
            UPDATE executions
            SET status = 'failed', completed_at = ?, error = ?
            WHERE id = ?
            """,
            (now, error, execution_id),
        )
        if execution.get("job_id"):
            self.db.execute(
                "UPDATE jobs SET status = 'failed', last_error = ?, updated_at = ? WHERE id = ?",
                (error, now, execution["job_id"]),
            )
        self.db.audit(actor, "execution.failed", "execution", execution_id, {"error": error})
        return self.get_execution(execution_id)

    def get_execution(self, execution_id: str) -> Dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM executions WHERE id = ?", (execution_id,))
        if not row:
            raise ControlPlaneError(f"execution not found: {execution_id}")
        return normalize_row(row)

    def list_executions(self, engagement_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if engagement_id:
            rows = self.db.fetch_all(
                "SELECT * FROM executions WHERE engagement_id = ? ORDER BY requested_at DESC",
                (engagement_id,),
            )
        else:
            rows = self.db.fetch_all("SELECT * FROM executions ORDER BY requested_at DESC")
        return [normalize_row(row) for row in rows]

    def list_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 500))
        rows = self.db.fetch_all("SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (safe_limit,))
        return [normalize_row(row) for row in rows]

    def overview(self) -> Dict[str, Any]:
        counts = {}
        for table in ("engagements", "assets", "jobs", "approvals", "executions"):
            row = self.db.fetch_one(f"SELECT COUNT(*) AS count FROM {table}")
            counts[table] = int(row["count"]) if row else 0
        queue_rows = self.db.fetch_all("SELECT status, COUNT(*) AS count FROM jobs GROUP BY status")
        return {
            "counts": counts,
            "queue": {row["status"]: int(row["count"]) for row in queue_rows},
            "operations": [spec.__dict__ for spec in OPERATIONS.values()],
        }

    def _normalize_scopes(self, scope_cidrs: Iterable[str]) -> List[str]:
        scopes = []
        for raw in scope_cidrs:
            text = str(raw).strip()
            if not text:
                continue
            try:
                network = self.scope_policy.validate_network(text)
            except ScopePolicyError as exc:
                raise ControlPlaneError(str(exc)) from exc
            scopes.append(str(network))
        if not scopes:
            raise ControlPlaneError("at least one scope CIDR is required")
        return sorted(set(scopes))

    def _operation_spec(self, operation: str) -> OperationSpec:
        spec = OPERATIONS.get(operation)
        if not spec:
            raise ControlPlaneError(f"unsupported operation: {operation}")
        return spec

    def _normalize_payload(
        self,
        operation: str,
        payload: Dict[str, Any],
        engagement: Dict[str, Any],
    ) -> Dict[str, Any]:
        if operation == "network.scan":
            target = str(payload.get("target") or "").strip()
            if not target:
                raise ControlPlaneError("target is required for network.scan")
            target_network = self._parse_ip_network(target)
            self.scope_policy.validate_network(str(target_network))
            self._ensure_network_in_engagement(target_network, engagement)
            ports = str(payload.get("ports") or "1-1024").strip()
            port_list = parse_ports(ports)
            normalized = {
                "target": str(target_network),
                "ports": ",".join(str(port) for port in port_list),
                "port_count": len(port_list),
                "skip_host_discovery": self._should_skip_host_discovery(payload, target_network),
            }
            iface = str(payload.get("iface") or "").strip()
            if iface:
                normalized["iface"] = iface
            return normalized

        if operation == "packet.capture":
            iface = str(payload.get("iface") or "").strip()
            if not iface:
                raise ControlPlaneError("iface is required for packet.capture")
            duration = int(payload.get("duration_seconds") or 60)
            if duration < 1 or duration > 3600:
                raise ControlPlaneError("duration_seconds must be between 1 and 3600")
            return {
                "iface": iface,
                "bpf_filter": str(payload.get("bpf_filter") or "").strip(),
                "duration_seconds": duration,
            }

        if operation == "arp.spoof":
            target_ip = self._parse_ip_address(str(payload.get("target_ip") or ""))
            gateway_ip = self._parse_ip_address(str(payload.get("gateway_ip") or ""))
            self._ensure_address_in_engagement(target_ip, engagement)
            self._ensure_address_in_engagement(gateway_ip, engagement)
            normalized = {"target_ip": str(target_ip), "gateway_ip": str(gateway_ip)}
            iface = str(payload.get("iface") or "").strip()
            if iface:
                normalized["iface"] = iface
            return normalized

        raise ControlPlaneError(f"unsupported operation: {operation}")

    def _actions_for(self, operation: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        if operation == "network.scan":
            nmap_bin = shutil.which("nmap") or "nmap"
            extra_args = "-Pn" if payload.get("skip_host_discovery") else ""
            command = build_nmap_command(nmap_bin, payload["target"], ports=payload["ports"], extra_args=extra_args)
            return [
                {
                    "type": "scope_check",
                    "target": payload["target"],
                    "ports": payload["ports"],
                },
                {
                    "type": "command",
                    "argv": command,
                    "shell_preview": " ".join(shlex.quote(part) for part in command),
                    "requires_raw_socket_or_root": "-sS" in command,
                },
                {
                    "type": "persist",
                    "tables": ["executions", "audit_log"],
                },
            ]

        if operation == "packet.capture":
            return [
                {
                    "type": "capture",
                    "iface": payload["iface"],
                    "bpf_filter": payload["bpf_filter"],
                    "duration_seconds": payload["duration_seconds"],
                    "requires_raw_socket_or_root": True,
                },
                {"type": "persist", "tables": ["executions", "audit_log"]},
            ]

        if operation == "arp.spoof":
            return [
                {
                    "type": "arp_spoof",
                    "target_ip": payload["target_ip"],
                    "gateway_ip": payload["gateway_ip"],
                    "iface": payload.get("iface"),
                    "requires_root": True,
                },
                {"type": "persist", "tables": ["executions", "audit_log"]},
            ]

        return []

    def _parse_ip_network(self, value: str) -> ipaddress._BaseNetwork:
        try:
            return ipaddress.ip_network(value.strip(), strict=False)
        except Exception as exc:
            raise ControlPlaneError(f"invalid network target '{value}': {exc}") from exc

    def _should_skip_host_discovery(
        self,
        payload: Dict[str, Any],
        network: ipaddress._BaseNetwork,
    ) -> bool:
        value = payload.get("skip_host_discovery")
        if value is None:
            return network.num_addresses == 1
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on", "pn", "-pn"}

    def _parse_ip_address(self, value: str) -> ipaddress._BaseAddress:
        try:
            return ipaddress.ip_address(value.strip())
        except Exception as exc:
            raise ControlPlaneError(f"invalid IP address '{value}': {exc}") from exc

    def _ensure_network_in_engagement(
        self,
        network: ipaddress._BaseNetwork,
        engagement: Dict[str, Any],
    ) -> None:
        allowed = [ipaddress.ip_network(cidr, strict=False) for cidr in engagement["scope_cidrs"]]
        if not any(network.subnet_of(scope) for scope in allowed):
            raise ControlPlaneError(
                f"target '{network}' is outside engagement scope: {engagement['scope_cidrs']}"
            )

    def _ensure_address_in_engagement(
        self,
        address: ipaddress._BaseAddress,
        engagement: Dict[str, Any],
    ) -> None:
        allowed = [ipaddress.ip_network(cidr, strict=False) for cidr in engagement["scope_cidrs"]]
        if not any(address in scope for scope in allowed):
            raise ControlPlaneError(
                f"address '{address}' is outside engagement scope: {engagement['scope_cidrs']}"
            )
