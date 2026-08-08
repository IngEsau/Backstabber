from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from core.control_plane import ControlPlane, ControlPlaneError
from core.persistence import Database
from core.worker import JobWorker


def emit(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def build_plane(args: argparse.Namespace) -> ControlPlane:
    db_path = Path(args.db).expanduser() if getattr(args, "db", None) else None
    return ControlPlane(db=Database(db_path))


def split_csv(values: Optional[Iterable[str]]) -> list[str]:
    out: list[str] = []
    for value in values or []:
        out.extend([part.strip() for part in value.split(",") if part.strip()])
    return out


def payload_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    if getattr(args, "payload_json", None):
        loaded = json.loads(args.payload_json)
        if not isinstance(loaded, dict):
            raise ControlPlaneError("--payload-json must be a JSON object")
        return loaded

    payload: Dict[str, Any] = {}
    for key in (
        "target",
        "ports",
        "iface",
        "bpf_filter",
        "duration_seconds",
        "target_ip",
        "gateway_ip",
    ):
        value = getattr(args, key, None)
        if value not in (None, ""):
            payload[key] = value
    return payload


def cmd_engagement_create(args: argparse.Namespace) -> int:
    plane = build_plane(args)
    engagement = plane.create_engagement(
        name=args.name,
        description=args.description or "",
        scope_cidrs=args.scope,
        actor=args.actor,
        approval_required=not args.no_approval,
    )
    emit(engagement)
    return 0


def cmd_engagement_list(args: argparse.Namespace) -> int:
    emit(build_plane(args).list_engagements())
    return 0


def cmd_asset_add(args: argparse.Namespace) -> int:
    plane = build_plane(args)
    asset = plane.add_asset(
        engagement_id=args.engagement,
        address=args.address,
        hostname=args.hostname,
        tags=split_csv(args.tag),
        notes=args.notes or "",
        actor=args.actor,
    )
    emit(asset)
    return 0


def cmd_asset_list(args: argparse.Namespace) -> int:
    emit(build_plane(args).list_assets(args.engagement))
    return 0


def cmd_job_dry_run(args: argparse.Namespace) -> int:
    plane = build_plane(args)
    plan = plane.build_plan(args.engagement, args.operation, payload_from_args(args), dry_run=True)
    execution = plane.record_dry_run(args.engagement, args.operation, plan["payload"], plan, actor=args.actor)
    emit({"plan": plan, "execution": execution})
    return 0


def cmd_job_enqueue(args: argparse.Namespace) -> int:
    result = build_plane(args).enqueue_job(
        args.engagement,
        args.operation,
        payload_from_args(args),
        actor=args.actor,
        dry_run=False,
    )
    emit(result)
    return 0


def cmd_job_list(args: argparse.Namespace) -> int:
    emit(build_plane(args).list_jobs(status=args.status))
    return 0


def cmd_approval_list(args: argparse.Namespace) -> int:
    emit(build_plane(args).list_approvals(status=args.status))
    return 0


def cmd_approval_approve(args: argparse.Namespace) -> int:
    emit(build_plane(args).approve_job(args.approval, actor=args.actor))
    return 0


def cmd_approval_reject(args: argparse.Namespace) -> int:
    emit(build_plane(args).reject_job(args.approval, actor=args.actor, reason=args.reason or ""))
    return 0


def cmd_execution_list(args: argparse.Namespace) -> int:
    emit(build_plane(args).list_executions(engagement_id=args.engagement))
    return 0


def cmd_audit_list(args: argparse.Namespace) -> int:
    emit(build_plane(args).list_audit(limit=args.limit))
    return 0


def cmd_overview(args: argparse.Namespace) -> int:
    emit(build_plane(args).overview())
    return 0


def cmd_worker_run(args: argparse.Namespace) -> int:
    worker = JobWorker(build_plane(args))
    if args.once:
        emit(worker.run_once() or {"status": "idle"})
        return 0
    worker.run_forever(poll_seconds=args.poll_seconds)
    return 0


def cmd_api_serve(args: argparse.Namespace) -> int:
    from api.server import run_api

    run_api(host=args.host, port=args.port, db_path=Path(args.db).expanduser() if args.db else None)
    return 0


def add_job_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-json", help="Raw JSON payload object")
    parser.add_argument("--target", help="Network target for network.scan, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", default="1-1024", help="TCP ports for network.scan")
    parser.add_argument("--iface", help="Interface name")
    parser.add_argument("--bpf-filter", help="BPF filter for packet.capture")
    parser.add_argument("--duration-seconds", type=int, help="Capture duration")
    parser.add_argument("--target-ip", help="Target IP for arp.spoof")
    parser.add_argument("--gateway-ip", help="Gateway IP for arp.spoof")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="backstabberctl", description="Backstabber control plane")
    parser.add_argument("--db", help="SQLite database path. Defaults to data/backstabber.db")
    parser.add_argument("--actor", default="local", help="Actor recorded in audit events")
    sub = parser.add_subparsers(dest="resource", required=True)

    overview = sub.add_parser("overview", help="Show control plane overview")
    overview.set_defaults(func=cmd_overview)

    engagement = sub.add_parser("engagement", help="Manage engagements")
    engagement_sub = engagement.add_subparsers(dest="action", required=True)
    engagement_create = engagement_sub.add_parser("create")
    engagement_create.add_argument("--name", required=True)
    engagement_create.add_argument("--description", default="")
    engagement_create.add_argument("--scope", action="append", required=True, help="Allowed CIDR. Repeatable.")
    engagement_create.add_argument("--no-approval", action="store_true")
    engagement_create.set_defaults(func=cmd_engagement_create)
    engagement_list = engagement_sub.add_parser("list")
    engagement_list.set_defaults(func=cmd_engagement_list)

    asset = sub.add_parser("asset", help="Manage assets")
    asset_sub = asset.add_subparsers(dest="action", required=True)
    asset_add = asset_sub.add_parser("add")
    asset_add.add_argument("--engagement", required=True)
    asset_add.add_argument("--address", required=True)
    asset_add.add_argument("--hostname")
    asset_add.add_argument("--tag", action="append")
    asset_add.add_argument("--notes", default="")
    asset_add.set_defaults(func=cmd_asset_add)
    asset_list = asset_sub.add_parser("list")
    asset_list.add_argument("--engagement", required=True)
    asset_list.set_defaults(func=cmd_asset_list)

    job = sub.add_parser("job", help="Manage durable jobs")
    job_sub = job.add_subparsers(dest="action", required=True)
    job_dry = job_sub.add_parser("dry-run")
    job_dry.add_argument("--engagement", required=True)
    job_dry.add_argument("--operation", required=True)
    add_job_payload_args(job_dry)
    job_dry.set_defaults(func=cmd_job_dry_run)
    job_enqueue = job_sub.add_parser("enqueue")
    job_enqueue.add_argument("--engagement", required=True)
    job_enqueue.add_argument("--operation", required=True)
    add_job_payload_args(job_enqueue)
    job_enqueue.set_defaults(func=cmd_job_enqueue)
    job_list = job_sub.add_parser("list")
    job_list.add_argument("--status")
    job_list.set_defaults(func=cmd_job_list)

    approval = sub.add_parser("approval", help="Manage approvals")
    approval_sub = approval.add_subparsers(dest="action", required=True)
    approval_list = approval_sub.add_parser("list")
    approval_list.add_argument("--status")
    approval_list.set_defaults(func=cmd_approval_list)
    approval_approve = approval_sub.add_parser("approve")
    approval_approve.add_argument("--approval", required=True)
    approval_approve.set_defaults(func=cmd_approval_approve)
    approval_reject = approval_sub.add_parser("reject")
    approval_reject.add_argument("--approval", required=True)
    approval_reject.add_argument("--reason", default="")
    approval_reject.set_defaults(func=cmd_approval_reject)

    execution = sub.add_parser("execution", help="Inspect executions")
    execution_sub = execution.add_subparsers(dest="action", required=True)
    execution_list = execution_sub.add_parser("list")
    execution_list.add_argument("--engagement")
    execution_list.set_defaults(func=cmd_execution_list)

    audit = sub.add_parser("audit", help="Inspect audit log")
    audit_sub = audit.add_subparsers(dest="action", required=True)
    audit_list = audit_sub.add_parser("list")
    audit_list.add_argument("--limit", type=int, default=100)
    audit_list.set_defaults(func=cmd_audit_list)

    worker = sub.add_parser("worker", help="Run durable job worker")
    worker_sub = worker.add_subparsers(dest="action", required=True)
    worker_run = worker_sub.add_parser("run")
    worker_run.add_argument("--once", action="store_true")
    worker_run.add_argument("--poll-seconds", type=float, default=2.0)
    worker_run.set_defaults(func=cmd_worker_run)

    api = sub.add_parser("api", help="Run HTTP API and dashboard")
    api_sub = api.add_subparsers(dest="action", required=True)
    api_serve = api_sub.add_parser("serve")
    api_serve.add_argument("--host", default="127.0.0.1")
    api_serve.add_argument("--port", type=int, default=8765)
    api_serve.set_defaults(func=cmd_api_serve)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ControlPlaneError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
