"""
Approval Center store for the AI SOC engineer.

Write operations (PROPOSE/EXECUTE level tools) do not run on the agent's say
so: the tool raises ApprovalRequired with its proposal, the UI shows the
proposed action to a human, and execution only happens with an approved
proposal id. This module persists those proposals (data/approvals.json) and
tracks their lifecycle:

    pending  -> approved | rejected | expired

Approving is *not* executing: an approved proposal carries the exact action +
payload the tool needs, and the execute endpoint re-runs the real tool with
that payload (no LLM involved in the execution step - see docs/permissions.md).
Proposals older than APPROVAL_EXPIRY_SECONDS are expired and cannot be
approved.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from config import cfg

DEFAULT_APPROVALS_PATH = "data/approvals.json"

STATUSES = ("pending", "approved", "rejected", "expired")


def _path(path: str | Path | None = None) -> Path:
    return Path(path or getattr(cfg, "APPROVALS_PATH", DEFAULT_APPROVALS_PATH))


def _load(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    return [p for p in data if isinstance(p, dict)]


def _save(items: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(items, indent=2, default=str))


def _now() -> float:
    return time.time()


# --------------------------------------------------------------------------- #
def create_proposal(
    *,
    action: str,
    reason: str,
    payload: dict[str, Any],
    permission: str = "propose",
    generated_config: Any = None,
    validation: dict[str, Any] | None = None,
    user: str | None = None,
    agent: str = "soc_engineer",
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Register a new pending proposal. Returns the stored record incl. id."""
    p = _path(path)
    items = _load(p)
    record = {
        "id": f"appr-{uuid.uuid4().hex[:12]}",
        "action": action,
        "reason": reason,
        "payload": payload,
        "permission": permission,
        "generated_config": generated_config,
        "validation": validation or {},
        "status": "pending",
        "created": _now(),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "user": user or getattr(cfg, "ENGINE_USER", "analyst"),
        "agent": agent,
    }
    items.append(record)
    _save(items, p)
    return record


def list_proposals(status: str | None = None, path: str | Path | None = None) -> list[dict[str, Any]]:
    p = _path(path)
    items = _load(p)
    # expire stale pending proposals on read
    changed = False
    for item in items:
        if item.get("status") == "pending" and _now() - float(item.get("created", 0)) > getattr(cfg, "APPROVAL_EXPIRY_SECONDS", 86400):
            item["status"] = "expired"
            changed = True
    if changed:
        _save(items, p)
    out = [i for i in items if status is None or i.get("status") == status]
    return out[::-1]  # newest first


def get_proposal(proposal_id: str, path: str | Path | None = None) -> dict[str, Any] | None:
    for item in _load(_path(path)):
        if item.get("id") == proposal_id:
            return item
    return None


def approve(proposal_id: str, by: str, path: str | Path | None = None) -> dict[str, Any]:
    """Approve a pending proposal. Expired ones cannot be approved."""
    p = _path(path)
    items = _load(p)
    for item in items:
        if item.get("id") != proposal_id:
            continue
        if item["status"] == "expired":
            raise ValueError(f"Proposal {proposal_id} has expired and can no longer be approved.")
        if item["status"] != "pending":
            raise ValueError(f"Proposal {proposal_id} is already {item['status']}.")
        item["status"] = "approved"
        item["approved_by"] = by
        item["approved_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        _save(items, p)
        return item
    raise KeyError(f"Proposal {proposal_id} not found.")


def reject(proposal_id: str, by: str, reason: str = "", path: str | Path | None = None) -> dict[str, Any]:
    p = _path(path)
    items = _load(p)
    for item in items:
        if item.get("id") != proposal_id:
            continue
        if item["status"] != "pending":
            raise ValueError(f"Proposal {proposal_id} is already {item['status']}.")
        item["status"] = "rejected"
        item["rejected_by"] = by
        item["reject_reason"] = reason
        item["rejected_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        _save(items, p)
        return item
    raise KeyError(f"Proposal {proposal_id} not found.")


def public_view(proposal: dict[str, Any]) -> dict[str, Any]:
    """Payload suitable for the UI/chat - never includes secrets (the payload
    is generated config the user needs to review, so it is shown; audit
    handles redaction of credential-bearing params at the tool layer)."""
    return {
        "id": proposal.get("id"),
        "action": proposal.get("action"),
        "reason": proposal.get("reason"),
        "permission": proposal.get("permission"),
        "generated_config": proposal.get("generated_config"),
        "validation": proposal.get("validation"),
        "status": proposal.get("status"),
        "created_at": proposal.get("created_at"),
        "user": proposal.get("user"),
    }