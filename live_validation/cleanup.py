"""Cleanup of PHASE 14 test artifacts.

Every destructive action goes through the same approved-EXECUTE path the
agent uses (delete_wazuh_rule / restart_wazuh_manager are EXECUTE level and
require approval + explicit confirmation). Deleting a rule also means
restarting the manager, which takes minutes - the CLI reports what it did
and what state the environment is left in.
"""
from __future__ import annotations

from typing import Any

from live_validation.env import LiveEnv
from live_validation.evidence import EvidenceLog


def reject_leftover_proposals(env: LiveEnv) -> int:
    """Reject any of the harness's own proposals still pending - they must not
    linger as actionable items in the Approval Center."""
    import approvals
    n = 0
    for pid in env.created_proposals:
        p = approvals.get_proposal(pid, path=env.approvals_path)
        if p and p.get("status") == "pending":
            try:
                approvals.reject(pid, env.by, "phase14 cleanup", path=env.approvals_path)
                n += 1
            except (ValueError, KeyError):
                pass
    return n


def cleanup_dashboards(env: LiveEnv, log: EvidenceLog) -> None:
    """Delete dashboards created by the harness (approved EXECUTE + confirm)."""
    s = "cleanup"
    if not env.created_dashboards:
        log.step(s, "dashboards", "delete_wazuh_dashboard", "info", True,
                 detail="no dashboards to clean")
        return
    for did in list(env.created_dashboards):
        if not env.auto_approve:
            log.step(s, f"dashboard {did}", "delete_wazuh_dashboard", "info", True,
                     detail="left in place (no --auto-approve)")
            continue
        try:
            outcome = env.propose("delete_wazuh_dashboard",
                                  {"dashboard_id": did, "reason": "phase14 cleanup"})
            pid = (outcome.get("proposal") or {}).get("id")
            if pid:
                env.created_proposals.append(pid)
                env.approve({"id": pid})
            result = env.execute_approved({"id": pid}) if pid else {"ok": False, "error": "no proposal"}
            ok = result.get("ok") is True
            log.step(s, f"dashboard {did}", "delete_wazuh_dashboard",
                     "wazuh_confirmed" if ok else "error", ok,
                     detail=str(result)[:160])
        except Exception as e:  # noqa: BLE001
            log.step(s, f"dashboard {did}", "delete_wazuh_dashboard", "error", False,
                     detail=str(e)[:160])


def cleanup_rules(env: LiveEnv, log: EvidenceLog) -> None:
    """Remove rules created by the harness and restart the manager to apply."""
    s = "cleanup"
    if not env.created_rules:
        log.step(s, "rules", "delete_wazuh_rule", "info", True, detail="no rules to clean")
        return
    removed = []
    for rid in list(env.created_rules):
        try:
            existing = env.wazuh.get_rule(rid)
            present = bool((existing.get("data") or {}).get("affected_items"))
        except Exception:  # noqa: BLE001
            present = True  # assume present, try to delete
        if not present:
            log.step(s, f"rule {rid}", "manager_api.get_rule", "wazuh_confirmed", True,
                     detail="already absent - nothing to delete")
            removed.append(rid)
            continue
        if not env.auto_approve:
            log.step(s, f"rule {rid}", "delete_wazuh_rule", "info", True,
                     detail="left in place (no --auto-approve)")
            continue
        try:
            outcome = env.propose("delete_wazuh_rule", {"rule_id": rid, "reason": "phase14 cleanup"})
            pid = (outcome.get("proposal") or {}).get("id")
            if pid:
                env.created_proposals.append(pid)
                env.approve({"id": pid})
            result = env.execute_approved({"id": pid}) if pid else {"ok": False, "error": "no proposal"}
            ok = result.get("ok") is True
            log.step(s, f"rule {rid}", "delete_wazuh_rule",
                     "wazuh_confirmed" if ok else "error", ok,
                     detail=(str(result)[:160]))
            if ok:
                removed.append(rid)
        except Exception as e:  # noqa: BLE001
            log.step(s, f"rule {rid}", "delete_wazuh_rule", "error", False, detail=str(e)[:160])
    if removed:
        # restart so the ruleset actually drops the removed rules
        try:
            outcome = env.propose("restart_wazuh_manager", {"reason": "phase14 cleanup: apply rule removal"})
            pid = (outcome.get("proposal") or {}).get("id")
            if pid:
                env.created_proposals.append(pid)
                env.approve({"id": pid})
            result = env.execute_approved({"id": pid}) if pid else {"ok": False, "error": "no proposal"}
            ok = result.get("ok") is True
            log.step(s, "manager restart to apply cleanup", "restart_wazuh_manager",
                     "wazuh_confirmed" if ok else "error", ok,
                     detail=(str(result)[:120]))
        except Exception as e:  # noqa: BLE001
            log.step(s, "manager restart to apply cleanup", "restart_wazuh_manager",
                     "error", False, detail=str(e)[:160])


def cleanup_syslog_listener(env: LiveEnv, log: EvidenceLog) -> None:
    """Restore ossec.conf to its pre-phase shape: remove the UDP 514 syslog
    <remote> block and restart the manager (docker exec - dev-stack admin op,
    not an application tool). Idempotent."""
    s = "cleanup"
    try:
        changed, detail = env.remove_syslog_514()
    except Exception as e:  # noqa: BLE001 - docker may be unavailable
        log.step(s, "syslog listener removal", "docker.exec", "error", False,
                 detail=f"docker unavailable or failed: {str(e)[:160]}")
        return
    if not changed:
        log.step(s, "syslog listener removal", "docker.exec", "info", True,
                 detail="no UDP 514 listener to remove (environment never modified)")
        return
    log.step(s, "syslog listener removal", "docker.exec", "wazuh_confirmed", True,
             detail="removed UDP 514 syslog <remote> block from ossec.conf")
    try:
        env.docker_exec(["/var/ossec/bin/wazuh-control", "restart"])
        ok = env.wait_for_manager(timeout_s=300) and env.wait_for_logtest(timeout_s=300)
        log.step(s, "manager restart after listener removal", "docker.exec+wazuh-control",
                 "wazuh_confirmed", ok,
                 detail="manager restarted and logtest responsive" if ok
                        else "manager NOT ready after restart")
    except Exception as e:  # noqa: BLE001
        log.step(s, "manager restart after listener removal", "docker.exec", "error", False,
                 detail=str(e)[:160])


def reset_stores(env: LiveEnv, approvals_json: str, audit_jsonl: str,
                 approvals_snapshot: str, audit_snapshot: str) -> dict[str, Any]:
    """Restore the approval/audit stores to the PHASE 14 baseline snapshot.

    This is an admin/dev-environment operation, never part of normal flows -
    the phase report records that snapshots were taken and restored."""
    from pathlib import Path
    out: dict[str, Any] = {}
    ap = Path(approvals_json)
    if ap.exists():
        backup = ap.read_text()
        if Path(approvals_snapshot).exists():
            ap.write_text(Path(approvals_snapshot).read_text())
            out["approvals"] = "restored from snapshot"
        else:
            ap.write_text("[]")
            out["approvals"] = "cleared (no snapshot)"
        with open(Path(approvals_json).with_suffix(".phase14.json"), "w") as fh:
            fh.write(backup)
        out["approvals_phase14_evidence"] = str(ap.with_suffix(".phase14.json"))
    al = Path(audit_jsonl)
    if al.exists():
        backup = al.read_text()
        if Path(audit_snapshot).exists():
            al.write_text(Path(audit_snapshot).read_text())
            out["audit"] = "restored from snapshot"
        else:
            al.write_text("")
            out["audit"] = "cleared (no snapshot)"
        with open(Path(audit_jsonl).with_suffix(".phase14.jsonl"), "w") as fh:
            fh.write(backup)
        out["audit_phase14_evidence"] = str(al.with_suffix(".phase14.jsonl"))
    return out