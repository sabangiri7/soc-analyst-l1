"""
Simple SOC dashboard - connect to multiple SIEM platforms and manage providers.

  python dashboard.py            # then open http://127.0.0.1:5001

Features:
  - See every registered SIEM connection (env-seeded + dashboard-added) with
    its platform, status, and recent alerts.
  - Add a provider: pick a platform (Splunk / QRadar / Elastic / Sentinel /
    Mock), give it a name, fill in its connection details. Stored in
    data/siem_providers.json (see siem_providers.py). Secrets are saved in
    that file and never echoed back to the UI.
  - Test each connection (reachability + auth) with /api/providers/<id>/test.
  - Pull alerts per provider and run the triage agent on them right from the
    dashboard - results land in data/triage_log.jsonl like any other run.

API (JSON): /api/platforms, /api/providers,
            POST /api/providers, DELETE /api/providers/<id>,
            POST /api/providers/<id>/test, GET /api/providers/<id>/alerts,
            POST /api/providers/<id>/triage
"""
from __future__ import annotations
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from config import cfg
import siem_providers as store
import agent_control as ac
from connectors.siem import PLATFORM_FIELDS
from agent.triage_agent import TriageAgent, needs_human_review
from agent.chat_agent import ChatAgent
from llm.base import LLMRateLimitedError
import lookup_tables as lookup
import rules
import notify
import metrics
import cases
import audit

app = Flask(__name__)

TRIAGE_LIMIT_DEFAULT = 5


def _triage_log_path(path: str | Path | None = None) -> Path:
    return Path(path) if path else Path(getattr(cfg, "TRIAGE_LOG_PATH", "") or "data/triage_log.jsonl")


def _chat_log_path(path: str | Path | None = None) -> Path:
    return Path(path) if path else Path(getattr(cfg, "CHAT_LOG_PATH", "") or "data/chat_log.jsonl")


def _engineer_log_path(path: str | Path | None = None) -> Path:
    return Path(path) if path else Path(getattr(cfg, "ENGINEER_LOG_PATH", "") or "data/engineer_log.jsonl")


# --------------------------------------------------------------------------- #
# Auth - optional single-shared-secret token (DASHBOARD_TOKEN) and/or per-user
# tokens (DASHBOARD_USERS="user:token,user:token,..."). When neither is set
# (the default) there is no auth, which is fine for strictly local use bound to
# 127.0.0.1; set one before pointing --host at anything else, since every
# route here (including ones that write to the SIEM, start/stop the overnight
# watcher, and CRUD lookup tables/rules) is otherwise wide open. The token is
# accepted as `Authorization: Bearer <token>` or `?token=...`; the page shell
# (`/`) always loads so the JS can read `?token=` off the URL and attach it to
# every subsequent /api/* call - see api() in index.html.
# With DASHBOARD_USERS, a valid Bearer token maps to a VERIFIED identity: the
# Approval Center uses it for separation of duties and ignores any
# client-supplied "by" field.
# --------------------------------------------------------------------------- #
def _supplied_token() -> str:
    supplied = request.headers.get("Authorization", "")
    if supplied.startswith("Bearer "):
        return supplied[len("Bearer "):]
    return request.args.get("token", "")


def _token_ok() -> bool:
    from config import cfg
    if not getattr(cfg, "DASHBOARD_TOKEN", ""):
        return False
    return _supplied_token() == cfg.DASHBOARD_TOKEN


def _token_user() -> str | None:
    """Map a Bearer token to a verified per-user identity from DASHBOARD_USERS.
    None when per-user auth isn't configured or the token is unknown."""
    from config import cfg
    users_cfg = getattr(cfg, "DASHBOARD_USERS", "") or ""
    if not users_cfg:
        return None
    supplied = _supplied_token()
    if not supplied:
        return None
    for entry in users_cfg.split(","):
        if ":" not in entry:
            continue
        user, tok = entry.split(":", 1)
        if tok.strip() == supplied:
            return user.strip()
    return None


@app.before_request
def _require_dashboard_token():
    from config import cfg
    if not (getattr(cfg, "DASHBOARD_TOKEN", "") or getattr(cfg, "DASHBOARD_USERS", "")):
        return None  # auth disabled (default) - purely local use
    if request.path == "/":
        return None  # let the page shell load; every /api/* call below is still gated
    if _token_ok() or _token_user():
        return None
    return jsonify({"error": "Unauthorized - set Authorization: Bearer <token> or ?token=<token>."}), 401


# --------------------------------------------------------------------------- #
def _connector_or_error(provider_id: str):
    provider = store.get_provider(provider_id)
    if not provider:
        return None, (jsonify({"error": f"Provider '{provider_id}' not found."}), 404), None
    try:
        conn = store.connector_for(provider)
    except Exception as e:  # noqa: BLE001 - surface config errors to the UI
        return None, (jsonify({"error": f"Could not build connector: {e}"}), 400), None
    return conn, None, provider


# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    from config import cfg
    return jsonify({
        "status": "ok",
        "llm_provider": cfg.LLM_PROVIDER,
        "siem_provider": cfg.SIEM_PROVIDER,
        "mock_mode": cfg.MOCK_MODE,
    })


@app.get("/api/platforms")
def api_platforms():
    out = []
    for key, meta in PLATFORM_FIELDS.items():
        out.append({"platform": key, **meta})
    return jsonify({"platforms": out})


@app.get("/api/metrics")
def api_metrics():
    """Aggregate stats over data/triage_log.jsonl (+ analyst-agreement rate
    from data/feedback_log.jsonl, when any review history exists) - see
    metrics.py for the actual computation."""
    return jsonify(metrics.compute_metrics())


@app.get("/api/cases")
def api_cases():
    """Alerts from data/triage_log.jsonl clustered by shared host/user
    within a time window - see cases.py. Query params: window_minutes,
    limit, min_alerts (default 1 - pass 2 to only see actual clusters)."""
    window = float(request.args.get("window_minutes", cases.DEFAULT_WINDOW_MINUTES))
    limit = int(request.args.get("limit", cases.DEFAULT_SCAN_LIMIT))
    min_alerts = int(request.args.get("min_alerts", 1))
    grouped = cases.group_cases(window_minutes=window, limit=limit)
    grouped = [c for c in grouped if c["alert_count"] >= min_alerts]
    return jsonify({"cases": grouped})


@app.get("/api/providers")
def api_providers():
    return jsonify({"providers": [store.redact_provider(p) for p in store.load_providers()]})


@app.post("/api/providers")
def api_add_provider():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        provider = store.add_provider(payload)
    except store.ProviderError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"provider": store.redact_provider(provider)}), 201


@app.delete("/api/providers/<provider_id>")
def api_delete_provider(provider_id: str):
    if not store.remove_provider(provider_id):
        return jsonify({"error": "Provider not found, or it is env-seeded (edit .env to change it)."}), 404
    return jsonify({"ok": True})


@app.post("/api/providers/<provider_id>/test")
def api_test(provider_id: str):
    conn, err, _ = _connector_or_error(provider_id)
    if err:
        return err
    return jsonify(conn.test_connection())


@app.get("/api/providers/<provider_id>/alerts")
def api_alerts(provider_id: str):
    conn, err, provider = _connector_or_error(provider_id)
    if err:
        return err
    limit = request.args.get("limit", default=100, type=int)
    try:
        alerts = conn.get_new_alerts()
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"Failed to pull alerts: {e}"}), 502
    return jsonify({
        "provider_id": provider_id,
        "provider_name": provider["name"],
        "platform": provider["platform"],
        "count": len(alerts),
        "alerts": alerts[:limit],
    })


@app.post("/api/providers/<provider_id>/triage")
def api_triage(provider_id: str):
    conn, err, provider = _connector_or_error(provider_id)
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    limit = int(body.get("limit", TRIAGE_LIMIT_DEFAULT))

    try:
        alerts = conn.get_new_alerts()
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"Failed to pull alerts: {e}"}), 502
    if not alerts:
        return jsonify({"provider_id": provider_id, "triaged": 0, "results": [], "note": "No new alerts."})

    try:
        agent = TriageAgent(siem=conn)
    except Exception as e:  # noqa: BLE001 - e.g. missing LLM key
        return jsonify({"error": f"Could not start the triage agent: {e}"}), 400

    _triage_log_path().parent.mkdir(parents=True, exist_ok=True)
    results = []
    for alert in alerts[:limit]:
        try:
            rule_matches = rules.evaluate_all(alert)
        except Exception:  # noqa: BLE001 - a bad rule should never block triage
            rule_matches = []
        triggered = [m for m in rule_matches if m["triggered"]]
        if triggered:
            try:
                notify.notify_rule_matches(alert, rule_matches)
            except Exception:  # noqa: BLE001 - a bad webhook must never block triage
                pass

        try:
            result = agent.triage(alert)
        except Exception as e:  # noqa: BLE001
            results.append({"alert_id": alert.get("alert_id", "?"), "rule_id": alert.get("rule_id"), "error": str(e)})
            continue
        needs_human = needs_human_review(result, rule_matches)
        with open(_triage_log_path(), "a") as f:
            f.write(json.dumps({
                "alert": alert,
                "result": asdict(result),
                "rule_matches": rule_matches,
                "needs_human_review": needs_human,
                "siem_provider": {"id": provider_id, "name": provider["name"], "platform": provider["platform"]},
            }, default=str) + "\n")
        results.append({
            "alert_id": alert.get("alert_id", "?"),
            "rule_id": alert.get("rule_id"),
            "rule_name": alert.get("rule_name", alert.get("description", "")),
            "verdict": result.verdict,
            "confidence": result.confidence,
            "recommended_action": result.recommended_action,
            "rationale": result.rationale,
            "rule_matches": [m["name"] for m in triggered],
            "needs_human_review": needs_human,
        })

    return jsonify({
        "provider_id": provider_id,
        "provider_name": provider["name"],
        "triaged": len(results),
        "results": results,
    })


# --------------------------------------------------------------------------- #
# Chat agent route - conversational SOC assistant with R/W lookup tables.
# --------------------------------------------------------------------------- #
CHAT_LOG = Path("data/chat_log.jsonl")
CHAT_LIMIT_DEFAULT = 50


@app.post("/api/chat")
def api_chat():
    body = request.get_json(force=True, silent=True) or {}
    message = (body.get("message") or "").strip()
    provider_id = body.get("provider_id") or ""
    history = body.get("history") or []
    if not message:
        return jsonify({"error": "message is required."}), 400

    siem = None
    if provider_id:
        conn, err, _ = _connector_or_error(provider_id)
        if err:
            return err
        siem = conn

    try:
        agent = ChatAgent(siem=siem, provider_id=provider_id or None)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"Could not start the chat agent: {e}"}), 400

    try:
        result = agent.chat(user_message=message, history=history or [])
    except LLMRateLimitedError as e:
        # Upstream LLM gateway is rate limited. Answer 429 to the browser
        # (with the gateway's Retry-After when known) instead of a Flask 500
        # traceback - and never retry the message here, that would just keep
        # the key inside the rate-limit window.
        return jsonify({
            "error": "The LLM gateway is rate limited; please wait a moment and try again.",
            "retry_after": e.retry_after,
            "request_id": e.request_id,
        }), 429

    _chat_log_path().parent.mkdir(parents=True, exist_ok=True)
    with open(_chat_log_path(), "a") as f:
        f.write(json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "message": message,
            "reply": result.reply,
            "data": result.data,
            "transcript_len": len(result.transcript),
        }, default=str) + "\n")

    return jsonify({
        "reply": result.reply,
        "data": result.data,
        "transcript_len": len(result.transcript),
    })


@app.get("/api/chat/history")
def api_chat_history():
    limit = int(request.args.get("limit", CHAT_LIMIT_DEFAULT))
    if not _chat_log_path().exists():
        return jsonify({"entries": [], "count": 0})
    entries = []
    for line in _chat_log_path().read_text().splitlines():
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    entries = entries[-limit:]
    return jsonify({"entries": entries, "count": len(entries)})


# --------------------------------------------------------------------------- #
# Lookup-tables CRUD routes.
# --------------------------------------------------------------------------- #
@app.get("/api/lookup-tables")
def api_lookup_tables():
    return jsonify({"tables": lookup.list_lookup_tables()})


@app.post("/api/lookup-tables")
def api_create_lookup_table():
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    description = (body.get("description") or "").strip()
    if not name:
        return jsonify({"error": "name is required."}), 400
    try:
        table = lookup.create_lookup_table(name, description)
    except KeyError as e:
        return jsonify({"error": str(e)}), 409
    return jsonify({"table": {"name": name, "entry_count": len((table.get("entries") or {})), "updated": table.get("updated")}}), 201


@app.get("/api/lookup-tables/<name>")
def api_read_lookup_table(name: str):
    table = lookup.read_lookup_table(name)
    if not table:
        return jsonify({"error": f"Lookup table '{name}' not found."}), 404
    return jsonify({"name": name, "table": table})


@app.post("/api/lookup-tables/<name>/entries/<key>")
def api_upsert_lookup_entry(name: str, key: str):
    body = request.get_json(force=True, silent=True) or {}
    value = body.get("value")
    try:
        table = lookup.upsert_lookup_entry(name, key, value)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 400
    return jsonify({"name": name, "key": key, "entry_count": len((table.get("entries") or {})), "updated": table.get("updated")})


@app.delete("/api/lookup-tables/<name>/entries/<key>")
def api_delete_lookup_entry(name: str, key: str):
    ok = lookup.delete_lookup_entry(name, key)
    if not ok:
        return jsonify({"error": f"Key '{key}' not found in table '{name}'."}), 404
    return jsonify({"ok": True})


@app.delete("/api/lookup-tables/<name>")
def api_delete_lookup_table(name: str):
    ok = lookup.delete_lookup_table(name)
    if not ok:
        return jsonify({"error": f"Lookup table '{name}' not found."}), 404
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
# Alert rules CRUD + test routes.
# --------------------------------------------------------------------------- #
@app.get("/api/rules/ops")
def api_rule_ops():
    """The valid condition operators - single source of truth is rules.VALID_OPS."""
    return jsonify({"ops": list(rules.VALID_OPS)})


@app.get("/api/rules")
def api_rules():
    return jsonify({"rules": rules.list_rules()})


@app.post("/api/rules")
def api_create_rule():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        rule = rules.create_rule(payload)
    except rules.RuleError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"rule": rule}), 201


@app.get("/api/rules/<rule_id>")
def api_read_rule(rule_id: str):
    rule = rules.read_rule(rule_id)
    if not rule:
        return jsonify({"error": f"Rule '{rule_id}' not found."}), 404
    return jsonify({"rule": rule})


@app.patch("/api/rules/<rule_id>")
def api_update_rule(rule_id: str):
    payload = request.get_json(force=True, silent=True) or {}
    try:
        rule = rules.update_rule(rule_id, payload)
    except rules.RuleError as e:
        return jsonify({"error": str(e)}), 400
    if not rule:
        return jsonify({"error": f"Rule '{rule_id}' not found."}), 404
    return jsonify({"rule": rule})


@app.delete("/api/rules/<rule_id>")
def api_delete_rule(rule_id: str):
    if not rules.delete_rule(rule_id):
        return jsonify({"error": f"Rule '{rule_id}' not found."}), 404
    return jsonify({"ok": True})


@app.post("/api/rules/<rule_id>/backtest")
def api_backtest_rule(rule_id: str):
    """How often would this saved rule have fired on historical alerts?
    Reads data/triage_log.jsonl - never touches the real threshold state."""
    rule = rules.read_rule(rule_id)
    if not rule:
        return jsonify({"error": f"Rule '{rule_id}' not found."}), 404
    body = request.get_json(force=True, silent=True) or {}
    limit = body.get("limit")
    result = rules.backtest_rule(rule, limit=int(limit) if limit else None)
    return jsonify({"result": result})


@app.post("/api/rules/<rule_id>/test")
def api_test_rule(rule_id: str):
    """Dry-run a stored rule against a sample alert - never mutates threshold state."""
    rule = rules.read_rule(rule_id)
    if not rule:
        return jsonify({"error": f"Rule '{rule_id}' not found."}), 404
    body = request.get_json(force=True, silent=True) or {}
    alert = body.get("alert")
    if not isinstance(alert, dict):
        return jsonify({"error": "Provide 'alert' as a JSON object to test against."}), 400
    result = rules.evaluate_rule(rule, alert, dry_run=True)
    return jsonify({"result": result})


@app.post("/api/rules/preview")
def api_preview_rule():
    """Dry-run an unsaved rule draft against a sample alert (rule-builder 'test before save')."""
    body = request.get_json(force=True, silent=True) or {}
    draft = body.get("rule")
    alert = body.get("alert")
    if not isinstance(draft, dict) or not isinstance(alert, dict):
        return jsonify({"error": "Provide 'rule' and 'alert' as JSON objects."}), 400
    try:
        valid = rules.validate_rule(draft)
    except rules.RuleError as e:
        return jsonify({"error": str(e)}), 400
    valid["id"] = "preview"
    result = rules.evaluate_rule(valid, alert, dry_run=True)
    return jsonify({"result": result})


@app.get("/api/rules/export")
def api_export_rules():
    """Portable rule set (no id/created/updated) - download or pipe into
    seed_data/rules/ to share across environments."""
    rule_ids = request.args.getlist("id") or None
    return jsonify({"rules": rules.export_rules(rule_ids)})


@app.post("/api/rules/import")
def api_import_rules():
    body = request.get_json(force=True, silent=True) or {}
    rule_defs = body.get("rules")
    if not isinstance(rule_defs, list):
        return jsonify({"error": "Provide 'rules' as a JSON list."}), 400
    on_conflict = "overwrite" if body.get("overwrite") else "skip"
    try:
        result = rules.import_rules(rule_defs, on_conflict=on_conflict)
    except rules.RuleError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


# --------------------------------------------------------------------------- #
# Agent control - overnight watchers: status, spawn, stop, KILL, logs.
# --------------------------------------------------------------------------- #
def _spawn_agent(agent_id: str, provider_id: str | None = None) -> int:
    """Start a run.py watcher for `agent_id`, capturing its output to run.log."""
    agent_id = ac.sanitize_id(agent_id)
    stop = ac.stop_file_path(agent_id)
    stop.parent.mkdir(parents=True, exist_ok=True)
    stop.unlink(missing_ok=True)

    log_path = ac.log_file_path(agent_id)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = open(log_path, "ab")
    cmd = [sys.executable, str(Path(__file__).parent / "run.py"), "--agent-id", agent_id]
    if provider_id:
        cmd += ["--siem", provider_id]
    try:
        proc = subprocess.Popen(cmd, stdout=log_fh, stderr=subprocess.STDOUT,
                                start_new_session=True)
    finally:
        log_fh.close()
    # "starting" heartbeat with a visible pid until the watcher's first write.
    ac.write_heartbeat(agent_id, {
        "status": "starting",
        "pid": proc.pid,
        "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "reason": "started",
    })
    return proc.pid


def _signal_agent(agent_id: str, sig: int) -> bool:
    """Signal a watcher AND drop its stop-file.

    The stop-file alone makes the watcher exit at the top of its next cycle
    (even when idle); the signal makes that immediate. Find the watcher by its
    live command line first (heartbeat pids can be stale or missing for older
    watchers), and only trust a heartbeat pid when /proc discovery found
    nothing to signal - so a recycled pid is never signalled by accident.
    """
    agent_id = ac.sanitize_id(agent_id)
    hb = ac.read_heartbeat(agent_id)
    try:
        pid = int(hb["pid"]) if hb.get("pid") else None
    except (TypeError, ValueError):
        pid = None
    proc_pids = ac.find_watcher_pids(agent_id)
    candidates = proc_pids or ([pid] if pid else [])
    hit = False
    for p in dict.fromkeys(candidates):
        try:
            os.kill(p, sig)
            hit = True
        except (ProcessLookupError, OSError):
            continue
    ac.stop_file_path(agent_id).touch(exist_ok=True)
    return hit


@app.get("/api/agent")
def api_agent_status():
    """Legacy single-agent status (default watcher)."""
    return jsonify(ac.status("default"))


@app.post("/api/agent/start")
def api_agent_start():
    """Legacy single-agent start (default watcher)."""
    body = request.get_json(force=True, silent=True) or {}
    provider_id = (body.get("provider_id") or "").strip() or None
    pid = _spawn_agent("default", provider_id)
    return jsonify({"ok": True, "pid": pid})


@app.post("/api/agent/stop")
def api_agent_stop():
    """Legacy single-agent stop (default watcher)."""
    hit = _signal_agent("default", signal.SIGTERM)
    return jsonify({"ok": True, "killed": hit})


@app.get("/api/agents")
def api_agents():
    """All deployed watchers + deployed/running/stopped counts."""
    agents = ac.list_agents()
    return jsonify({"agents": agents, "counts": ac.counts(agents)})


@app.post("/api/agents/start")
def api_agents_start():
    """Deploy a named watcher, optionally pinned to a SIEM provider.

    agent_id defaults to the provider id (natural name for a per-provider
    watcher) or 'default'. Refuses to double-start a watcher that is alive.
    """
    body = request.get_json(force=True, silent=True) or {}
    provider_id = (body.get("provider_id") or "").strip() or None
    agent_id = ac.sanitize_id(body.get("agent_id")) if (body.get("agent_id") or "").strip() else (
        provider_id or "default"
    )
    if ac.status(agent_id)["running"]:
        return jsonify({"error": f"Watcher '{agent_id}' is already running."}), 409
    pid = _spawn_agent(agent_id, provider_id)
    return jsonify({"ok": True, "agent_id": agent_id, "pid": pid})


@app.post("/api/agents/<agent_id>/stop")
def api_agents_stop(agent_id: str):
    """Graceful stop: SIGTERM + stop-file (watcher exits cleanly end-of-cycle)."""
    hit = _signal_agent(agent_id, signal.SIGTERM)
    return jsonify({"ok": True, "agent_id": ac.sanitize_id(agent_id), "killed": hit})


@app.post("/api/agents/<agent_id>/kill")
def api_agents_kill(agent_id: str):
    """Kill switch: SIGKILL immediately, no cleanup. Leaves a stopped heartbeat."""
    aid = ac.sanitize_id(agent_id)
    hit = _signal_agent(aid, signal.SIGKILL)
    ac.mark_stopped(aid, "killed (SIGKILL)")
    return jsonify({"ok": True, "agent_id": aid, "killed": hit})


@app.get("/api/agents/<agent_id>/logs")
def api_agents_logs(agent_id: str):
    """Tail of a watcher's captured output (the last N lines of run.log)."""
    aid = ac.sanitize_id(agent_id)
    lines_arg = request.args.get("lines", "200")
    try:
        n = int(lines_arg)
    except ValueError:
        n = 200
    log_path = ac.log_file_path(aid)
    lines = ac.tail_lines(log_path, n) if log_path.exists() else []
    return jsonify({"agent": ac.status(aid), "lines": lines, "total": len(lines)})


# --------------------------------------------------------------------------- #
# AI SOC Engineer - chat, focused builders, Approval Center, audit (PHASE 12).
# --------------------------------------------------------------------------- #
ENGINEER_LOG = Path("data/engineer_log.jsonl")
AUDIT_LOG = Path("data/audit_log.jsonl")


def _engineer_context(user: str = "dashboard-user", agent: str = "engineer_ui"):
    from tools.api_client import WazuhManagerAPI
    from tools.base import ToolContext
    from tools.indexer_client import IndexerClient
    return ToolContext(wazuh=WazuhManagerAPI(), indexer=IndexerClient(),
                       user=user, agent=agent)


@app.post("/api/engineer/chat")
def api_engineer_chat():
    """Run the conversational AI SOC engineer. Tool activity and proposals are
    returned in the transcript; proposals are already persisted in the
    Approval Center (approvals.json)."""
    body = request.get_json(force=True, silent=True) or {}
    message = (body.get("message") or "").strip()
    history = body.get("history") or []
    if not message:
        return jsonify({"error": "message is required."}), 400
    try:
        from agent.soc_engineer import SOCEngineer
        engineer = SOCEngineer(user="dashboard-user")
        result = engineer.chat(user_message=message, history=list(history)[-20:])
    except Exception as e:  # noqa: BLE001 - surface provider/config errors to the UI
        return jsonify({"error": f"Engineer failed: {e}"}), 400

    _engineer_log_path().parent.mkdir(parents=True, exist_ok=True)
    with open(_engineer_log_path(), "a") as f:
        f.write(json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "message": message,
            "reply": result.reply,
            "proposal_ids": [p.get("id") for p in result.proposals],
            "tool_calls": [t.get("tool") for t in result.transcript if t.get("type") == "tool"],
        }, default=str) + "\n")
    return jsonify({
        "reply": result.reply,
        "data": result.data,
        "proposals": result.proposals,
        "transcript": result.transcript,
    })


@app.get("/api/engineer/tools")
def api_engineer_tools():
    """Canonical tool metadata (name/description/permission) for the builder
    UIs - never arbitrary tool execution on its own."""
    from tools.registry import build_tools_meta
    return jsonify({"tools": build_tools_meta()})


@app.post("/api/engineer/tool")
def api_engineer_tool():
    """Run one tool with the standard safety model: READ tools execute
    immediately; PROPOSE/EXECUTE tools without an approved proposal produce an
    approval_required outcome that lands in the Approval Center (no write
    happens). The execute endpoint below is the only path that writes."""
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("tool") or "").strip()
    params = body.get("params") or {}
    if not name:
        return jsonify({"error": "tool is required."}), 400
    from tools.registry import execute as run_tool
    ctx = _engineer_context(user=body.get("by") or "dashboard-user", agent="engineer_ui")
    outcome = run_tool(ctx, name, params)
    return jsonify(outcome)


# ------------------------- Approval Center ------------------------- #
@app.get("/api/proposals")
def api_proposals():
    import approvals
    status = request.args.get("status") or None
    return jsonify({"proposals": [approvals.public_view(p)
                                  for p in approvals.list_proposals(status)]})


def _verified_approver() -> tuple[str, bool] | None:
    """(user, identity_verified) for the current request, or None when the
    request has no valid credentials. Per-user tokens map to a VERIFIED
    identity; a bare shared token is an unverified fallback."""
    user = _token_user()
    if user is not None:
        return user, True
    if _token_ok():
        body = request.get_json(force=True, silent=True) or {}
        return (body.get("by") or "dashboard-user"), False
    return None


@app.post("/api/proposals/<pid>/approve")
def api_proposal_approve(pid: str):
    import approvals
    approver = _verified_approver()
    if approver is None:
        return jsonify({"error": "Unauthorized - a valid token is required to approve."}), 401
    by, verified = approver
    # A client-supplied "by" is ignored for verified identities: the token IS
    # the identity, so a proposer can never approve as someone else.
    try:
        proposal = approvals.approve(pid, by, identity_verified=verified)
    except approvals.ApprovalPolicyError as e:
        return jsonify({"error": str(e)}), 403
    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    audit.audit_log(tool="approval_center", action="proposal_approved",
                    permission="human", approval_status="approved", params={},
                    result={"proposal_id": pid, "by": by, "identity_verified": verified})
    return jsonify({"proposal": approvals.public_view(proposal)})


@app.post("/api/proposals/<pid>/reject")
def api_proposal_reject(pid: str):
    import approvals
    approver = _verified_approver()
    if approver is None:
        return jsonify({"error": "Unauthorized - a valid token is required to reject."}), 401
    by, _ = approver
    body = request.get_json(force=True, silent=True) or {}
    reason = body.get("reason") or ""
    try:
        proposal = approvals.reject(pid, by, reason)
    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    audit.audit_log(tool="approval_center", action="proposal_rejected",
                    permission="human", approval_status="rejected", params={},
                    result={"proposal_id": pid, "by": by, "reason": reason})
    return jsonify({"proposal": approvals.public_view(proposal)})


@app.post("/api/proposals/<pid>/execute")
def api_proposal_execute(pid: str):
    """Execute an approved proposal deterministically with its stored payload.
    This is the ONLY path that writes: the proposal is claimed atomically
    (single-use - a replay is 409), EXECUTE-level actions need an explicit
    'confirm' flag, and the real tool runs with the STORED payload via
    approval_executor (no LLM involved)."""
    import approval_executor
    from config import cfg
    body = request.get_json(force=True, silent=True) or {}
    approver = _verified_approver()
    if approver is None:
        return jsonify({"error": "Unauthorized - a valid token is required to execute."}), 401
    by, verified = approver
    out = approval_executor.execute_proposal(
        pid,
        by=by,
        confirm=bool(body.get("confirm")),
        identity_verified=verified,
        ctx_factory=lambda by: _engineer_context(user=by, agent="approval_executor"),
        path=cfg.APPROVALS_PATH,
    )
    http_status = out.pop("http_status", 200)
    return jsonify(out), http_status


# ------------------------------ Audit log ------------------------------- #
@app.get("/api/audit")
def api_audit():
    limit = int(request.args.get("limit", 100))
    return jsonify({"entries": audit.read_audit_log(limit=limit)})


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SOC SIEM dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    parser.add_argument("--port", default=5001, type=int, help="bind port (default 5001)")
    args = parser.parse_args()

    print("=" * 60)
    print("SOC triage dashboard")
    print(f"  Open:      http://{args.host}:{args.port}")
    print(f"  Providers: {store.default_providers_path()}")
    if cfg.DASHBOARD_TOKEN:
        print("  Auth:      ON - open with ?token=<your DASHBOARD_TOKEN>")
    elif args.host not in ("127.0.0.1", "localhost"):
        print("  Auth:      OFF - WARNING: binding to a non-local host with no "
              "DASHBOARD_TOKEN set means every route here is open to anyone "
              "who can reach this address. Set DASHBOARD_TOKEN in .env.")
    else:
        print("  Auth:      OFF (fine for local-only use - set DASHBOARD_TOKEN before exposing this beyond 127.0.0.1)")
    print("=" * 60)
    app.run(host=args.host, port=args.port, debug=False)