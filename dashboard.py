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
from typing import Any

from flask import Flask, jsonify, render_template, request

import siem_providers as store
from connectors.siem import PLATFORM_FIELDS
from agent.triage_agent import TriageAgent, needs_human_review
from agent.chat_agent import ChatAgent
import lookup_tables as lookup
import rules
import notify
import metrics
import cases

app = Flask(__name__)

TRIAGE_LOG = Path("data/triage_log.jsonl")
TRIAGE_LIMIT_DEFAULT = 5


# --------------------------------------------------------------------------- #
# Auth - optional single-shared-secret token (DASHBOARD_TOKEN). Empty (the
# default) means no auth, which is fine for strictly local use bound to
# 127.0.0.1; set it before pointing --host at anything else, since every
# route here (including ones that write to the SIEM, start/stop the
# overnight watcher, and CRUD lookup tables/rules) is otherwise wide open.
# The token is accepted as `Authorization: Bearer <token>` or `?token=...`;
# the page shell (`/`) always loads so the JS can read `?token=` off the URL
# and attach it to every subsequent /api/* call - see api() in index.html.
# --------------------------------------------------------------------------- #
def _token_ok() -> bool:
    from config import cfg
    supplied = request.headers.get("Authorization", "")
    if supplied.startswith("Bearer "):
        supplied = supplied[len("Bearer "):]
    else:
        supplied = request.args.get("token", "")
    return supplied == cfg.DASHBOARD_TOKEN


@app.before_request
def _require_dashboard_token():
    from config import cfg
    if not cfg.DASHBOARD_TOKEN:
        return None  # auth disabled (default) - purely local use
    if request.path == "/":
        return None  # let the page shell load; every /api/* call below is still gated
    if not _token_ok():
        return jsonify({"error": "Unauthorized - set Authorization: Bearer <token> or ?token=<token>."}), 401
    return None


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

    TRIAGE_LOG.parent.mkdir(parents=True, exist_ok=True)
    results = []
    for alert in alerts[:limit]:
        try:
            rule_matches = rules.evaluate_all(alert)
        except Exception as e:  # noqa: BLE001 - a bad rule should never block triage
            rule_matches = []
        triggered = [m for m in rule_matches if m["triggered"]]
        if triggered:
            try:
                notify.notify_rule_matches(alert, rule_matches)
            except Exception as e:  # noqa: BLE001 - a bad webhook must never block triage
                pass

        try:
            result = agent.triage(alert)
        except Exception as e:  # noqa: BLE001
            results.append({"alert_id": alert.get("alert_id", "?"), "error": str(e)})
            continue
        needs_human = needs_human_review(result, rule_matches)
        with open(TRIAGE_LOG, "a") as f:
            f.write(json.dumps({
                "alert": alert,
                "result": asdict(result),
                "rule_matches": rule_matches,
                "needs_human_review": needs_human,
                "siem_provider": {"id": provider_id, "name": provider["name"], "platform": provider["platform"]},
            }, default=str) + "\n")
        results.append({
            "alert_id": alert.get("alert_id", "?"),
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

    result = agent.chat(user_message=message, history=history or [])

    CHAT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(CHAT_LOG, "a") as f:
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
    if not CHAT_LOG.exists():
        return jsonify({"entries": [], "count": 0})
    entries = []
    for line in CHAT_LOG.read_text().splitlines():
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
# Agent control routes - overnight watcher status / start / stop.
# --------------------------------------------------------------------------- #
AGENT_POLL_TOLERANCE = 120  # seconds: heartbeat fresher than this counts as "running"


@app.get("/api/agent")
def api_agent_status():
    from config import cfg
    hb_path = Path(cfg.AGENT_HEARTBEAT_PATH or "data/agent_heartbeat.json")
    stop_path = Path(cfg.AGENT_STOP_FILE or "data/agent_stop.txt")
    try:
        hb = json.loads(hb_path.read_text())
    except (OSError, json.JSONDecodeError):
        hb = {}
    running = bool(hb.get("status") == "running")
    now = time.time()
    last_ts = hb.get("at")
    last_age = None
    if last_ts:
        try:
            import datetime
            last_dt = datetime.datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
            last_age = (datetime.datetime.now(datetime.timezone.utc) - last_dt).total_seconds()
        except Exception:
            last_age = None
    return jsonify({
        "running": running and (last_age is None or last_age < AGENT_POLL_TOLERANCE),
        "last_heartbeat": last_ts,
        "last_heartbeat_age_s": last_age,
        "pid": hb.get("pid"),
        "stop_file_present": stop_path.exists(),
        "cycle": hb.get("cycle"),
        "triaged_this_cycle": hb.get("triaged_this_cycle"),
        "alerts_seen": hb.get("alerts_seen"),
        "status": hb.get("status"),
        "reason": hb.get("reason"),
    })


@app.post("/api/agent/start")
def api_agent_start():
    from config import cfg
    stop_path = Path(cfg.AGENT_STOP_FILE or "data/agent_stop.txt")
    if stop_path.exists():
        stop_path.unlink()

    cmd = [sys.executable, str(Path(__file__).parent / "run.py")]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    # Write a temporary heartbeat so the dashboard can pick up the pid quickly.
    hb_path = Path(cfg.AGENT_HEARTBEAT_PATH or "data/agent_heartbeat.json")
    hb_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = hb_path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"status": "starting", "pid": proc.pid, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}, indent=2))
    tmp.replace(hb_path)
    return jsonify({"ok": True, "pid": proc.pid})


@app.post("/api/agent/stop")
def api_agent_stop():
    from config import cfg
    hb_path = Path(cfg.AGENT_HEARTBEAT_PATH or "data/agent_heartbeat.json")
    stop_path = Path(cfg.AGENT_STOP_FILE or "data/agent_stop.txt")
    try:
        hb = json.loads(hb_path.read_text())
    except (OSError, json.JSONDecodeError):
        hb = {}
    pid = hb.get("pid")
    if pid:
        try:
            os.kill(int(pid), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
    stop_path.touch()
    return jsonify({"ok": True})


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SOC SIEM dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    parser.add_argument("--port", default=5001, type=int, help="bind port (default 5001)")
    args = parser.parse_args()

    from config import cfg

    print("=" * 60)
    print("SOC triage dashboard")
    print(f"  Open:      http://{args.host}:{args.port}")
    print(f"  Providers: {store.default_providers_path()}")
    if cfg.DASHBOARD_TOKEN:
        print(f"  Auth:      ON - open with ?token=<your DASHBOARD_TOKEN>")
    elif args.host not in ("127.0.0.1", "localhost"):
        print("  Auth:      OFF - WARNING: binding to a non-local host with no "
              "DASHBOARD_TOKEN set means every route here is open to anyone "
              "who can reach this address. Set DASHBOARD_TOKEN in .env.")
    else:
        print("  Auth:      OFF (fine for local-only use - set DASHBOARD_TOKEN before exposing this beyond 127.0.0.1)")
    print("=" * 60)
    app.run(host=args.host, port=args.port, debug=False)