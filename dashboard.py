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
from agent.triage_agent import TriageAgent
from agent.chat_agent import ChatAgent
import lookup_tables as lookup

app = Flask(__name__)

TRIAGE_LOG = Path("data/triage_log.jsonl")
TRIAGE_LIMIT_DEFAULT = 5


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


@app.get("/api/providers")
def api_providers():
    return jsonify({"providers": store.load_providers()})


@app.post("/api/providers")
def api_add_provider():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        provider = store.add_provider(payload)
    except store.ProviderError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"provider": provider}), 201


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
            result = agent.triage(alert)
        except Exception as e:  # noqa: BLE001
            results.append({"alert_id": alert.get("alert_id", "?"), "error": str(e)})
            continue
        needs_human = (
            result.verdict == "escalate"
            or result.confidence < 0.9
            or result.recommended_action in ("isolate_host", "disable_account")
        )
        with open(TRIAGE_LOG, "a") as f:
            f.write(json.dumps({
                "alert": alert,
                "result": asdict(result),
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

    print("=" * 60)
    print("SOC triage dashboard")
    print(f"  Open:      http://{args.host}:{args.port}")
    print(f"  Providers: {store.default_providers_path()}")
    print("=" * 60)
    app.run(host=args.host, port=args.port, debug=False)