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
from dataclasses import asdict
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

import siem_providers as store
from connectors.siem import PLATFORM_FIELDS
from agent.triage_agent import TriageAgent

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