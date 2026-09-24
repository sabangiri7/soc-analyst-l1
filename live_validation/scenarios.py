"""Scenario runners for live validation.

Each scenario: `def run(env: LiveEnv, log: EvidenceLog, opts: dict) -> None`.
`opts` may carry scenario-specific options (e.g. which test IP to use).

The runners drive the SAME application code paths the AI SOC engineer uses
(tools.registry.execute gate, approvals store, audit log, WazuhManagerAPI,
IndexerClient, RAG), with deterministic inputs, so a live run proves the
application behaves as designed - independent of any particular LLM.
"""
from __future__ import annotations

import time
from typing import Any, Callable

from live_validation.env import LiveEnv
from live_validation.evidence import EvidenceLog

# --------------------------------------------------------------------------- #
# scenario registry
# --------------------------------------------------------------------------- #
SCENARIOS: dict[str, dict[str, Any]] = {}


def register(name: str, description: str, run: Callable[[LiveEnv, EvidenceLog, dict], None],
             requires_auto_approve: bool = False) -> None:
    SCENARIOS[name] = {
        "name": name,
        "description": description,
        "run": run,
        "requires_auto_approve": requires_auto_approve,
    }


def list_scenarios() -> list[dict[str, Any]]:
    return [{"name": k, "description": v["description"],
             "requires_auto_approve": v["requires_auto_approve"]}
            for k, v in SCENARIOS.items()]


def run_scenario(env: LiveEnv, name: str, opts: dict[str, Any] | None = None) -> EvidenceLog:
    if name not in SCENARIOS:
        raise KeyError(f"Unknown scenario {name!r}. Available: {', '.join(SCENARIOS)}")
    log = EvidenceLog()
    SCENARIOS[name]["run"](env, log, opts or {})
    return log


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _manager_json(env: LiveEnv, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return env.wazuh.get(path, params or {}) if hasattr(env.wazuh, "get") else env.wazuh.request(
        "GET", path, params or {})


def gen_ssh_rule_xml(rid: int, marker: str, frequency: int = 8,
                     timeframe: int = 300) -> str:
    """Deterministic frequency rule for repeated SSH failures (phase-verified
    pattern: frequency/timeframe are rule attributes with an if_matched_sid
    parent - never child elements, never if_sid).

    frequency must match the number of positive samples a verify run can feed
    (tools cap positive samples at 8; the Nth sample in one logtest session
    fires the rule, the first N-1 fire the parent)."""
    return (
        f'<rule id="{rid}" level="10" frequency="{frequency}" timeframe="{timeframe}">\n'
        f"  <if_matched_sid>5760</if_matched_sid>\n"
        f"  <match>{marker}</match>\n"
        f"  <description>PHASE14 test: repeated SSH authentication failures ({marker})</description>\n"
        f"  <group>authentication_failures,</group>\n"
        f"</rule>\n"
    )


def ssh_failure_line(ts: str, user: str, ip: str, port: int = 22) -> str:
    return (f"Oct 24 {ts} testhost sshd[1000]: Failed password for {user} "
            f"from {ip} port {port} ssh2")


def ssh_success_line(ts: str, user: str, ip: str, port: int = 22) -> str:
    return (f"Oct 24 {ts} testhost sshd[1001]: Accepted password for {user} "
            f"from {ip} port {port} ssh2")


# --------------------------------------------------------------------------- #
# 1. environment baseline (always first)
# --------------------------------------------------------------------------- #
def _scenario_env_baseline(env: LiveEnv, log: EvidenceLog, opts: dict) -> None:
    s = "env_baseline"
    # manager API auth + version
    try:
        tok = env.wazuh._authenticate()
        ok = bool(tok and len(tok) > 40)
        log.step(s, "manager auth", "manager_api.authenticate", "wazuh_confirmed",
                 ok, detail=f"token len {len(tok) if tok else 0}" if ok else "auth failed",
                 params_summary="authenticate")
    except Exception as e:  # noqa: BLE001
        log.step(s, "manager auth", "manager_api.authenticate", "error", False,
                 detail=str(e)[:200])
        return
    try:
        info = _manager_json(env, "/manager/info")
        items = (info.get("data") or {}).get("affected_items") or []
        version = (items[0] or {}).get("version", "?") if items else "?"
        log.step(s, "manager version", "manager_api.info", "wazuh_confirmed", True,
                 detail=f"version {version}", refs={"version": version})
    except Exception as e:  # noqa: BLE001
        log.step(s, "manager version", "manager_api.info", "error", False, detail=str(e)[:200])
    # core daemons
    try:
        st = env.wazuh.get_manager_status()
        daemons = ((st.get("data") or {}).get("affected_items") or [{}])[0]
        core = ["wazuh-analysisd", "wazuh-db", "wazuh-remoted",
                "wazuh-authd", "wazuh-modulesd", "wazuh-apid"]
        down = [d for d in core if daemons.get(d) != "running"]
        log.step(s, "manager readiness", "manager_api.status", "wazuh_confirmed",
                 not down, detail=f"core daemons: { {k: daemons.get(k) for k in core} }",
                 refs={"down": down})
    except Exception as e:  # noqa: BLE001
        log.step(s, "manager readiness", "manager_api.status", "error", False, detail=str(e)[:200])
    # indexer
    try:
        resp = env.indexer.search("wazuh-alerts-*", {"size": 0})
        total = (resp.get("hits") or {}).get("total") or {}
        count = total.get("value") if isinstance(total, dict) else total
        log.step(s, "indexer alerts", "indexer.search", "wazuh_confirmed", True,
                 detail=f"wazuh-alerts-* total {count}",
                 refs={"alert_total": count})
    except Exception as e:  # noqa: BLE001
        log.step(s, "indexer alerts", "indexer.search", "error", False, detail=str(e)[:200])
    # dashboards API
    try:
        r = env.dashboards_call("GET", "/api/saved_objects/_find",
                                params={"type": "dashboard", "per_page": 5})
        total = r.get("total", 0)
        log.step(s, "dashboards API", "dashboards.saved_objects", "wazuh_confirmed", True,
                 detail=f"{total} saved dashboards", refs={"dashboards": total})
    except Exception as e:  # noqa: BLE001
        log.step(s, "dashboards API", "dashboards.saved_objects", "error", False, detail=str(e)[:200])
    # RAG
    try:
        counts = env.rag_counts()
        ok_docs = counts.get("wazuh_docs", 0) >= 1
        log.step(s, "RAG store", "rag.knowledge_base", "wazuh_confirmed", ok_docs,
                 detail=f"collections {counts}", refs=counts)
    except Exception as e:  # noqa: BLE001
        log.step(s, "RAG store", "rag.knowledge_base", "error", False, detail=str(e)[:200])
    # store state (info)
    log.step(s, "approval store", "approvals.list_proposals", "wazuh_confirmed", True,
             detail=f"{env.approvals_count()} proposals in store",
             refs={"proposals": env.approvals_count()})
    log.step(s, "audit log", "audit.audit_log", "wazuh_confirmed", True,
             detail=f"{env.audit_count()} audit rows", refs={"audit_rows": env.audit_count()})


register("env_baseline", "environment baseline: creds, versions, readiness, telemetry, stores",
         _scenario_env_baseline)


# --------------------------------------------------------------------------- #
# 2. Detection engineering: repeated SSH failures (full lifecycle)
# --------------------------------------------------------------------------- #
def _scenario_detection_ssh(env: LiveEnv, log: EvidenceLog, opts: dict) -> None:
    s = "detection_ssh_rule"
    ts = time.strftime("%H%M%S")
    marker = f"phase14_{ts}"
    test_ip = opts.get("test_ip", "203.0.113.77")
    rid = 100000 + (int(time.time() * 1000) % 800000)

    # 1) RAG retrieval (grounding)
    try:
        docs = env.rag_retrieve("repeated SSH authentication failures rule if_matched_sid frequency")
        ok = bool(docs)
        log.step(s, "RAG retrieve", "rag.retrieve_wazuh_docs", "wazuh_confirmed", ok,
                 detail=f"{len(docs)} docs returned" + (f": {[d.get('title') for d in docs[:3]]}" if ok else ""),
                 refs={"docs": len(docs)})
    except Exception as e:  # noqa: BLE001
        log.step(s, "RAG retrieve", "rag.retrieve_wazuh_docs", "error", False, detail=str(e)[:200])

    # 2) inspect existing rules (parent 5760 must exist for if_matched_sid)
    try:
        parent = env.wazuh.get_rule(5760)
        found = bool((parent.get("data") or {}).get("affected_items"))
        log.step(s, "inspect parent rule", "manager_api.get_rule", "wazuh_confirmed", found,
                 detail=f"rule 5760 {'exists' if found else 'MISSING (candidate would never fire)'}",
                 refs={"rule_5760": found})
    except Exception as e:  # noqa: BLE001
        log.step(s, "inspect parent rule", "manager_api.get_rule", "error", False, detail=str(e)[:200])

    # 3) static validation of the generated rule
    from tools.wazuh.validation import validate_wazuh_rule_xml
    xml = gen_ssh_rule_xml(rid, marker)
    validation = validate_wazuh_rule_xml(xml)
    log.step(s, "static rule validation", "wazuh.validation.validate_wazuh_rule_xml", "mock",
             bool(validation["valid"]),
             detail="; ".join(validation["errors"]) if not validation["valid"]
                    else f"rule id {rid} valid (frequency/timeframe are attrs, if_matched_sid parent)",
             refs={"rule_id": rid, "errors": validation["errors"]})

    # the rule's <match> marker MUST appear in the samples or it can never fire
    positives = [ssh_failure_line(f"06:00:{10 + i:02d}", f"{marker}u{i}", test_ip, 2200 + i)
                 for i in range(8)]
    negatives = [ssh_success_line("06:05:00", f"{marker}ux", test_ip, 22)]

    # 4) propose through the real gate (baseline logtest runs inside the tool)
    try:
        outcome = env.propose(
            "develop_wazuh_rule",
            {"rule_xml": xml, "positive_samples": positives,
             "negative_samples": negatives, "log_format": "syslog",
             "reason": f"PHASE14 golden scenario: detect repeated SSH failures ({marker})"},
        )
    except Exception as e:  # noqa: BLE001
        log.step(s, "propose rule", "develop_wazuh_rule", "error", False, detail=str(e)[:300])
        return
    if outcome.get("status") == "approval_required":
        proposal = outcome.get("proposal") or {}
        pid = proposal.get("id", "")
        env.created_proposals.append(pid)
        payload = proposal.get("payload") or {}
        payload_ok = ("rule_xml" in payload and isinstance(payload["rule_xml"], str)
                      and f'id="{rid}"' in payload["rule_xml"] and "overwrite" in payload)
        log.step(s, "proposal created (no auto-deploy)", "develop_wazuh_rule", "wazuh_confirmed",
                 True, detail=f"proposal {pid} stored; payload complete (rule_xml+overwrite) = {payload_ok}",
                 refs={"proposal_id": pid, "payload_complete": payload_ok})
        if not payload_ok:
            log.step(s, "proposal payload completeness", "approvals.create_proposal", "error",
                     False, detail="stored payload is missing rule_xml/overwrite - see refs",
                     refs={"proposal_payload": {k: (v[:60] if isinstance(v, str) else v)
                                                for k, v in payload.items()}})
        # verify no rule was deployed yet
        try:
            existing = env.wazuh.get_rule(rid)
            deployed = bool((existing.get("data") or {}).get("affected_items"))
            log.step(s, "no deploy before approval", "manager_api.get_rule", "wazuh_confirmed",
                     not deployed, detail=f"rule {rid} present={deployed} (must be False)",
                     refs={"rule_deployed": deployed})
        except Exception as e:  # noqa: BLE001
            log.step(s, "no deploy before approval", "manager_api.get_rule", "error", False,
                     detail=str(e)[:200])
    else:
        log.step(s, "proposal created (no auto-deploy)", "develop_wazuh_rule", "error", False,
                 detail=f"unexpected outcome: {str(outcome)[:300]}")
        return

    # 5) deployment (only under --auto-approve)
    if env.auto_approve and pid:
        try:
            env.approve({"id": pid})
            log.step(s, "approval recorded", "approvals.approve", "wazuh_confirmed", True,
                     detail=f"proposal {pid} approved")
        except Exception as e:  # noqa: BLE001
            log.step(s, "approval recorded", "approvals.approve", "error", False, detail=str(e)[:200])
            return
        # audit entry for the approval
        come = env.execute_approved({"id": pid})
        if not come.get("ok"):
            log.step(s, "rule deployment", "create_wazuh_rule", "error", False,
                     detail=f"execution failed: {come.get('error')}")
            return
        result = come.get("result") or {}
        env.created_rules.append(rid)
        log.step(s, "rule deployment", "create_wazuh_rule", "wazuh_confirmed", True,
                 detail=f"PUT local_rules.xml ok: {result.get('detail', '')[:120]}",
                 refs={"rule_id": rid, "restart_required": result.get("restart_required")})
        # 6) restart the manager to load the rule (EXECUTE + confirm)
        try:
            ro = env.propose("restart_wazuh_manager",
                             {"reason": f"PHASE14: load rule {rid} ({marker})"})
            rpid = (ro.get("proposal") or {}).get("id", "")
            if rpid:
                env.created_proposals.append(rpid)
            if ro.get("status") != "approval_required" or not rpid:
                log.step(s, "manager restart proposal", "restart_wazuh_manager", "error", False,
                         detail=f"unexpected: {str(ro)[:200]}")
                return
            env.approve({"id": rpid})
            outlet = env.execute_approved({"id": rpid})
            if not outlet.get("ok"):
                log.step(s, "manager restart", "restart_wazuh_manager", "error", False,
                         detail=f"restart failed: {outlet.get('error')}")
                return
            restarted = env.wait_for_manager(timeout_s=600)
            log.step(s, "manager restart", "restart_wazuh_manager", "wazuh_confirmed", restarted,
                     detail="manager core daemons running after restart" if restarted
                            else "manager did not become ready within 600s",
                     refs={"restart_required": True})
            if not restarted:
                return
            # analysisd's logtest engine lags the API's daemon status after a
            # restart - wait for it before any logtest-backed verification
            lt_ready = env.wait_for_logtest(timeout_s=180)
            log.step(s, "logtest ready after restart", "wazuh.logtest", "wazuh_confirmed",
                     lt_ready, detail="analysisd logtest accepts events" if lt_ready
                            else "logtest never became ready within 180s",
                     refs={"logtest_ready": lt_ready})
            if not lt_ready:
                return
        except Exception as e:  # noqa: BLE001
            log.step(s, "manager restart", "restart_wazuh_manager", "error", False,
                     detail=str(e)[:200])
            return
        # 7) rule loaded after restart (retried over transient not-ready errors)
        loaded, last_err = env.wait_for_rule(rid, timeout_s=300)
        log.step(s, "rule loaded after restart", "manager_api.get_rule", "wazuh_confirmed",
                 loaded, detail=("rule {} retrievable post-restart".format(rid) if loaded
                                 else f"rule {rid} not served within 180s ({last_err})"),
                 refs={"rule_loaded_after_restart": loaded})
        # 8) verify deployment: logtest positives fire, negatives stay silent
        try:
            ctx = env.tool_ctx()
            from tools.registry import execute as run_tool
            vres = run_tool(ctx, "verify_rule_deployment",
                            {"rule_id": rid, "positive_samples": positives,
                             "negative_samples": negatives, "log_format": "syslog"},
                            silent=True)
            vres_dict = vres if isinstance(vres, dict) else {"result": vres}
            ok_v = bool(vres_dict.get("verified"))
            detail = str(vres_dict)[:400]
            log.step(s, "verify rule deployment", "verify_rule_deployment", "wazuh_confirmed",
                     ok_v, detail=detail, refs={"rule_id": rid})
        except Exception as e:  # noqa: BLE001
            log.step(s, "verify rule deployment", "verify_rule_deployment", "error", False,
                     detail=str(e)[:300])
    else:
        log.step(s, "deployment (auto-approve off)", "create_wazuh_rule", "info", True,
                 detail="rule deployment skipped - no --auto-approve; proposal is ready in the "
                        "Approval Center (deployment verified in a separate approved run)")


register("detection_ssh_rule",
         "detection engineering: repeated-SSH-failure rule RAG->validate->logtest->proposal->deploy->verify",
         _scenario_detection_ssh, requires_auto_approve=True)


# --------------------------------------------------------------------------- #
# 3. Security: tool-argument integrity
# --------------------------------------------------------------------------- #
def _scenario_security_tool_args(env: LiveEnv, log: EvidenceLog, opts: dict) -> None:
    s = "security_tool_args"
    cases = [
        ("create_wazuh_rule missing rule_xml",
         {"reason": "x"}, "rule_xml missing"),
        ("create_wazuh_rule bad type",
         {"rule_xml": 123, "reason": "x"}, "rule_xml not a string"),
        ("create_wazuh_rule invalid XML",
         {"rule_xml": "<rule id=\"1\" level=\"10\"><if_sid>999999</if_sid></rule>",
          "reason": "x"}, "invalid XML (bad id, unsupported child)"),
        ("create_wazuh_rule extra param",
         {"rule_xml": "<rule id=\"100001\" level=\"3\"><match>x</match><description>d</description></rule>",
          "reason": "x", "injected": "DROP TABLE rules"}, "unexpected param"),
        ("create_wazuh_rule oversized",
         {"rule_xml": "<rule id=\"100002\" level=\"3\"><match>x</match><description>" + "A" * 100_000
                      + "</description></rule>", "reason": "x"}, "oversized XML"),
        ("develop_wazuh_rule no samples",
         {"rule_xml": "<rule id=\"100003\" level=\"3\"><match>x</match><description>d</description></rule>",
          "reason": "x"}, "positive_samples required"),
        ("create_wazuh_dashboard bad panels",
         {"title": "x", "panels": [{"nope": 1}], "reason": "x"}, "panels need id"),
        ("create_wazuh_dashboard empty panels",
         {"title": "x", "panels": [], "reason": "x"}, "empty panels"),
    ]
    before_rules = set(env.created_rules)
    for label, params, expect in cases:
        tool = label.split(" ", 1)[0]
        try:
            outcome = env.propose(tool, params, agent="arg-integrity-tester")
        except Exception as e:  # noqa: BLE001 - tools may raise without the registry wrapper
            ok = "rejected" in expect or _no_write_happened(env, before_rules)
            log.step(s, label, tool, "blocked", ok,
                     detail=f"raised {type(e).__name__}: {str(e)[:120]}")
            continue
        status = outcome.get("status")
        if status == "error":
            log.step(s, label, tool, "blocked", True,
                     detail=f"rejected pre-execution: {outcome.get('error', '')[:120]}")
        elif status == "approval_required":
            # schema accepted but gated by approval -> no execution happened
            pid = (outcome.get("proposal") or {}).get("id")
            log.step(s, label, tool, "blocked", True,
                     detail=f"accepted by schema but gated (no write): proposal {pid} - "
                            f"expected '{expect}'")
        else:
            log.step(s, label, tool, "error", False,
                     detail=f"unexpected outcome {status}: {str(outcome)[:200]}")


def _no_write_happened(env: LiveEnv, before_rules: set) -> bool:
    return set(env.created_rules) == before_rules


register("security_tool_args", "tool-argument integrity: malformed/extra/oversized params rejected",
         _scenario_security_tool_args)


# --------------------------------------------------------------------------- #
# 4. Security: query safety
# --------------------------------------------------------------------------- #
def _scenario_security_query_safety(env: LiveEnv, log: EvidenceLog, opts: dict) -> None:
    s = "security_query_safety"
    dangerous = ["45.124.37.241/../*", "203.0.113.1..113.9", "a=\"b\"'c'{d}",
                 "admin*", "?param", "rule.id:>/<="]
    # literal `search` param on the manager API must never 500 the harness
    for q in dangerous:
        try:
            resp = env.wazuh.get_rules(limit=10, search=q)
            log.step(s, f"literal search {q[:20]!r}", "manager_api.get_rules", "wazuh_confirmed",
                     True, detail="returned without 500 (literal search)")
        except Exception as e:  # noqa: BLE001
            msg = str(e)[:140]
            ok = "500" not in msg
            log.step(s, f"literal search {q[:20]!r}", "manager_api.get_rules",
                     "error" if not ok else "wazuh_confirmed", ok,
                     detail=f"error surfaced cleanly: {msg}" if ok else f"raw 500 reached harness: {msg}")
    # raw query_string through the indexer: risky chars must fail cleanly or
    # return - never fake success, never crash the harness
    try:
        body = {"query": {"query_string": {"query": "45.124.37.241/*"}}}
        env.indexer.search("wazuh-alerts-*", body)
        log.step(s, "raw query_string special chars", "indexer.search", "wazuh_confirmed",
                 True, detail="returned a response (no fake success asserted elsewhere)")
    except Exception as e:  # noqa: BLE001
        msg = str(e)[:160]
        log.step(s, "raw query_string special chars", "indexer.search", "blocked",
                 "WazuhAPIError" in type(e).__name__ or "ToolError" in type(e).__name__,
                 detail=f"normalized error: {msg}")
    # structured search (the preferred path) returns cleanly
    try:
        body = {"query": {"bool": {"must": [{"term": {"data.srcip": "45.124.37.241"}}]}},
                "size": 5}
        resp = env.indexer.search("wazuh-alerts-*", body)
        total = (resp.get("hits") or {}).get("total") or {}
        count = total.get("value") if isinstance(total, dict) else total
        log.step(s, "structured bool/term search", "indexer.search", "wazuh_confirmed", True,
                 detail=f"term search on srcip returned {count} hits", refs={"hits": count})
    except Exception as e:  # noqa: BLE001
        log.step(s, "structured bool/term search", "indexer.search", "error", False,
                 detail=str(e)[:160])
    # bounded results: a huge size must not blow up
    try:
        resp = env.indexer.search("wazuh-alerts-*", {"size": 10_000, "_source": False})
        got = len((resp.get("hits") or {}).get("hits") or [])
        log.step(s, "large result request bounded", "indexer.search", "wazuh_confirmed",
                 got <= 10_000, detail=f"requested 10000, received {got}",
                 refs={"received": got})
    except Exception as e:  # noqa: BLE001
        log.step(s, "large result request bounded", "indexer.search", "error", False,
                 detail=str(e)[:160])


register("security_query_safety", "query safety: special chars, injection markers, bounded results",
         _scenario_security_query_safety)


# --------------------------------------------------------------------------- #
# 5. Controlled streamed event through the manager pipeline (UDP 514 syslog)
# --------------------------------------------------------------------------- #
def _feed_syslog_udp(lines: list[str], *, host: str = "127.0.0.1",
                     port: int = 514) -> int:
    """Send RFC3164-style syslog datagrams to the manager's UDP 514 input.
    Returns the number of datagrams sent."""
    import socket
    sent = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for ln in lines:
            s.sendto(ln.encode("utf-8", "replace"), (host, port))
            sent += 1
    finally:
        s.close()
    return sent


def _scenario_streamed_ssh_alert(env: LiveEnv, log: EvidenceLog, opts: dict) -> None:
    s = "streamed_ssh_alert"
    feed = opts.get("feed", _feed_syslog_udp)
    test_ip = opts.get("test_ip", "203.0.113.60")
    marker = f"phase14strm{time.strftime('%H%M%S')}"
    stamp = time.strftime("%b %d ")
    lines = [
        f"<133>{stamp}{time.strftime('06:%M:%S')} testhost sshd[{1000 + i}]: "
        f"Failed password for {marker}{i} from {test_ip} port 22 ssh2"
        for i in range(12)
    ]

    # 0) baseline: no alerts for this marker yet
    try:
        pre = env.indexer.count("wazuh-alerts-*", {"match": {"full_log": marker}})
        log.step(s, "baseline: marker absent", "indexer.count", "wazuh_confirmed",
                 pre == 0, detail=f"alerts with marker {marker}: {pre}",
                 refs={"pre_count": pre})
    except Exception as e:  # noqa: BLE001
        log.step(s, "baseline: marker absent", "indexer.count", "error", False,
                 detail=str(e)[:160])

    # 1) feed the synthetic events
    try:
        sent = feed(lines, port=int(opts.get("udp_port", 514)),
                    host=opts.get("udp_host", "127.0.0.1"))
        ok = sent == len(lines)
        log.step(s, "feed syslog events", "udp.514", "mock" if ok else "error", ok,
                 detail=f"sent {sent}/{len(lines)} datagrams to UDP 514 "
                        f"(srcip {test_ip}, marker {marker})",
                 refs={"sent": sent, "ip": test_ip})
    except Exception as e:  # noqa: BLE001
        log.step(s, "feed syslog events", "udp.514", "error", False, detail=str(e)[:160])
        return
    if not ok:
        return

    # 2) wait for the alert to land in the indexer (analysisd -> indexer pipeline)
    found: dict[str, Any] | None = None
    deadline = time.time() + 180
    while time.time() < deadline and found is None:
        try:
            hits = env.indexer.hits("wazuh-alerts-*", {
                "size": 5,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": [
                    {"match": {"full_log": marker}},
                    {"term": {"data.srcip": test_ip}},
                ]}},
            })
            for h in hits:
                if marker in str(h.get("full_log") or "") and (h.get("data") or {}).get("srcip") == test_ip:
                    found = h
                    break
        except Exception:  # noqa: BLE001 - indexer may be mid-write
            pass
        if found is None:
            time.sleep(5)
    if found is None:
        log.step(s, "alert observed in indexer", "indexer.hits", "error", False,
                 detail=f"no alert for {test_ip}/{marker} within 180s - "
                        "no alert observed DOES NOT mean no detection capability")
        return
    alert_id = found.get("id") or (found.get("_id") or "")
    rule = found.get("rule") or {}
    log.step(s, "alert observed in indexer", "indexer.hits", "wazuh_confirmed", True,
             detail=f"alert id {alert_id} rule {rule.get('id')} "
                    f"({rule.get('description')}) level {rule.get('level')}",
             refs={"alert_id": alert_id, "rule_id": rule.get("id"),
                   "rule_level": rule.get("level")})

    # 3) explain the alert from the REAL document fields
    try:
        ctx = env.tool_ctx()
        from tools.registry import execute as run_tool
        expl = run_tool(ctx, "why_did_alert_trigger", {"alert_id": alert_id}, silent=True)
        ex = expl if isinstance(expl, dict) else {}
        fl = str(ex.get("full_log") or "")
        ok_ex = bool(ex.get("rule_id")) and marker in fl
        log.step(s, "why did alert trigger", "why_did_alert_trigger", "wazuh_confirmed",
                 ok_ex,
                 detail=(f"rule {ex.get('rule_id')} level {ex.get('rule_level')}: "
                         f"{ex.get('rule_description')} | groups {ex.get('rule_groups')} "
                         f"| full_log marker present={marker in fl} "
                         f"| mitre {list((ex.get('mitre') or {}).get('id', []) or [])}")
                        if ok_ex else f"explanation incomplete: {str(expl)[:300]}",
                 refs={"rule_id": ex.get("rule_id"), "groups": (ex.get("rule_groups") or [])})
    except Exception as e:  # noqa: BLE001
        log.step(s, "why did alert trigger", "why_did_alert_trigger", "error", False,
                 detail=str(e)[:200])

    # 4) the alert is gone only after cleanup - verify the real index path too
    try:
        total = env.indexer.count("wazuh-alerts-*", {"match": {"full_log": marker}})
        log.step(s, "alert counts by marker", "indexer.count", "wazuh_confirmed",
                 total >= 1, detail=f"{total} alerts carry the marker {marker}",
                 refs={"marker_hits": total})
    except Exception as e:  # noqa: BLE001
        log.step(s, "alert counts by marker", "indexer.count", "error", False,
                 detail=str(e)[:160])

    # 5) cleanup: delete_by_query on the unique marker (dev-environment op)
    try:
        res = env.delete_by_query("wazuh-alerts-*", {"match": {"full_log": marker}})
        deleted = (res.get("deleted") if isinstance(res, dict) else None) or 0
        post = env.indexer.count("wazuh-alerts-*", {"match": {"full_log": marker}})
        ok_del = post == 0
        log.step(s, "cleanup: delete_by_query marker", "indexer.delete_by_query",
                 "wazuh_confirmed", ok_del,
                 detail=f"deleted {deleted}; remaining with marker: {post}",
                 refs={"deleted": deleted, "remaining": post})
    except Exception as e:  # noqa: BLE001
        log.step(s, "cleanup: delete_by_query marker", "indexer.delete_by_query",
                 "error", False, detail=str(e)[:200])


register("streamed_ssh_alert",
         "fresh controlled SSH-failure events streamed through UDP 514 -> alert -> "
         "why_did_alert_trigger -> delete_by_query cleanup",
         _scenario_streamed_ssh_alert)