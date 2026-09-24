"""
PHASE 13: offline tests for the engineer tool engines - investigation,
detection, dashboard, detection-gaps, and the registry permission gate.

Everything is mocked (ToolContext with MagicMock wazuh/indexer): no live
Wazuh, no network, and no `data/` file writes (approvals.create_proposal /
audit.audit_log are patched wherever the registry is exercised).

Run: cd soc-agent && MOCK_MODE=true python3 -m unittest tests.test_engine_tools -v
"""
from __future__ import annotations
import json
import os
import unittest
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

from tools.base import ApprovalRequired, ToolContext, ToolError, ToolParamError


def make_ctx(wazuh=None, indexer=None, approval=None) -> ToolContext:
    return ToolContext(
        wazuh=wazuh or mock.MagicMock(),
        indexer=indexer or mock.MagicMock(),
        approval=approval,
    )


LOCAL_RULES_TEMPLATE = """<!-- Local rules -->
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
  </rule>
</group>
"""

RULE_5760 = {"id": 5760, "level": 5,
             "description": "sshd: authentication failed.",
             "groups": ["authentication_failures"],
             "details": {"match": "Failed password|Failed keyboard|authentication error"}}


class TestInvestigationTools(unittest.TestCase):
    """tools/investigate/investigator.py - indexed evidence, no LLM guessing."""

    @staticmethod
    def _bucket(key, count):
        return {"key": key, "doc_count": count,
                "max_level": {"value": 10.0},
                "first_seen": {"value_as_string": "2026-09-23T10:00:00.000Z"},
                "last_seen": {"value_as_string": "2026-09-23T11:00:00.000Z"},
                "groups": {"buckets": [{"key": "web", "doc_count": count}]},
                "rules": {"buckets": [{"key": "31151", "doc_count": count}]},
                "agents": {"buckets": [{"key": "wks-web-01", "doc_count": count}]}}

    def test_top_attacking_ips_parses_buckets(self):
        from tools.investigate.investigator import top_attacking_ips
        indexer = mock.MagicMock()
        indexer.search.return_value = {"aggregations": {"top_src": {"buckets": [
            self._bucket("203.0.113.7", 12)]}}}
        out = top_attacking_ips(indexer, group="web", time_range="-24h")
        self.assertEqual(out["count"], 1)
        ip = out["ips"][0]
        self.assertEqual(ip["src_ip"], "203.0.113.7")
        self.assertEqual(ip["alert_count"], 12)
        self.assertEqual(ip["rule_groups"], ["web"])
        self.assertEqual(ip["top_rules"][0]["id"], "31151")
        indexer.search.assert_called_with("wazuh-alerts-*", mock.ANY)
        body = indexer.search.call_args[0][1]
        self.assertIn("top_src", body["aggs"])
        self.assertEqual(body["size"], 0)

    def test_top_attacking_ips_falls_back_to_attack_group(self):
        from tools.investigate.investigator import top_attacking_ips
        indexer = mock.MagicMock()
        empty = {"aggregations": {"top_src": {"buckets": []}}}
        full = {"aggregations": {"top_src": {"buckets": [self._bucket("198.51.100.9", 3)]}}}
        # run_for("web") is called first, then the fallback loop tries
        # "web" again before "attack" -> three searches in this build.
        indexer.search.side_effect = [empty, empty, full]
        out = top_attacking_ips(indexer, group="web", time_range="-24h")
        self.assertEqual(out["ips"][0]["src_ip"], "198.51.100.9")
        self.assertGreaterEqual(indexer.search.call_count, 2)

    def test_investigate_ip_builds_result(self):
        from tools.investigate.investigator import investigate_ip
        indexer = mock.MagicMock()

        def fake_search(index, body):
            if index == "wazuh-archives-*":
                return {"hits": {"hits": [{"_source": {"timestamp": "t", "location": "loc",
                                                       "full_log": "failed pw",
                                                       "decoder": {"name": "sshd"}}}]}}
            return {"hits": {"total": {"value": 7}},
                    "aggregations": {
                        "rule_groups": {"buckets": [{"key": "web", "doc_count": 7}]},
                        "rules": {"buckets": [{"key": "31151", "doc_count": 7}]},
                        "agents": {"buckets": []},
                        "dst_ips": {"buckets": [{"key": "10.0.0.1", "doc_count": 7}]},
                        "dst_ports": {"buckets": []},
                        "max_level": {"value": 10.0},
                        "first_seen": {"value_as_string": "a"},
                        "last_seen": {"value_as_string": "b"},
                        "timeline": {"buckets": [{"key_as_string": "k", "doc_count": 2}]},
                        "mitre": {"buckets": [{"key": "T1110", "doc_count": 4}]}}}
        indexer.search.side_effect = fake_search
        out = investigate_ip(indexer, ip="203.0.113.7", time_range="-24h")
        self.assertEqual(out["ip"], "203.0.113.7")
        self.assertEqual(out["total_alerts"], 7)
        self.assertEqual(out["mitre_techniques"], ["T1110"])
        self.assertEqual(len(out["sample_events"]), 1)

    def test_investigate_ip_requires_ip(self):
        from tools.investigate.investigator import InvestigateIP
        with self.assertRaises(ToolParamError):
            InvestigateIP().run(make_ctx(), ip="")

    def test_why_did_alert_trigger_found(self):
        from tools.investigate.investigator import why_did_alert_trigger
        indexer = mock.MagicMock()

        def fake_search(index, body):
            if index == "wazuh-archives-*":
                return {"hits": {"hits": [{"_source": {"timestamp": "t2", "location": "l",
                                                       "full_log": "context"}}]}}
            return {"hits": {"hits": [{"_source": {
                "id": "ALT-1", "timestamp": "2026-09-23T10:00:00",
                "rule": {"id": 31151, "level": 10, "description": "x",
                         "groups": ["web"], "mitre": {"id": ["T1110"]}},
                "agent": {"name": "wks-01"},
                "full_log": "failed pw",
                "data": {"srcip": "203.0.113.7"}}}]}}
        indexer.search.side_effect = fake_search
        out = why_did_alert_trigger(indexer, alert_id="ALT-1")
        self.assertEqual(out["rule_id"], 31151)
        self.assertEqual(out["mitre"]["id"], ["T1110"])
        self.assertEqual(len(out["related_events"]), 1)

    def test_why_did_alert_trigger_missing_raises(self):
        from tools.investigate.investigator import why_did_alert_trigger
        indexer = mock.MagicMock()
        indexer.search.return_value = {"hits": {"hits": [{"_source": {"id": "OTHER"}}]}}
        with self.assertRaises(ToolError):
            why_did_alert_trigger(indexer, alert_id="ALT-9")


class TestDetectionEngine(unittest.TestCase):
    """tools/detection/detection_engine.py - static validation, deterministic
    proposals, and frequency-aware post-deploy verification."""

    FREQ_RULE = ('<rule id="105563" level="10" frequency="3" timeframe="60">\n'
                 '  <if_matched_sid>5760</if_matched_sid>\n'
                 '  <description>Repeated SSH authentication failures</description>\n'
                 '</rule>')

    PLAIN_RULE = ('<rule id="105565" level="5">\n'
                  '  <match>Failed password</match>\n'
                  '  <description>Detects a failed SSH password</description>\n'
                  '</rule>')

    @staticmethod
    def _no_alert(token="tok"):
        return {"data": {"alert": False, "output": {"rule": {}}, "codemsg": 0, "token": token}}

    def _manager_ctx(self):
        wazuh = mock.MagicMock()
        wazuh.get_rules_file.return_value = LOCAL_RULES_TEMPLATE

        def fake_get_rules(**kw):
            q = kw.get("q") or ""
            if kw.get("limit") == 100:
                return {"data": {"affected_items": [RULE_5760], "total_affected_items": 1}}
            if "105563" in q:
                return {"data": {"affected_items": [], "total_affected_items": 0}}
            return {"data": {"affected_items": [RULE_5760], "total_affected_items": 1}}

        wazuh.get_rules.side_effect = fake_get_rules
        wazuh.run_logtest.return_value = self._no_alert()
        wazuh.end_logtest_session.return_value = {}
        wazuh.put_rules_file.return_value = {"message": "Rule was successfully uploaded",
                                             "data": {"affected_items": ["local_rules.xml"]}}
        return make_ctx(wazuh=wazuh)

    # -- develop_wazuh_rule ------------------------------------------- #
    def test_child_element_frequency_rejected_without_manager_call(self):
        from tools.detection.detection_engine import DevelopWazuhRule
        bad = ('<rule id="105564" level="10">\n'
               '  <match>Failed password</match>\n'
               '  <frequency>3</frequency>\n'
               '  <timeframe>60</timeframe>\n'
               '  <description>x</description>\n'
               '</rule>')
        ctx = make_ctx()
        with self.assertRaises(ToolError) as cm:
            DevelopWazuhRule().run(ctx, rule_xml=bad,
                                   positive_samples=["Failed password for root"],
                                   reason="test")
        self.assertIn("must be a rule ATTRIBUTE", str(cm.exception))
        ctx.wazuh.get_rules_file.assert_not_called()
        ctx.wazuh.run_logtest.assert_not_called()

    def test_develop_proposes_rerunnable_payload(self):
        from tools.detection.detection_engine import DevelopWazuhRule
        ctx = self._manager_ctx()
        with self.assertRaises(ApprovalRequired) as cm:
            DevelopWazuhRule().run(ctx, rule_xml=self.FREQ_RULE,
                                   positive_samples=["p1", "p2"],
                                   negative_samples=["n1"],
                                   reason="golden rule")
        proposed = cm.exception.proposed_action
        self.assertEqual(proposed["action"], "create_wazuh_rule")
        # PHASE 12 invariant: the stored payload is a re-runnable call to the
        # same tool with its own input params - not a display snapshot.
        self.assertEqual(proposed["payload"],
                         {"rule_xml": self.FREQ_RULE, "overwrite": False,
                          "reason": "golden rule"})
        self.assertIn("105563", proposed.get("generated_config", ""))
        # planning must never write to the manager
        ctx.wazuh.put_rules_file.assert_not_called()

    def test_develop_executes_with_matching_approval(self):
        from tools.detection.detection_engine import DevelopWazuhRule
        ctx = self._manager_ctx()
        ctx.approval = {"action": "create_wazuh_rule"}
        out = DevelopWazuhRule().run(ctx, rule_xml=self.FREQ_RULE,
                                     positive_samples=["p1"],
                                     negative_samples=["n1"],
                                     reason="golden rule")
        self.assertEqual(out["status"], "executed")
        self.assertEqual(out["rule_id"], 105563)
        self.assertTrue(out["restart_required"])
        ctx.wazuh.put_rules_file.assert_called_once()
        new_content = ctx.wazuh.put_rules_file.call_args[0][1]
        self.assertIn("105563", new_content)

    def test_develop_requires_positive_samples(self):
        from tools.detection.detection_engine import DevelopWazuhRule
        ctx = make_ctx()
        with self.assertRaises(ToolError):
            DevelopWazuhRule().run(ctx, rule_xml=self.PLAIN_RULE,
                                   positive_samples=[], reason="x")

    # -- verify_rule_deployment --------------------------------------- #
    def test_verify_frequency_rule_uses_single_session(self):
        from tools.detection.detection_engine import VerifyRuleDeployment
        wazuh = mock.MagicMock()
        wazuh.get_rules_file.return_value = (
            '<group name="local,">\n' + self.FREQ_RULE + '\n</group>\n')
        tokens_seen = []

        def fake_logtest(log, log_format=None, location=None, token=None):
            tokens_seen.append(token)
            idx = len(tokens_seen)
            if idx <= 2:
                rid, desc = 5760, "sshd: authentication failed."
            elif idx == 3:
                rid, desc = 105563, "Repeated SSH authentication failures"
            else:
                rid, desc = 5715, "sshd: authentication succeeded."
            data = {"codemsg": 0, "alert": True,
                    "output": {"rule": {"id": rid, "level": 5, "description": desc},
                               "decoder": {"name": "sshd"}}}
            if idx <= 3:
                data["token"] = "tok1"
            return {"data": data}

        wazuh.run_logtest.side_effect = fake_logtest
        wazuh.end_logtest_session.return_value = {}
        ctx = make_ctx(wazuh=wazuh)
        pos = ["Failed password for root #1", "Failed password for root #2",
               "Failed password for root #3"]
        out = VerifyRuleDeployment().run(ctx, rule_id=105563, positive_samples=pos,
                                         negative_samples=["Accepted password for admin"])
        self.assertTrue(out["frequency_rule"])
        self.assertTrue(out["verified"])
        self.assertEqual(out["positive_pass"], "1/3")   # fires on the 3rd (threshold)
        self.assertEqual(out["negative_pass"], "1/1")
        # all positives shared ONE session (token threaded); the negative got
        # a fresh session.
        self.assertEqual(tokens_seen, [None, "tok1", "tok1", None])
        wazuh.end_logtest_session.assert_called_once_with("tok1")

    def test_verify_plain_rule(self):
        from tools.detection.detection_engine import VerifyRuleDeployment
        wazuh = mock.MagicMock()
        wazuh.get_rules_file.return_value = (
            '<group name="local,">\n' + self.PLAIN_RULE + '\n</group>\n')

        def fake_logtest(log, log_format=None, location=None, token=None):
            if "Accepted" in log:
                rid, desc = 5715, "sshd: authentication succeeded."
            else:
                rid, desc = 105565, "Detects a failed SSH password"
            return {"data": {"codemsg": 0, "alert": True,
                             "output": {"rule": {"id": rid, "level": 5, "description": desc},
                                        "decoder": {"name": "sshd"}}}}

        wazuh.run_logtest.side_effect = fake_logtest
        wazuh.end_logtest_session.return_value = {}
        ctx = make_ctx(wazuh=wazuh)
        out = VerifyRuleDeployment().run(ctx, rule_id=105565,
                                         positive_samples=["Failed password for root"],
                                         negative_samples=["Accepted password for admin"])
        self.assertFalse(out["frequency_rule"])
        self.assertTrue(out["verified"])
        self.assertEqual(out["positive_pass"], "1/1")
        self.assertEqual(out["negative_pass"], "1/1")

    def test_verify_rule_gone_reports_false(self):
        from tools.detection.detection_engine import VerifyRuleDeployment
        wazuh = mock.MagicMock()
        wazuh.get_rules_file.return_value = LOCAL_RULES_TEMPLATE
        wazuh.run_logtest.return_value = {
            "data": {"codemsg": 0, "alert": True,
                     "output": {"rule": {"id": 5760, "level": 5,
                                         "description": "sshd: authentication failed."},
                                "decoder": {"name": "sshd"}}}}
        wazuh.end_logtest_session.return_value = {}
        ctx = make_ctx(wazuh=wazuh)
        out = VerifyRuleDeployment().run(ctx, rule_id=105565,
                                         positive_samples=["Failed password"],
                                         negative_samples=["Accepted"])
        self.assertFalse(out["verified"])
        self.assertEqual(out["positive_pass"], "0/1")


class TestDashboardEngine(unittest.TestCase):
    """tools/dashboard/engine.py - evidence-backed, approval-gated design."""

    @staticmethod
    def _ctx_with_schema():
        indexer = mock.MagicMock()
        indexer.field_caps.return_value = {"data.srcip": "keyword", "agent.name": "keyword",
                                           "rule.groups": "keyword", "rule.level": "long"}
        indexer.search.return_value = {"hits": {"total": {"value": 42}}, "took": 3}
        return make_ctx(indexer=indexer)

    def test_design_proposes_rerunnable_payload(self):
        from tools.dashboard.engine import DesignDetectionDashboard
        ctx = self._ctx_with_schema()
        with mock.patch("tools.dashboard.engine._find_index_pattern", return_value="idx-abc"):
            with self.assertRaises(ApprovalRequired) as cm:
                DesignDetectionDashboard().run(ctx, title="Web Server Attacks", focus="web",
                                               description="web attack dashboard",
                                               time_range="-7d", reason="golden dashboard")
        proposed = cm.exception.proposed_action
        self.assertEqual(proposed["action"], "design_detection_dashboard")
        # PHASE 12 invariant: payload is the tool's own input params.
        self.assertEqual(proposed["payload"], {
            "title": "Web Server Attacks", "focus": "web",
            "description": "web attack dashboard",
            "time_range": "-7d", "reason": "golden dashboard"})
        cfg = proposed.get("generated_config") or {}
        self.assertIn("visualizations", cfg)
        self.assertIn("panelsJSON", cfg)
        # every panel query was verified against the (mocked) indexer
        self.assertGreaterEqual(ctx.indexer.search.call_count, 4)

    def test_invalid_focus_rejected(self):
        from tools.dashboard.engine import DesignDetectionDashboard
        ctx = self._ctx_with_schema()
        with self.assertRaises(ToolError):
            DesignDetectionDashboard().run(ctx, title="t", focus="windows", reason="r")

    def test_schema_failure_aborts(self):
        from tools.dashboard.engine import DesignDetectionDashboard
        indexer = mock.MagicMock()
        indexer.field_caps.side_effect = RuntimeError("indexer down")
        ctx = make_ctx(indexer=indexer)
        with self.assertRaises(ToolError) as cm:
            DesignDetectionDashboard().run(ctx, title="t", focus="web", reason="r")
        self.assertIn("Cannot read indexer schema", str(cm.exception))

    # -- pattern discovery: never bind alert panels to a non-alert index family --

    def test_find_index_pattern_prefers_alerts_over_statistics(self):
        # Regression: the API can list wazuh-statistics-* first; it must never
        # win over the alerts pattern (bounds a dashboard that renders empty).
        from tools.dashboard import engine
        resp = {"saved_objects": [
            {"id": "wazuh-statistics-*", "attributes": {"title": "wazuh-statistics-*"}},
            {"id": "abcd-1234", "attributes": {"title": "wazuh-alerts-*"}},
        ]}
        with mock.patch("tools.dashboard.engine.dashboards_request", return_value=resp):
            self.assertEqual(engine._find_index_pattern(), "abcd-1234")
        # id may also be the pattern id itself, without a title match.
        resp = {"saved_objects": [
            {"id": "wazuh-statistics-*", "attributes": {"title": "wazuh-statistics-*"}},
            {"id": "wazuh-alerts-*", "attributes": {"title": "Wazuh alerts"}},
        ]}
        with mock.patch("tools.dashboard.engine.dashboards_request", return_value=resp):
            self.assertEqual(engine._find_index_pattern(), "wazuh-alerts-*")

    def test_find_index_pattern_rejects_non_alert_families(self):
        from tools.dashboard import engine
        resp = {"saved_objects": [
            {"id": "wazuh-statistics-*", "attributes": {"title": "wazuh-statistics-*"}},
            {"id": "wazuh-archives-*", "attributes": {"title": "wazuh-archives-*"}},
            {"id": "wazuh-monitoring-*", "attributes": {"title": "wazuh-monitoring-*"}},
        ]}
        with mock.patch("tools.dashboard.engine.dashboards_request", return_value=resp):
            self.assertIsNone(engine._find_index_pattern())
        # caller falls back to the conventional alerts id.
        with mock.patch("tools.dashboard.engine._find_index_pattern", return_value=None) as m:
            from tools.dashboard.engine import DesignDetectionDashboard
            ctx = self._ctx_with_schema()
            with self.assertRaises(ApprovalRequired) as cm:
                DesignDetectionDashboard().run(ctx, title="t", focus="web", reason="r")
            self.assertEqual(cm.exception.proposed_action["generated_config"]["index_pattern"],
                             "wazuh-alerts-*")

    def test_find_index_pattern_unreachable_returns_none(self):
        from tools.dashboard import engine
        with mock.patch("tools.dashboard.engine.dashboards_request",
                        side_effect=RuntimeError("dashboards down")):
            self.assertIsNone(engine._find_index_pattern())

    # -- proposal is a complete, resolvable, OSD-openable saved-object bundle --

    def test_proposal_bundle_is_complete_and_resolvable(self):
        from tools.dashboard.engine import DesignDetectionDashboard
        ctx = self._ctx_with_schema()
        with mock.patch("tools.dashboard.engine._find_index_pattern", return_value="idx-abc"):
            with self.assertRaises(ApprovalRequired) as cm:
                DesignDetectionDashboard().run(ctx, title="Web Server Attacks", focus="web",
                                               description="web attack dashboard",
                                               time_range="-7d", reason="golden dashboard")
        cfg = cm.exception.proposed_action["generated_config"]
        self.assertEqual(cfg["index_pattern"], "idx-abc")
        self.assertEqual(cfg["title"], "Web Server Attacks")
        bundle = cfg["saved_objects"]
        self.assertEqual([o["type"] for o in bundle].count("visualization"), 7)
        self.assertEqual([o["type"] for o in bundle].count("dashboard"), 1)
        # panelsJSON ids must resolve exactly against the bundle's visualization ids.
        dash = next(o for o in bundle if o["type"] == "dashboard")
        panel_ids = {p["id"] for p in json.loads(dash["attributes"]["panelsJSON"])}
        vis_ids = {o["id"] for o in bundle if o["type"] == "visualization"}
        self.assertEqual(panel_ids, vis_ids)
        self.assertEqual(dash["id"], "dashboard-web-server-attacks")
        # every visualization is a full saved object: visState + searchSourceJSON
        # (index + 7d window + web filter) + index-pattern reference.
        term_web_seen = False
        for vis in (o for o in bundle if o["type"] == "visualization"):
            attrs = vis["attributes"]
            self.assertIn("visState", attrs)
            ss = json.loads(attrs["kibanaSavedObjectMeta"]["searchSourceJSON"])
            self.assertEqual(ss["index"], "idx-abc")
            filters = {list(f["term"])[0]: f["term"] for f in ss["filter"] if "term" in f}
            if filters.get("rule.groups") == {"rule.groups": "web"}:
                term_web_seen = True
            self.assertTrue(any("range" in f and "timestamp" in f["range"] for f in ss["filter"]),
                            f"{vis['id']} missing 7d range filter")
            self.assertEqual(vis["references"][0]["id"], "idx-abc")
        self.assertTrue(term_web_seen, "no visualization carries the rule.groups: web filter")

    # -- execution creates OSD-openable saved objects (searchSourceJSON attached) --

    def test_executed_saved_objects_include_search_source(self):
        from tools.dashboard.engine import DesignDetectionDashboard
        indexer = mock.MagicMock()
        indexer.field_caps.return_value = {"data.srcip": "keyword", "agent.name": "keyword",
                                           "rule.groups": "keyword", "rule.level": "long"}
        indexer.search.return_value = {"hits": {"total": {"value": 42}}, "took": 3}
        ctx = make_ctx(indexer=indexer, approval={"action": "design_detection_dashboard"})
        calls: list[tuple[str, dict]] = []

        def fake_request(method: str, path: str, body: dict | None = None, **kw) -> dict:
            calls.append((path, body))
            if path.endswith("/visualization"):
                return {"saved_object": {"id": f"sv-{len(calls)}", "type": "visualization"}}
            return {"saved_object": {"id": "dash-1", "type": "dashboard"}}

        with mock.patch("tools.dashboard.engine._find_index_pattern", return_value="idx-abc"), \
             mock.patch("tools.dashboard.engine.dashboards_request", side_effect=fake_request):
            out = DesignDetectionDashboard().run(ctx, title="Web Server Attacks", focus="web",
                                                 description="d", time_range="-7d", reason="r")
        self.assertEqual(out["status"], "executed")
        self.assertEqual(out["dashboard_id"], "dash-1")
        vis_bodies = [b for path, b in calls if path.endswith("/visualization")]
        self.assertEqual(len(vis_bodies), 7)
        web_seen = False
        for body in vis_bodies:
            attrs = body["attributes"]
            ss = json.loads(attrs["kibanaSavedObjectMeta"]["searchSourceJSON"])
            self.assertEqual(ss["index"], "idx-abc")
            self.assertTrue(any("range" in f for f in ss["filter"]))
            if any("term" in f and f["term"].get("rule.groups") == "web" for f in ss["filter"]):
                web_seen = True
            self.assertEqual(body["references"][0]["id"], "idx-abc")
        self.assertTrue(web_seen)
        dash_path, dash_body = [c for c in calls if c[0].endswith("/dashboard")][0]
        self.assertIn("kibanaSavedObjectMeta", dash_body["attributes"])
        refs = dash_body["references"]
        self.assertTrue(refs and all(r["type"] == "visualization" for r in refs))
        panel_ids = {p["id"] for p in json.loads(dash_body["attributes"]["panelsJSON"])}
        self.assertEqual(panel_ids, {r["id"] for r in refs})


class TestGapsEngine(unittest.TestCase):
    """tools/gaps/detection_gaps.py - 5-state coverage from real data."""

    SQLI_RULE = {"id": 92001, "level": 14,
                 "description": "Attempt to perform an SQL injection attack",
                 "groups": ["web"],
                 "details": {"match": "sql injection|union select"}}

    def _ctx(self, alerts=0, events=3):
        wazuh = mock.MagicMock()
        wazuh.get_rules.return_value = {"data": {"affected_items": [self.SQLI_RULE],
                                                 "total_affected_items": 1}}
        indexer = mock.MagicMock()
        indexer.search.side_effect = lambda index_name, body: {
            "hits": {"total": {"value": alerts if index_name.startswith("wazuh-alerts")
                               else events}}}
        return make_ctx(wazuh=wazuh, indexer=indexer)

    def test_classifies_partial_and_gap(self):
        from tools.gaps.detection_gaps import AnalyzeDetectionGaps
        ctx = self._ctx(alerts=0, events=3)
        out = AnalyzeDetectionGaps().run(ctx, target="web", time_range="-7d")
        by_name = {r["category"]: r for r in out["coverage"]}
        self.assertEqual(by_name["sql_injection"]["state"], "partial")  # rules but no alerts
        self.assertEqual(by_name["sql_injection"]["rules"], 1)
        self.assertEqual(by_name["xss"]["state"], "gap")               # activity, no rules
        self.assertEqual(len(out["gap_candidates"]), len(out["coverage"]))
        self.assertIn("need attention", out["summary"])

    def test_classifies_detected_and_unknown(self):
        from tools.gaps.detection_gaps import AnalyzeDetectionGaps
        ctx = self._ctx(alerts=5, events=0)
        out = AnalyzeDetectionGaps().run(ctx, target="web", time_range="-7d")
        by_name = {r["category"]: r for r in out["coverage"]}
        self.assertEqual(by_name["sql_injection"]["state"], "detected")
        self.assertEqual(by_name["xss"]["state"], "unknown")
        self.assertEqual(out["gap_candidates"], [])

    def test_unknown_target_rejected(self):
        from tools.gaps.detection_gaps import AnalyzeDetectionGaps
        ctx = make_ctx()
        with self.assertRaises(ToolError):
            AnalyzeDetectionGaps().run(ctx, target="windows")


class TestRegistryPermissionGate(unittest.TestCase):
    """tools/registry.py - the ONE place tools run: schema validation,
    permission gating, audit, and DATA-wrapping before the LLM sees results."""

    RULE = ('<rule id="105567" level="5">\n'
            '  <match>Failed password</match>\n'
            '  <description>PHASE 13 registry unit rule</description>\n'
            '</rule>')

    def setUp(self):
        self.wazuh = mock.MagicMock()
        self.indexer = mock.MagicMock()

    def test_read_tool_executes_immediately(self):
        from tools import registry
        self.wazuh.get_rules.return_value = {"data": {
            "affected_items": [RULE_5760], "total_affected_items": 1}}
        ctx = make_ctx(wazuh=self.wazuh, indexer=self.indexer)
        with mock.patch("audit.audit_log"):
            out = registry.execute(ctx, "get_wazuh_rules", {"limit": 5})
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["result"]["count"], 1)

    def test_propose_returns_approval_required_without_writing(self):
        from tools import registry
        self.wazuh.get_rules_file.return_value = LOCAL_RULES_TEMPLATE
        self.wazuh.put_rules_file.return_value = {"message": "ok"}
        ctx = make_ctx(wazuh=self.wazuh, indexer=self.indexer)
        with mock.patch("audit.audit_log") as ml, \
             mock.patch("approvals.create_proposal",
                        return_value={"id": "appr-123", "action": "create_wazuh_rule"}) as mc:
            out = registry.execute(ctx, "create_wazuh_rule",
                                   {"rule_xml": self.RULE, "reason": "unit test"})
        self.assertEqual(out["status"], "approval_required")
        self.assertEqual(out["proposal"]["id"], "appr-123")
        mc.assert_called_once()
        self.wazuh.put_rules_file.assert_not_called()
        ml.assert_called()  # the awaiting-approval row was audited

    def test_approved_write_executes(self):
        from tools import registry
        self.wazuh.get_rules_file.return_value = LOCAL_RULES_TEMPLATE
        self.wazuh.put_rules_file.return_value = {"message": "Rule was successfully uploaded"}
        ctx = make_ctx(wazuh=self.wazuh, indexer=self.indexer,
                       approval={"action": "create_wazuh_rule"})
        with mock.patch("audit.audit_log"):
            out = registry.execute(ctx, "create_wazuh_rule",
                                   {"rule_xml": self.RULE, "reason": "approved run"})
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["result"]["detail"], "Rule was successfully uploaded")
        self.wazuh.put_rules_file.assert_called_once()

    def test_mismatched_approval_is_denied(self):
        from tools import registry
        self.wazuh.get_rules_file.return_value = LOCAL_RULES_TEMPLATE
        ctx = make_ctx(wazuh=self.wazuh, indexer=self.indexer,
                       approval={"action": "delete_wazuh_rule"})
        with mock.patch("audit.audit_log"):
            out = registry.execute(ctx, "create_wazuh_rule",
                                   {"rule_xml": self.RULE, "reason": "x"})
        self.assertEqual(out["status"], "error")
        self.assertIn("Approval mismatch", out["error"])
        self.wazuh.put_rules_file.assert_not_called()

    def test_invalid_params_rejected_without_running(self):
        from tools import registry
        ctx = make_ctx(wazuh=self.wazuh, indexer=self.indexer)
        with mock.patch("audit.audit_log") as ml:
            out = registry.execute(ctx, "get_wazuh_rule", {})  # rule_id required
        self.assertEqual(out["status"], "error")
        self.assertIn("Missing required parameter: rule_id", out["error"])
        ml.assert_called_once()
        self.wazuh.get_rule.assert_not_called()

    def test_silent_returns_raw_result(self):
        from tools import registry
        self.wazuh.get_rules.return_value = {"data": {
            "affected_items": [], "total_affected_items": 0}}
        ctx = make_ctx(wazuh=self.wazuh, indexer=self.indexer)
        with mock.patch("audit.audit_log"):
            out = registry.execute(ctx, "get_wazuh_rules", {"limit": 5}, silent=True)
        self.assertIsInstance(out, dict)
        self.assertEqual(out.get("count"), 0)


class TestFrequencyValidation(unittest.TestCase):
    """tools/wazuh/validation.py - the PHASE 12 rule-RF constraints."""

    def test_frequency_requires_if_matched_sid_attribute_form(self):
        from tools.wazuh.validation import validate_wazuh_rule_xml
        with_parent = ('<rule id="105601" level="10" frequency="3" timeframe="60">\n'
                       '  <if_matched_sid>5760</if_matched_sid>\n'
                       '  <description>x</description>\n'
                       '</rule>')
        no_parent = ('<rule id="105602" level="10" frequency="3" timeframe="60">\n'
                     '  <if_sid>5760</if_sid>\n'
                     '  <description>x</description>\n'
                     '</rule>')
        self.assertTrue(validate_wazuh_rule_xml(with_parent)["valid"])
        v = validate_wazuh_rule_xml(no_parent)
        self.assertFalse(v["valid"])
        self.assertTrue(any("if_matched_sid" in e for e in v["errors"]))

    def test_child_element_timeframe_rejected(self):
        from tools.wazuh.validation import validate_wazuh_rule_xml
        bad = ('<rule id="105603" level="10">\n'
               '  <timeframe>60</timeframe>\n'
               '  <description>x</description>\n'
               '</rule>')
        v = validate_wazuh_rule_xml(bad)
        self.assertFalse(v["valid"])
        self.assertTrue(any("must be a rule ATTRIBUTE" in e for e in v["errors"]))

    def test_plain_rule_valid(self):
        from tools.wazuh.validation import validate_wazuh_rule_xml
        v = validate_wazuh_rule_xml(
            '<rule id="105604" level="5">\n'
            '  <match>Failed password</match>\n'
            '  <description>test</description>\n'
            '</rule>')
        self.assertTrue(v["valid"])


if __name__ == "__main__":
    unittest.main()