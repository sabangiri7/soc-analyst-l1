"""
Hermetic tests for the PHASE 14 live-validation framework.

These never touch a live Wazuh environment: clients are fakes and the
approval/audit stores are not written. The real live runs happen only through
`python scripts/live_validation.py --live`.

Run: MOCK_MODE=true python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from live_validation.evidence import Evidence, EvidenceLog
from live_validation.env import LiveEnv
from live_validation import scenarios as scen


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #
class FakeWazuh:
    def _authenticate(self):
        return "JWT " + "x" * 100

    def get(self, path, params=None):
        if path == "/manager/info":
            return {"data": {"affected_items": [{"version": "v4.14.7"}]}}
        if path == "/manager/status":
            return {"data": {"affected_items": [{
                "wazuh-analysisd": "running", "wazuh-db": "running",
                "wazuh-remoted": "running", "wazuh-authd": "running",
                "wazuh-modulesd": "running", "wazuh-apid": "running"}]}}
        return {"data": {"affected_items": []}}

    def get_manager_status(self):
        return self.get("/manager/status")

    def get_rule(self, rule_id):
        return {"data": {"affected_items": [{"id": rule_id}]} if rule_id == 5760 else []}

    def get_rules(self, **kw):
        return {"data": {"affected_items": []}}


class FakeIndexer:
    def search(self, index, body):
        return {"hits": {"total": {"value": 716}}}


class FakeKB:
    def counts(self):
        return {"playbooks": 0, "cases": 0, "lessons": 0, "wazuh_docs": 5}

    def search(self, query, top_k=3, collection="wazuh_docs"):
        return [{"id": "d1", "title": "frequency rules", "score": 0.9}]


def make_env(**kw) -> LiveEnv:
    env = LiveEnv(wazuh=FakeWazuh(), indexer=FakeIndexer(),
                  dashboards=lambda method, path, **kw2: {"total": 0},
                  approvals_path="/tmp/nonexistent-approvals.json",
                  audit_path="/tmp/nonexistent-audit.jsonl", **kw)
    env._kb = FakeKB()
    return env


# --------------------------------------------------------------------------- #
# evidence
# --------------------------------------------------------------------------- #
class EvidenceTests(unittest.TestCase):
    def test_invalid_result_kind_rejected(self):
        with self.assertRaises(ValueError):
            Evidence("s", "step", "t", "bogus_kind", True)

    def test_error_row_cannot_pass(self):
        with self.assertRaises(ValueError):
            Evidence("s", "step", "t", "error", True)

    def test_rollup_pass_and_fail(self):
        log = EvidenceLog()
        log.step("a", "ok", "t1", "wazuh_confirmed", True)
        log.step("a", "bad", "t2", "error", False, detail="boom")
        log.step("b", "ok", "t3", "wazuh_confirmed", True)
        st = log.scenario_status("a")
        self.assertEqual(st["status"], "FAIL")
        self.assertEqual(st["failed"], 1)
        self.assertEqual(st["failures"][0]["detail"], "boom")
        self.assertEqual(log.scenario_status("b")["status"], "PASS")
        self.assertFalse(log.all_pass())

    def test_matrix_and_json(self):
        log = EvidenceLog()
        log.step("a", "ok", "t1", "wazuh_confirmed", True)
        self.assertIn("a", log.matrix())
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
            path = fh.name
        try:
            log.to_json(path)
            data = json.loads(Path(path).read_text())
            self.assertEqual(data["summary"]["a"]["status"], "PASS")
            self.assertTrue(data["all_pass"])
        finally:
            Path(path).unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# env: propose / execute gates
# --------------------------------------------------------------------------- #
class EnvGateTests(unittest.TestCase):
    def setUp(self):
        self.env = make_env()

    @mock.patch("tools.registry.execute")
    def test_propose_routes_through_registry(self, reg):
        reg.return_value = {
            "status": "approval_required",
            "proposal": {"id": "appr-test123", "action": "create_wazuh_rule"},
        }
        outcome = self.env.propose("create_wazuh_rule", {"rule_xml": "<x/>", "reason": "r"})
        self.assertEqual(outcome["status"], "approval_required")
        self.assertEqual(outcome["proposal"]["id"], "appr-test123")

    @mock.patch("tools.registry.execute")
    def test_execute_approved_rejects_unapproved(self, reg):
        with mock.patch("approvals.get_proposal") as getp:
            getp.return_value = {"id": "p1", "status": "pending",
                                 "permission": "propose", "payload": {}}
            out = self.env.execute_approved({"id": "p1"})
        self.assertFalse(out["ok"])
        reg.assert_not_called()

    @mock.patch("tools.registry.execute")
    def test_execute_approved_requires_confirm_for_execute(self, reg):
        with mock.patch("approvals.get_proposal") as getp:
            getp.return_value = {"id": "p1", "status": "approved",
                                 "permission": "execute", "payload": {}}
            out = self.env.execute_approved({"id": "p1"})
        self.assertFalse(out["ok"])
        self.assertIn("confirm", out["error"])
        reg.assert_not_called()

    @mock.patch("tools.registry.execute")
    def test_execute_approved_with_confirm_runs_and_sets_approval(self, reg):
        self.env.confirm_execute = True
        reg.return_value = {"status": "ok", "result": {"status": "executed"}}
        with mock.patch("approvals.get_proposal") as getp:
            getp.return_value = {"id": "p1", "status": "approved", "permission": "execute",
                                 "action": "restart_wazuh_manager", "payload": {"a": 1}}
            out = self.env.execute_approved({"id": "p1"})
        self.assertTrue(out["ok"])
        ctx = reg.call_args[0][0]
        self.assertEqual(ctx.approval["id"], "p1")
        self.assertEqual(reg.call_args[0][1], "restart_wazuh_manager")

    @mock.patch("tools.registry.execute")
    def test_execute_approved_treats_status_error_as_failure(self, reg):
        reg.return_value = {"status": "error", "error": "api exploded"}
        with mock.patch("approvals.get_proposal") as getp:
            getp.return_value = {"id": "p1", "status": "approved",
                                 "permission": "propose", "payload": {}}
            out = self.env.execute_approved({"id": "p1"})
        self.assertFalse(out["ok"])
        self.assertIn("api exploded", out["error"])

    def test_preflight_happy_path(self):
        self.assertEqual(self.env.preflight(), [])

    def test_preflight_collects_problems(self):
        env = LiveEnv(wazuh=mock.Mock(_authenticate=mock.Mock(side_effect=RuntimeError("nope"))),
                      indexer=mock.Mock(search=mock.Mock(side_effect=Exception("es down"))),
                      dashboards=mock.Mock(side_effect=RuntimeError("dash down")))
        problems = env.preflight()
        self.assertTrue(any("manager API auth failed" in p for p in problems))
        self.assertTrue(any("indexer search failed" in p for p in problems))
        self.assertTrue(any("dashboards API failed" in p for p in problems))


# --------------------------------------------------------------------------- #
# scenarios (hermetic)
# --------------------------------------------------------------------------- #
class EnvBaselineScenarioTests(unittest.TestCase):
    def test_env_baseline_passes_with_fakes(self):
        env = make_env()
        log = scen.run_scenario(env, "env_baseline", {})
        st = log.scenario_status("env_baseline")
        self.assertEqual(st["status"], "PASS", st["failures"])


class DetectionScenarioTests(unittest.TestCase):
    def _proposal_from_params(self, pid, params, permission="propose", action="create_wazuh_rule"):
        return {"id": pid, "status": "pending", "permission": permission, "action": action,
                "payload": {"rule_xml": params["rule_xml"], "overwrite": False,
                            "reason": params.get("reason", "")}}

    def test_detection_stops_at_approval_gate_when_not_auto(self):
        env = make_env()

        def fake_propose(tool_name, params, agent="phase14-validator"):
            if tool_name == "develop_wazuh_rule":
                p = self._proposal_from_params("appr-det01", params)
                return {"status": "approval_required", "proposal": p}
            raise AssertionError(f"unexpected propose {tool_name}")

        with mock.patch.object(env, "propose", side_effect=fake_propose):
            log = scen.run_scenario(env, "detection_ssh_rule", {})
        st = log.scenario_status("detection_ssh_rule")
        self.assertEqual(st["status"], "PASS", st["failures"])
        # deployed-verify step must be the skipped-info variant
        rows = {i.step: i for i in log.scenario_items("detection_ssh_rule")}
        self.assertIn("deployment (auto-approve off)", rows)
        self.assertEqual(rows["deployment (auto-approve off)"].result_kind, "info")
        # proposal payload completeness was asserted true
        self.assertTrue(rows["proposal created (no auto-deploy)"].refs["payload_complete"])

    def test_detection_auto_approve_path(self):
        env = make_env(auto_approve=True, confirm_execute=True)
        restart_proposal = {"id": "appr-det03", "status": "approved", "permission": "execute",
                            "action": "restart_wazuh_manager", "payload": {"reason": "restart"}}

        def fake_propose(tool_name, params, agent="phase14-validator"):
            if tool_name == "develop_wazuh_rule":
                p = self._proposal_from_params("appr-det02", params)
                return {"status": "approval_required", "proposal": p}
            if tool_name == "restart_wazuh_manager":
                return {"status": "approval_required", "proposal": restart_proposal}
            raise AssertionError(f"unexpected propose {tool_name}")

        results = iter([
            {"ok": True, "result": {"status": "executed", "rule_id": 100905,
                                    "restart_required": True, "detail": "PUT ok"}},
            {"ok": True, "result": {"status": "executed"}},
        ])

        def get_rule(rid):
            # rule is only present once the scenario records it as deployed
            if rid == 5760 or rid in env.created_rules:
                return {"data": {"affected_items": [{"id": rid}]}}
            return {"data": {"affected_items": []}}

        with mock.patch.object(env, "propose", side_effect=fake_propose), \
             mock.patch.object(env, "approve", side_effect=lambda p, by=None: p), \
             mock.patch.object(env, "execute_approved", side_effect=lambda p: next(results)), \
             mock.patch.object(env, "wait_for_manager", return_value=True), \
             mock.patch.object(env.wazuh, "get_rule", side_effect=get_rule), \
             mock.patch("tools.registry.execute", return_value={
                 "status": "ok", "result": {"passed": True}}) as reg:
            log = scen.run_scenario(env, "detection_ssh_rule", {})
        st = log.scenario_status("detection_ssh_rule")
        self.assertEqual(st["status"], "PASS", st["failures"])
        rows = {i.step: i for i in log.scenario_items("detection_ssh_rule")}
        self.assertEqual(rows["rule deployment"].result_kind, "wazuh_confirmed")
        self.assertEqual(rows["manager restart"].result_kind, "wazuh_confirmed")
        self.assertTrue(rows["rule loaded after restart"].passed)
        self.assertTrue(rows["verify rule deployment"].passed)
        # verify_rule_deployment went through the real registry gate
        self.assertEqual(reg.call_args[0][1], "verify_rule_deployment")


class SecurityScenarioTests(unittest.TestCase):
    def test_tool_args_rejections(self):
        env = make_env()
        # schema-level rejections happen in the registry before any client call
        with mock.patch.object(env, "propose", side_effect=[
            {"status": "error", "error": "rule_xml: required"},
            {"status": "error", "error": "rule_xml must be a string"},
            {"status": "error", "error": "Rule failed static validation"},
            {"status": "approval_required", "proposal": {"id": "appr-sec"}},
            {"status": "error", "error": "oversized"},
            {"status": "error", "error": "positive_samples: required"},
            {"status": "error", "error": "panels must reference visualization ids"},
            {"status": "error", "error": "panels must be a list"},
        ]):
            log = scen.run_scenario(env, "security_tool_args", {})
        st = log.scenario_status("security_tool_args")
        self.assertEqual(st["status"], "PASS", st["failures"])
        for item in log.scenario_items("security_tool_args"):
            self.assertEqual(item.result_kind, "blocked", item.step)

    def test_query_safety_with_fakes(self):
        env = make_env()
        with mock.patch.object(env.wazuh, "get_rules", return_value={"data": {"affected_items": []}}):
            log = scen.run_scenario(env, "security_query_safety", {})
        st = log.scenario_status("security_query_safety")
        self.assertEqual(st["status"], "PASS", st["failures"])


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
class CliTests(unittest.TestCase):
    def test_refuses_without_live_flag(self):
        from live_validation.cli import main
        with mock.patch("config.cfg.MOCK_MODE", False):
            self.assertEqual(main(["--scenario", "env_baseline"]), 2)

    def test_refuses_in_mock_mode(self):
        from live_validation.cli import main
        with mock.patch("config.cfg.MOCK_MODE", True):
            self.assertEqual(main(["--live"]), 2)

    @mock.patch("live_validation.env.LiveEnv")
    @mock.patch("live_validation.scenarios.run_scenario")
    @mock.patch("config.cfg.MOCK_MODE", False)
    def test_happy_path_writes_evidence(self, run_scenario, live_env_cls):
        from live_validation.cli import main
        env_instance = mock.Mock()
        env_instance.preflight.return_value = []
        live_env_cls.return_value = env_instance
        slog = EvidenceLog()
        slog.step("env_baseline", "ok", "t", "wazuh_confirmed", True)
        run_scenario.return_value = slog
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "evidence.json"
            rc = main(["--live", "--scenario", "env_baseline", "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["summary"]["env_baseline"]["status"], "PASS")

    @mock.patch("live_validation.env.LiveEnv")
    @mock.patch("config.cfg.MOCK_MODE", False)
    def test_unknown_scenario_exits_2(self, live_env_cls):
        from live_validation.cli import main
        live_env_cls.return_value.preflight.return_value = []
        self.assertEqual(main(["--live", "--scenario", "does_not_exist"]), 2)


if __name__ == "__main__":
    unittest.main()