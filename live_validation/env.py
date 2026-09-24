"""Live environment wrapper: clients, the application's propose/execute gates,
and preflight availability checks.

Execution semantics replicate the dashboard's Approval Center implementation
exactly (see dashboard.py `api_proposal_execute`): an approved proposal carries
the exact action + payload, and tools.registry.execute re-runs the real tool
with that stored payload - no LLM, no display blob, no re-derivation.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

import requests  # module-level so hermetic tests can patch live_validation.env.requests

from config import cfg
from tools.base import ToolContext


class LiveEnv:
    """Bundles live clients + options for one validation run.

    `wazuh`, `indexer` and `dashboards` are injectable so hermetic tests can
    substitute fake clients; defaults are the real connectors.
    """

    def __init__(
        self,
        *,
        wazuh: Any = None,
        indexer: Any = None,
        dashboards: Callable[..., dict[str, Any]] | None = None,
        approvals_path: str | Path | None = None,
        audit_path: str | Path | None = None,
        by: str = "phase14-validator",
        auto_approve: bool = False,
        confirm_execute: bool = False,
        cleanup: bool = True,
    ) -> None:
        from tools.api_client import WazuhManagerAPI
        from tools.indexer_client import IndexerClient

        self.wazuh = wazuh if wazuh is not None else WazuhManagerAPI()
        self.indexer = indexer if indexer is not None else IndexerClient()
        self.dashboards = dashboards  # default wired lazily in dashboards_call()
        self.approvals_path = approvals_path
        self.audit_path = audit_path
        self.by = by
        self.auto_approve = auto_approve
        self.confirm_execute = confirm_execute
        self.cleanup = cleanup
        # artifacts the scenarios have created (for cleanup)
        self.created_rules: list[int] = []
        self.created_dashboards: list[str] = []
        self.created_proposals: list[str] = []
        self.rule_file = "local_rules.xml"
        self._kb: Any = None

    # ------------------------------------------------------------------ #
    def tool_ctx(self, user: str | None = None, agent: str = "phase14-validator") -> ToolContext:
        return ToolContext(wazuh=self.wazuh, indexer=self.indexer,
                           user=user or self.by, agent=agent)

    def approve(self, proposal: dict[str, Any], by: str | None = None) -> dict[str, Any]:
        import approvals
        return approvals.approve(proposal["id"], by or self.by, path=self.approvals_path)

    def propose(self, tool_name: str, params: dict[str, Any],
                agent: str = "phase14-validator") -> dict[str, Any]:
        """Run one tool through the standard gate. Write tools yield an
        approval_required outcome whose proposal is persisted."""
        from tools.registry import execute as run_tool
        ctx = self.tool_ctx(agent=agent)
        outcome = run_tool(ctx, tool_name, params, silent=False)
        return outcome

    def execute_approved(self, proposal: dict[str, Any]) -> dict[str, Any]:
        """Deterministic execution of an approved proposal (mirrors the
        dashboard execute endpoint). EXECUTE-level actions require the
        `confirm` flag on top of approval."""
        import approvals
        from tools.registry import execute as run_tool

        p = approvals.get_proposal(proposal["id"], path=self.approvals_path)
        if not p:
            return {"ok": False, "error": f"Proposal {proposal['id']} not found."}
        if p.get("status") != "approved":
            return {"ok": False,
                    "error": f"Proposal {proposal['id']} is not approved (status: {p.get('status')})."}
        if p.get("permission") == "execute" and not self.confirm_execute:
            return {"ok": False,
                    "error": "EXECUTE-level action: requires an explicit confirmation "
                             "on top of the approval (set confirm_execute)."}

        ctx = self.tool_ctx(user=self.by, agent="approval_executor")
        ctx.approval = p
        try:
            result = run_tool(ctx, p.get("action", ""), p.get("payload") or {}, silent=True)
        except Exception as e:  # noqa: BLE001 - tool failure surfaces with its audit row
            return {"ok": False, "error": str(e)}
        if isinstance(result, dict) and result.get("status") == "error":
            return {"ok": False, "error": result.get("error", "execution failed"),
                    "result": result}
        return {"ok": True, "result": result}

    # ------------------------------------------------------------------ #
    def dashboards_call(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        fn = self.dashboards
        if fn is None:
            from tools.dashboard.client import dashboards_request
            fn = dashboards_request
        return fn(method, path, **kw)

    def rag_counts(self) -> dict[str, int]:
        if self._kb is None:
            from rag.knowledge_base import KnowledgeBase
            self._kb = KnowledgeBase()
        return dict(self._kb.counts())

    def rag_retrieve(self, query: str, top_k: int = 3, collection: str = "wazuh_docs") -> list[dict[str, Any]]:
        if self._kb is None:
            from rag.knowledge_base import KnowledgeBase
            self._kb = KnowledgeBase()
        return list(self._kb.search(query, top_k=top_k, collection=collection))

    def approvals_count(self, status: str | None = None) -> int:
        import approvals
        return len(approvals.list_proposals(status, path=self.approvals_path))

    def audit_count(self) -> int:
        p = Path(self.audit_path or getattr(cfg, "AUDIT_LOG_PATH", "data/audit_log.jsonl"))
        if not p.exists():
            return 0
        return sum(1 for _ in p.open())

    def audit_rows(self, limit: int | None = None) -> list[dict[str, Any]]:
        p = Path(self.audit_path or getattr(cfg, "AUDIT_LOG_PATH", "data/audit_log.jsonl"))
        if not p.exists():
            return []
        rows = [json.loads(line) for line in p.open() if line.strip()]
        return rows if limit is None else rows[-limit:]

    # ------------------------------------------------------------------ #
    # preflight - the CLI refuses to run scenarios before this passes
    # ------------------------------------------------------------------ #
    def preflight(self) -> list[str]:
        """Return a list of problems (empty == ready). Never raises."""
        problems: list[str] = []
        # manager API
        try:
            tok = self.wazuh._authenticate()
            if not tok:
                problems.append("manager API returned an empty token")
        except Exception as e:  # noqa: BLE001
            problems.append(f"manager API auth failed: {type(e).__name__}: {str(e)[:120]}")
        # manager readiness (core daemons)
        try:
            st = self.wazuh.get_manager_status()
            daemons = ((st.get("data") or {}).get("affected_items") or [{}])[0]
            core = ["wazuh-analysisd", "wazuh-db", "wazuh-remoted",
                    "wazuh-authd", "wazuh-modulesd", "wazuh-apid"]
            down = [d for d in core if daemons.get(d) != "running"]
            if down:
                problems.append(f"manager core daemons not running: {', '.join(down)}")
        except Exception as e:  # noqa: BLE001
            problems.append(f"manager status failed: {type(e).__name__}: {str(e)[:120]}")
        # indexer
        try:
            resp = self.indexer.search("wazuh-alerts-*", {"size": 0})
            if not isinstance(resp, dict):
                problems.append("indexer search returned a non-JSON response")
        except Exception as e:  # noqa: BLE001
            problems.append(f"indexer search failed: {type(e).__name__}: {str(e)[:120]}")
        # dashboards
        try:
            r = self.dashboards_call("GET", "/api/saved_objects/_find",
                                     params={"type": "dashboard", "per_page": 1})
            if not isinstance(r, dict):
                problems.append("dashboards API returned a non-JSON response")
        except Exception as e:  # noqa: BLE001
            problems.append(f"dashboards API failed: {type(e).__name__}: {str(e)[:120]}")
        return problems

    # ------------------------------------------------------------------ #
    def wait_for_manager(self, timeout_s: float = 600.0, poll_s: float = 10.0) -> bool:
        """Block until the manager API reports core daemons running."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                st = self.wazuh.get_manager_status()
                daemons = ((st.get("data") or {}).get("affected_items") or [{}])[0]
                if all(daemons.get(d) == "running"
                       for d in ("wazuh-analysisd", "wazuh-db", "wazuh-remoted",
                                 "wazuh-authd", "wazuh-modulesd", "wazuh-apid")):
                    return True
            except Exception:  # noqa: BLE001 - transient during restart
                pass
            time.sleep(poll_s)
        return False