"""Evidence model for live validation scenarios.

Every scenario step records an Evidence item that classifies HOW the claim was
produced:

    ai_generated     - produced by the agent/LLM (needs Wazuh confirmation)
    wazuh_confirmed  - observed from the live Wazuh manager / indexer /
                       dashboards API or the approval/audit stores
    mock             - generated deterministically by the harness (no LLM)
    blocked          - correctly refused by the permission/validation layer
    error            - unexpected failure (scenario step fails)
    info             - context, not a pass/fail claim

A scenario is PASS only when every gate step passed; the aggregation keeps the
exact failed steps so evidence is never hand-waved.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any

RESULT_KINDS = ("ai_generated", "wazuh_confirmed", "mock", "blocked", "error", "info")


@dataclass
class Evidence:
    scenario: str
    step: str
    tool: str
    result_kind: str
    passed: bool
    detail: str = ""
    refs: dict[str, Any] = field(default_factory=dict)
    params_summary: str = ""

    def __post_init__(self) -> None:
        if self.result_kind not in RESULT_KINDS:
            raise ValueError(f"invalid result_kind {self.result_kind!r}")
        if self.result_kind == "error" and self.passed:
            raise ValueError("an error evidence row cannot be passed")


class EvidenceLog:
    """Ordered evidence rows for one (or many) scenarios + PASS/FAIL rollup."""

    def __init__(self) -> None:
        self.items: list[Evidence] = []
        self.run_id: str = time.strftime("%Y%m%dT%H%M%S")

    def add(self, e: Evidence) -> None:
        self.items.append(e)

    def step(self, scenario: str, step: str, tool: str, result_kind: str,
             passed: bool, detail: str = "", refs: dict[str, Any] | None = None,
             params_summary: str = "") -> Evidence:
        e = Evidence(scenario, step, tool, result_kind, passed, detail,
                     refs or {}, params_summary)
        self.add(e)
        return e

    # ------------------------------------------------------------------ #
    def scenario_items(self, scenario: str) -> list[Evidence]:
        return [i for i in self.items if i.scenario == scenario]

    def scenario_status(self, scenario: str) -> dict[str, Any]:
        rows = self.scenario_items(scenario)
        if not rows:
            return {"scenario": scenario, "status": "NOT RUN", "passed": 0,
                    "failed": 0, "total": 0, "failures": []}
        failed = [i for i in rows if not i.passed]
        return {
            "scenario": scenario,
            "status": "PASS" if not failed else "FAIL",
            "passed": sum(1 for i in rows if i.passed),
            "failed": len(failed),
            "total": len(rows),
            "failures": [{"step": i.step, "tool": i.tool, "detail": i.detail[:300]}
                         for i in failed],
        }

    @property
    def scenarios(self) -> list[str]:
        seen: list[str] = []
        for i in self.items:
            if i.scenario not in seen:
                seen.append(i.scenario)
        return seen

    def summary(self) -> dict[str, Any]:
        return {s: self.scenario_status(s) for s in self.scenarios}

    def all_pass(self) -> bool:
        return all(v["status"] == "PASS" for v in self.summary().values())

    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "summary": self.summary(),
            "all_pass": self.all_pass(),
            "evidence": [asdict(i) for i in self.items],
        }

    def to_json(self, path: str) -> None:
        with open(path, "w") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    def matrix(self) -> str:
        """Human-readable validation matrix (LIVE / MOCK / UNIT / NOT TESTED
        is resolved by the report generator, which knows how each row ran)."""
        lines = [f"{'scenario':<24} {'total':>5} {'passed':>6} {'failed':>6}  status"]
        for s in self.scenarios:
            st = self.scenario_status(s)
            lines.append(f"{s:<24} {st['total']:>5} {st['passed']:>6} "
                         f"{st['failed']:>6}  {st['status']}")
        return "\n".join(lines)