"""
Dashboard engineering workflow for the AI SOC engineer.

Turns a request like "create a dashboard for web server attacks" into an
evidence-backed, human-approvable dashboard proposal:

  1. Inspect the indexer schema (field_caps) and verify each panel's OpenSearch
     query actually matches data (size-0 count) - the evidence for the panel.
  2. Compose deterministic visualization payloads (agg-based visState) +
     dashboard panelsJSON from validated fields only.
  3. Propose the bundle through the Approval Center. After approval, execution
     creates each visualization then the dashboard via the OpenSearch
     Dashboards saved-objects API and reports the server-confirmed ids.

Best-effort by design: the Wazuh dashboard (port 443, admin/admin in the
bundled stack) may be unreachable or configured differently - the engine never
claims a dashboard was created unless the dashboards server returned the saved
object. Dashboard creation is PROPOSE; deletion is EXECUTE.
"""
from __future__ import annotations

import json
from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.dashboard.client import dashboards_request
from tools.indexer.queries import search_body, to_range_expr, verify_opensearch_query

_INDEX = "wazuh-alerts-*"
_PANEL_LIMIT = 8


# --------------------------------------------------------------------------- #
def _find_index_pattern() -> str | None:
    """Discover the Wazuh alert index pattern id from the dashboards server.
    Returns None when unreachable - the caller falls back to the conventional
    'wazuh-alerts-*' id, which the Wazuh stack's default config uses."""
    try:
        resp = dashboards_request(
            "GET", "/api/saved_objects/_find",
            params={"type": "index-pattern", "per_page": 50},
        )
    except Exception:  # noqa: BLE001 - best-effort discovery
        return None
    items = resp.get("saved_objects") or resp.get("objects") or []
    best = None
    for item in items:
        title = ((item.get("attributes") or {}).get("title") or "").lower()
        if "wazuh" in title or "alerts" in title:
            return item.get("id")
        if best is None:
            best = item.get("id")
    return best or ("wazuh-alerts-*" if any("wazuh" in str(i) for i in items) else best)


# --------------------------------------------------------------------------- #
def _panel_plan(focus: str, schema: dict[str, str]) -> list[dict[str, Any]]:
    """Deterministic panel list for a focus. Each panel: slug, title, vis_type,
    aggs (agg-based visState), query (OpenSearch body used to verify)."""
    has_ip = "data.srcip" in schema
    has_agent = "agent.name" in schema
    filter_term: dict[str, Any] | None = None
    if focus == "web":
        filter_term = {"term": {"rule.groups": "web"}}
    elif focus == "ssh":
        filter_term = {"term": {"rule.groups": "authentication_failures"}}
    elif focus == "network":
        filter_term = {"term": {"rule.groups": "attack"}}

    base_query: dict[str, Any] = {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-7d"}}}]}}
    if filter_term:
        base_query["bool"]["filter"].append(filter_term)

    def q() -> dict[str, Any]:
        return json.loads(json.dumps(base_query))

    metric_aggs = [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "alerts (7d)"}},
    ]
    panels: list[dict[str, Any]] = [
        {
            "slug": "alert_count",
            "title": f"Alert volume - {focus or 'all'}",
            "vis_type": "metric",
            "aggs": metric_aggs,
            "query": {"bool": {"filter": [base_query["bool"]["filter"][0]]}},
        },
        {
            "slug": "alert_trend",
            "title": "Alert trend (7d)",
            "vis_type": "line",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric",
                 "params": {"customLabel": "alerts"}},
                {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                 "params": {"field": "timestamp", "interval": "auto", "includeEmptyRows": True,
                            "customLabel": "time"}},
            ],
            "query": base_query,
        },
    ]
    if has_ip:
        panels.append({
            "slug": "top_src_ips",
            "title": "Top source IPs",
            "vis_type": "pie",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric",
                 "params": {"customLabel": "alerts"}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                 "params": {"field": "data.srcip", "size": 8, "order": "desc", "orderBy": "1",
                            "customLabel": "source IP"}},
            ],
            "query": q(),
        })
    panels.extend([
        {
            "slug": "top_groups",
            "title": "Top rule groups",
            "vis_type": "bar",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric",
                 "params": {"customLabel": "alerts"}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                 "params": {"field": "rule.groups", "size": 6, "order": "desc", "orderBy": "1",
                            "customLabel": "group"}},
            ],
            "query": q(),
        },
        {
            "slug": "top_rules",
            "title": "Top rules",
            "vis_type": "bar",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric",
                 "params": {"customLabel": "alerts"}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                 "params": {"field": "rule.id", "size": 8, "order": "desc", "orderBy": "1",
                            "customLabel": "rule id"}},
            ],
            "query": q(),
        },
        {
            "slug": "level_dist",
            "title": "Alert level distribution",
            "vis_type": "bar",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric",
                 "params": {"customLabel": "alerts"}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                 "params": {"field": "rule.level", "size": 15, "order": "desc", "orderBy": "1",
                            "customLabel": "level"}},
            ],
            "query": q(),
        },
    ])
    if has_agent:
        panels.append({
            "slug": "top_agents",
            "title": "Top agents",
            "vis_type": "bar",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric",
                 "params": {"customLabel": "alerts"}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                 "params": {"field": "agent.name", "size": 6, "order": "desc", "orderBy": "1",
                            "customLabel": "agent"}},
            ],
            "query": q(),
        })
    return panels[: _PANEL_LIMIT]


def _vis_state(title: str, vis_type: str, aggs: list[dict[str, Any]]) -> str:
    params: dict[str, Any] = {}
    if vis_type == "pie":
        params = {"type": "pie", "addTooltip": True, "legendPosition": "right", "isDonut": True}
    elif vis_type == "metric":
        params = {"metric": {"colorSchema": "Green to Red", "metricColorMode": "Labels",
                             "useRanges": False, "percentageMode": False},
                  "type": "metric"}
    elif vis_type in ("bar", "line", "area"):
        params = {"type": "histogram", "grid": {"categoryLines": False},
                  "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                                    "show": True, "style": {}, "scale": {"type": "linear"}}],
                  "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                                 "position": "left", "show": True, "style": {}, "scale": {"type": "linear"}}],
                  "seriesParams": [{"show": True, "type": vis_type, "mode": "stacked",
                                    "data": {"label": "alerts", "id": "1"}, "valueAxis": "ValueAxis-1"}]}
    state = {"title": title, "type": vis_type, "aggs": aggs, "params": params, "listeners": {}}
    return json.dumps(state)


def _search_source(index_pattern: str, aggs: list[dict[str, Any]]) -> str:
    """searchSourceJSON for the saved object - ties the visualization (and so the
    panel) to the wazuh alert index pattern."""
    return json.dumps({
        "query": {"query": "", "language": "kuery"},
        "filter": [],
        "index": index_pattern,
        "aggs": json.loads(json.dumps(aggs)),
    })


# --------------------------------------------------------------------------- #
class DesignDetectionDashboard(BaseWazuhTool):
    name = "design_detection_dashboard"
    description = ("Dashboard engineering workflow: build a Wazuh-dashboard proposal (alert volume, "
                   "trend, top source IPs, rule groups, rules, levels, agents) from the real indexer "
                   "schema, verifying each panel's query actually matches data. Focus: web | ssh | "
                   "network | general. WRITE on execute: creates the visualizations + dashboard on the "
                   "Wazuh dashboard server (best-effort; requires human approval).")
    input_schema = {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "dashboard title, e.g. 'Web Server Attacks'" },
            "focus": {"type": "string", "description": "web | ssh | network | general"},
            "description": {"type": "string"},
            "time_range": {"type": "string", "description": "verification window (default -7d)"},
            "reason": {"type": "string", "description": "why this dashboard is needed"},
        },
        "required": ["title", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        focus = (p.get("focus") or "general").lower()
        if focus not in ("web", "ssh", "network", "general"):
            raise ToolError("focus must be one of: web | ssh | network | general")

        # 1) schema + panel plan
        try:
            schema = ctx.indexer.field_caps(_INDEX)
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Cannot read indexer schema - dashboard design aborted: {e}") from e
        panels = _panel_plan(focus, schema)
        panel_query_map = {panel["slug"]: panel["query"] for panel in panels}

        # 2) verify each panel's query matches data (evidence)
        verified: list[dict[str, Any]] = []
        degraded: list[str] = []
        for panel in panels:
            check = verify_opensearch_query(ctx.indexer, _INDEX, search_body(panel["query"], size=0))
            if not check.get("valid"):
                degraded.append(panel["slug"])
                check = {"valid": False, "error": check.get("error")}
            verified.append({"slug": panel["slug"], "title": panel["title"], "matched": check.get("matched", 0),
                             "note": check.get("error", "panel query verified")})

        # 3) index pattern (best-effort discovery)
        index_pattern = _find_index_pattern() or "wazuh-alerts-*"

        # 4) build the full bundle (visualizations + dashboard panels)
        visualizations = []
        grid: list[dict[str, Any]] = []
        x = 0
        for panel in panels:
            vis_state = _vis_state(panel["title"], panel["vis_type"], panel["aggs"])
            visualizations.append({
                "slug": panel["slug"],
                "title": panel["title"],
                "vis_type": panel["vis_type"],
                "vis_state": vis_state,
                "search_source": _search_source(index_pattern, panel["aggs"]),
            })
            grid.append({"id": f"vis-{panel['slug']}", "x": x % 2 * 24, "y": (x // 2) * 15,
                         "w": 24, "h": 15, "type": "visualization"})
            x += 1
        panels_json = json.dumps(grid)

        proposed = {
            # Re-running this same workflow with an approved context executes
            # deterministically: it re-verifies each panel query against the
            # indexer, creates the visualizations and the dashboard, and reports
            # only the server-confirmed ids. The payload is the tool's own input.
            "action": "design_detection_dashboard",
            "reason": p.get("reason", ""),
            "payload": {k: p[k] for k in ("title", "focus", "description",
                                          "time_range", "reason") if k in p},
            "permission": self.permission.value,
        }
        proposed["generated_config"] = {
            "title": p["title"],
            "focus": focus,
            "index_pattern": index_pattern,
            "visualizations": [{"slug": v["slug"], "title": v["title"], "vis_type": v["vis_type"]}
                               for v in visualizations],
            "panelsJSON": panels_json,
        }
        validated = not degraded
        proposed["validation"] = {
            "valid": validated,
            "errors": [f"panel '{d}' query failed: {next((v['note'] for v in verified if v['slug'] == d), '')}"
                       for d in degraded] or None,
            "note": ("Queries verified against the real indexer; creation is best-effort on the "
                     "dashboards server and will report the server-confirmed ids."),
            "evidence": {"focus": focus, "index": _INDEX, "index_pattern": index_pattern,
                         "panels": verified},
            "next_steps": ["approve -> create visualizations + dashboard on the dashboards server",
                           "open the dashboard in the Wazuh UI to confirm rendering"],
        }
        ctx.approve_or_raise(proposed)

        # --- execution: create visualizations, then the dashboard, verifying each ---
        created_vis: list[dict[str, Any]] = []
        try:
            for v in visualizations:
                resp = dashboards_request(
                    "POST", "/api/saved_objects/visualization",
                    body={
                        "attributes": {
                            "title": v["title"],
                            "visState": v["vis_state"],
                            "description": "Generated by the AI SOC engineer (approved)",
                            "version": 1,
                        },
                        "references": [{"id": index_pattern,
                                        "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                                        "type": "index-pattern"}] if index_pattern else [],
                    },
                )
                obj = resp.get("saved_object") or resp.get("object") or {}
                vid = obj.get("id") or resp.get("id")
                created_vis.append({"slug": v["slug"], "id": vid, "title": v["title"]})
        except ToolError as e:
            raise ToolError(f"Visualization step failed (dashboard not created): {e}") from e

        # map real visualization ids into the grid
        slug_to_id = {v["slug"]: v["id"] for v in created_vis}
        real_panels = []
        yseen: dict[int, int] = {}
        for panel in grid:
            slug = panel["id"].replace("vis-", "")
            pid = slug_to_id.get(slug)
            if not pid:
                continue
            y = yseen.get(panel["y"], panel["y"])
            yseen[panel["y"]] = y + 15
            real_panels.append({"id": pid, "x": panel["x"], "y": y,
                                "w": panel["w"], "h": panel["h"], "type": "visualization"})
        try:
            dash = dashboards_request(
                "POST", "/api/saved_objects/dashboard",
                body={
                    "attributes": {
                        "title": p["title"],
                        "description": p.get("description", ""),
                        "hits": 0,
                        "panelsJSON": json.dumps(real_panels),
                        "timeRestore": False,
                        "version": 1,
                    },
                    "references": [],
                },
            )
        except ToolError as e:
            raise ToolError(f"Dashboard create failed after {len(created_vis)} visualizations: {e}") from e
        dobj = dash.get("saved_object") or dash.get("object") or {}
        did = dobj.get("id") or dash.get("id")
        return {
            "status": "executed",
            "dashboard_id": did,
            "title": p["title"],
            "visualizations": created_vis,
            "panels_created": len(real_panels),
            "verified_panels": [{"slug": v["slug"], "matched": v["matched"]} for v in verified],
            "detail": dash.get("message"),
        }


TOOLS = [DesignDetectionDashboard]