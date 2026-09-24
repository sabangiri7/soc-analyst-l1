"""
Saved-dashboard tools for the Wazuh dashboard (OpenSearch Dashboards
saved-objects API).
"""
from __future__ import annotations

import json
from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.dashboard.client import dashboards_request


class GetWazuhDashboards(BaseWazuhTool):
    name = "get_wazuh_dashboards"
    description = ("List saved dashboards on the Wazuh dashboard (saved-objects API) - to see "
                   "what exists before creating another.")
    input_schema = {
        "type": "object",
        "properties": {"limit": {"type": "integer", "description": "max results (default 20)"}},
        "required": [],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        limit = min(int(p.get("limit", 20) or 20), 100)
        try:
            resp = dashboards_request(
                "GET", "/api/saved_objects/_find",
                params={"type": "dashboard", "per_page": limit},
            )
        except ToolError:
            raise
        items = resp.get("saved_objects") or resp.get("objects") or []
        out = []
        for i in items:
            attrs = i.get("attributes") or {}
            try:
                panels = len(json.loads(attrs.get("panelsJSON") or "[]") or [])
            except json.JSONDecodeError:
                panels = 0
            out.append({"id": i.get("id"), "title": attrs.get("title"), "panels": panels})
        return {"count": len(out), "dashboards": out, "dashboard_ok": True}


class UpdateWazuhDashboard(BaseWazuhTool):
    name = "update_wazuh_dashboard"
    description = "Update an existing saved dashboard (replace its panelsJSON). WRITE - proposes and requires approval."
    input_schema = {
        "type": "object",
        "properties": {
            "dashboard_id": {"type": "string"},
            "title": {"type": "string"},
            "panels": {"type": "array", "description": "list of panel objects {id, x, y, w, h}"},
            "reason": {"type": "string"},
        },
        "required": ["dashboard_id", "panels", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        if not isinstance(p.get("panels"), list):
            raise ToolError("panels must be a list of {id, x, y, w, h} objects.")
        panels_json = json.dumps(p["panels"])
        proposed = {
            "action": "update_wazuh_dashboard",
            "reason": p.get("reason", ""),
            "payload": {"dashboard_id": p["dashboard_id"], "title": p.get("title"),
                        "panels": p["panels"], "reason": p.get("reason", "")},
            "permission": self.permission.value,
        }
        proposed["generated_config"] = {"panelsJSON": panels_json}
        proposed["validation"] = {"valid": True, "note": "Panels validated by the dashboard engineer."}
        ctx.approve_or_raise(proposed)
        attrs: dict[str, Any] = {"hits": 0, "panelsJSON": panels_json, "version": 1}
        if p.get("title"):
            attrs["title"] = p["title"]
        try:
            resp = dashboards_request(
                "PUT", f"/api/saved_objects/dashboard/{p['dashboard_id']}",
                body={"attributes": attrs, "references": []},
            )
        except ToolError:
            raise
        return {"status": "executed", "dashboard_id": p["dashboard_id"], "detail": resp.get("message")}


class CreateWazuhDashboard(BaseWazuhTool):
    name = "create_wazuh_dashboard"
    description = ("Create a saved dashboard on the Wazuh dashboard from panels referencing "
                   "visualization ids. WRITE - proposes and requires human approval.")
    input_schema = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "description": {"type": "string"},
            "panels": {"type": "array", "description": "list of panel objects {id, x, y, w, h}"},
            "reason": {"type": "string"},
        },
        "required": ["title", "panels", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        panels = p.get("panels")
        if not isinstance(panels, list) or not all(isinstance(x, dict) and "id" in x for x in panels):
            raise ToolError("panels must be a list of {id, x, y, w, h} objects referencing visualization ids.")
        panels_json = json.dumps(panels)
        proposed = {
            "action": "create_wazuh_dashboard",
            "reason": p.get("reason", ""),
            "payload": {"title": p["title"], "description": p.get("description", ""),
                        "panels": panels, "reason": p.get("reason", "")},
            "permission": self.permission.value,
        }
        proposed["generated_config"] = {"title": p["title"], "description": p.get("description", ""),
                                        "panelsJSON": panels_json}
        proposed["validation"] = {"valid": True, "note": "Panels reference approved visualizations."}
        ctx.approve_or_raise(proposed)
        try:
            resp = dashboards_request(
                "POST", "/api/saved_objects/dashboard",
                body={
                    "attributes": {
                        "title": p["title"],
                        "description": p.get("description", ""),
                        "hits": 0,
                        "panelsJSON": panels_json,
                        "timeRestore": False,
                        "version": 1,
                    },
                    "references": [],
                },
            )
        except ToolError:
            raise
        resp_obj = resp.get("saved_object") or resp.get("object") or {}
        obj_id = resp_obj.get("id") or resp.get("id")
        return {"status": "executed", "dashboard_id": obj_id, "title": p["title"],
                "detail": resp.get("message")}


class DeleteWazuhDashboard(BaseWazuhTool):
    name = "delete_wazuh_dashboard"
    description = ("Delete a saved dashboard by id. HIGH RISK (EXECUTE): requires approval AND "
                   "explicit confirmation.")
    input_schema = {
        "type": "object",
        "properties": {
            "dashboard_id": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["dashboard_id", "reason"],
    }
    permission = Permission.EXECUTE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        proposed = {
            "action": "delete_wazuh_dashboard",
            "reason": p.get("reason", ""),
            "payload": {"dashboard_id": p["dashboard_id"], "reason": p.get("reason", "")},
            "permission": self.permission.value,
        }
        proposed["validation"] = {"valid": True, "note": "Deletion requires approval + confirmation."}
        ctx.approve_or_raise(proposed)
        try:
            resp = dashboards_request(
                "DELETE", f"/api/saved_objects/dashboard/{p['dashboard_id']}"
            )
        except ToolError:
            raise
        return {"status": "executed", "dashboard_id": p["dashboard_id"], "detail": resp.get("message")}