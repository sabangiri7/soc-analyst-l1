"""
Wazuh dashboard (OpenSearch Dashboards) saved-objects HTTP client.

Separate host from the manager API and the indexer - the Dashboards server
serves the saved-objects API (default https://localhost:443, admin/admin in
the bundled docker stack). Best-effort by design: every call either returns a
2xx payload or raises ToolError with the real dashboards-server message; the
engineer never claims a dashboard was created unless the server said so.
"""
from __future__ import annotations

from typing import Any

import requests

from config import cfg
from tools.base import ToolError


def dashboards_request(method: str, path: str, *, params: dict[str, Any] | None = None,
                       body: Any = None, timeout: float | None = None) -> dict[str, Any]:
    url = (cfg.WAZUH_DASHBOARD_URL or "https://localhost:443").rstrip("/")
    auth = requests.auth.HTTPBasicAuth(
        cfg.WAZUH_DASHBOARD_USERNAME or "admin",
        cfg.WAZUH_DASHBOARD_PASSWORD or "admin",
    )
    try:
        r = requests.request(
            method, f"{url}{path}", params=params, json=body,
            auth=auth, verify=cfg.WAZUH_DASHBOARD_VERIFY_SSL,
            timeout=timeout or cfg.TOOL_QUERY_TIMEOUT,
        )
    except requests.RequestException as e:
        raise ToolError(f"OpenSearch Dashboards unreachable ({url}): {e}") from e
    try:
        payload = r.json()
    except ValueError:
        payload = {"raw": r.text[:400]}
    if r.status_code >= 400:
        msg = payload.get("message") or payload.get("error") or payload.get("raw") or payload
        raise ToolError(f"Dashboards API {method} {path} -> {r.status_code}: {msg}")
    return payload