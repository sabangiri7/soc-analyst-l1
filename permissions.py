"""
Permission model for the AI SOC engineer.

Three levels, enforced server-side in tools/registry.py:

    READ        automatically permitted (searches, lists, status, ...)
    PROPOSE     the agent may generate/validate the action but the write
                itself requires an approved proposal (create/modify rule,
                decoder, dashboard, configuration)
    EXECUTE     high-risk: requires approval + explicit confirmation
                (delete rule/dashboard, restart manager, disable agent,
                block IP / active response)

Every tool class declares its own level (`permission` attribute on
BaseWazuhTool). This module is the single source of truth for what a level
means and for describing actions to the user.
"""
from __future__ import annotations

from typing import Any

from tools.base import Permission, PermissionDenied


# High-risk action keywords - when a tool or proposal matches one of these,
# extra confirmation is required on top of approval (the "EXECUTE" band of
# the spec's safety model).
HIGH_RISK_ACTIONS = (
    "delete_",
    "restart",
    "disable",
    "block",
    "active_response",
    "remove_",
    "purge",
)

CONFIRM_REQUIRED_ACTIONS = (
    "delete_wazuh_rule",
    "delete_wazuh_decoder",
    "restart_wazuh_manager",
    "restart_wazuh_agent",
    "disable_wazuh_agent",
    "block_ip",
)


def is_high_risk(action: str) -> bool:
    """True when an action should require a second confirmation after
    approval (EXECUTE band)."""
    return any(action.lower().startswith(k) for k in HIGH_RISK_ACTIONS)


def needs_confirmation(action: str) -> bool:
    return action in CONFIRM_REQUIRED_ACTIONS


def describe(level: Permission | str) -> str:
    if isinstance(level, str):
        level = Permission(level)
    return level.label


def check_can_run(permission: Permission, action: str, confirmed: bool = False) -> None:
    """Server-side gate for executions. `confirmed` is the extra confirmation
    an operator gives in the UI for high-risk actions."""
    if permission in (Permission.PROPOSE, Permission.EXECUTE):
        raise PermissionDenied(
            f"Action '{action}' is a {permission.value.upper()} operation - it "
            "cannot run directly. Submit it for approval first."
        )


__all__ = [
    "Permission",
    "HIGH_RISK_ACTIONS",
    "CONFIRM_REQUIRED_ACTIONS",
    "is_high_risk",
    "needs_confirmation",
    "describe",
    "check_can_run",
]