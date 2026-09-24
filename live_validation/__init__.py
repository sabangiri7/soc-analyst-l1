"""Live validation framework for the AI SOC engineer (PHASE 14).

Runs real workflows against the live Wazuh development environment through the
same application code paths the agent uses (registry gate, approval store,
audit log), and records per-step evidence so "AI-generated" claims are always
separated from "Wazuh-confirmed" facts.

Usage:
    python scripts/live_validation.py --live
    python scripts/live_validation.py --live --scenario detection_ssh_rule

The harness never runs automatically as part of the unit suite, never stores
credentials, and only touches the dev Wazuh stack.
"""
from live_validation.cli import main as cli_main

__all__ = ["cli_main"]