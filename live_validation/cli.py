"""CLI entry for live validation.

The harness is intentionally separate from the unit suite (which must remain
runnable offline): it requires an explicit --live flag, refuses to run when
MOCK_MODE is on, verifies credentials + API availability before doing
anything, and only deploys/restarts when --auto-approve is passed (with
EXECUTE-level confirmations implicit in env.confirm_execute).
"""
from __future__ import annotations

import argparse
import sys
from typing import Any

from config import cfg

SCENARIO_ORDER = [
    "env_baseline",
    "detection_ssh_rule",
    "security_tool_args",
    "security_query_safety",
]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="live_validation",
        description="PHASE 14 live validation - requires a live Wazuh dev "
                    "environment. Never run automatically with the unit suite.",
    )
    p.add_argument("--live", action="store_true",
                   help="explicitly confirm a live Wazuh environment is intended")
    p.add_argument("--scenario", default="all",
                   help="scenario name or comma-separated list (default: all)")
    p.add_argument("--auto-approve", action="store_true",
                   help="for validation runs: approve the harness's own proposals and "
                        "execute them (deploy rules/dashboards, restart manager). Without "
                        "this flag workflows stop at the approval gate (N/A for env_baseline)")
    p.add_argument("--confirm-execute", action="store_true",
                   help="confirm EXECUTE-level actions (delete/restart) on top of approval")
    p.add_argument("--out", default="data/phase14_evidence.json",
                   help="evidence JSON output path")
    p.add_argument("--cleanup", action="store_true",
                   help="remove test artifacts after the run (rules/dashboards/proposals)")
    p.add_argument("--opts", default="",
                   help="scenario options as key=value,key2=value2 (e.g. test_ip=203.0.113.77)")
    p.add_argument("--approvals-path", default=None, help="approval store path (dev/testing)")
    p.add_argument("--audit-path", default=None, help="audit log path (dev/testing)")
    return p


def _parse_opts(raw: str) -> dict[str, Any]:
    opts: dict[str, Any] = {}
    for pair in raw.split(","):
        if not pair:
            continue
        if "=" not in pair:
            opts[pair] = True
            continue
        k, v = pair.split("=", 1)
        opts[k] = v
    return opts


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print("=" * 72)
    print("PHASE 14 LIVE VALIDATION - requires a live Wazuh development environment")
    print("=" * 72)
    if not args.live:
        print("REFUSING: pass --live to confirm you intend a live run "
              "(this harness never runs with the unit suite).")
        return 2
    if getattr(cfg, "MOCK_MODE", False):
        print("REFUSING: MOCK_MODE is on - live validation needs real connectors.")
        return 2
    if cfg.WAZUH_API_PASSWORD is None or cfg.WAZUH_USERNAME is None:
        print("REFUSING: missing WAZUH_* credentials in .env.")
        return 2

    from live_validation.env import LiveEnv
    from live_validation.evidence import EvidenceLog
    from live_validation import scenarios as scen

    opts = _parse_opts(args.opts)
    env = LiveEnv(
        approvals_path=args.approvals_path,
        audit_path=args.audit_path,
        by="phase14-validator",
        auto_approve=args.auto_approve,
        confirm_execute=args.confirm_execute or args.auto_approve,
        cleanup=args.cleanup,
    )

    # preflight
    print("\n[preflight] checking credentials + API availability ...")
    problems = env.preflight()
    if problems:
        print("PREFLIGHT FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("preflight OK (manager API, manager status, indexer, dashboards)")

    # choose scenarios
    if args.scenario == "all":
        names = [s for s in SCENARIO_ORDER if s in scen.SCENARIOS]
    else:
        names = [n.strip() for n in args.scenario.split(",") if n.strip()]
    unknown = [n for n in names if n not in scen.SCENARIOS]
    if unknown:
        print(f"ERROR: unknown scenario(s): {unknown}")
        return 2
    for n in names:
        reg = scen.SCENARIOS[n]
        if reg["requires_auto_approve"] and not args.auto_approve:
            print(f"NOTE: scenario '{n}' will stop at the approval gate "
                  "(pass --auto-approve to also deploy/verify).")

    log = EvidenceLog()
    for name in names:
        print(f"\n--- scenario: {name} ---")
        try:
            slog = scen.run_scenario(env, name, opts)
        except Exception as e:  # noqa: BLE001 - scenario crash is a failed run
            log.step(name, "scenario-crash", "live_validation.scenarios", "error", False,
                     detail=f"{type(e).__name__}: {str(e)[:300]}")
            continue
        for item in slog.items:
            log.add(item)
        st = log.scenario_status(name)
        print(f"  {st['status']} ({st['passed']}/{st['total']} steps passed)")
        for f in st["failures"]:
            print(f"    FAIL {f['tool']} [{f['step']}]: {f['detail']}")

    print("\n" + "=" * 72)
    print("VALIDATION MATRIX")
    print(log.matrix())
    print("=" * 72)

    if args.cleanup:
        print("\n[cleanup] removing PHASE 14 test artifacts ...")
        from live_validation.cleanup import reject_leftover_proposals, cleanup_rules, cleanup_dashboards
        n = reject_leftover_proposals(env)
        print(f"  rejected {n} leftover pending proposals")
        cleanup_dashboards(env, log)
        cleanup_rules(env, log)
        print("  cleanup done (see evidence for per-artifact results)")

    if args.out:
        log.to_json(args.out)
        print(f"\nevidence written to {args.out}")

    ok = log.all_pass()
    print("\nRESULT:", "ALL SCENARIOS PASS" if ok else "SCENARIO FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())