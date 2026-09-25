"""
Find saved dashboards on the Wazuh dashboard that won't open/render.

    python scripts/check_wazuh_dashboards.py                  # check every dashboard
    python scripts/check_wazuh_dashboards.py --title "AI"      # only titles containing "AI"
    python scripts/check_wazuh_dashboards.py --id <dashboard-id>
    python scripts/check_wazuh_dashboards.py --json            # machine-readable

Read-only: it never modifies or deletes anything. Uses the same validator the
engine runs before/after creating dashboards (tools/dashboard/osd_objects.py)
and the same connection settings (WAZUH_DASHBOARD_* in .env). Exit code 1
when any checked dashboard is broken.

To fix a broken AI-generated dashboard: ask the SOC engineer to re-create it
(design_detection_dashboard - the fixed engine builds renderable objects),
then delete the broken one via delete_wazuh_dashboard. Both go through the
Approval Center.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.dashboard.dashboards import verify_dashboards  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--id", help="check one dashboard id")
    ap.add_argument("--title", help="only dashboards whose title contains this text")
    ap.add_argument("--json", action="store_true", help="print the raw report as JSON")
    args = ap.parse_args()

    try:
        report = verify_dashboards(args.id, args.title)
    except Exception as e:  # noqa: BLE001
        print(f"Could not reach the Wazuh dashboard: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for d in report["dashboards"]:
            mark = "OK    " if d["renders"] else "BROKEN"
            print(f"[{mark}] {d['title']}  (id: {d['dashboard_id']})")
            for issue in d["issues"]:
                print(f"         - {issue}")
        print(f"\n{report['checked']} checked, {report['broken']} broken")
    return 1 if report["broken"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
