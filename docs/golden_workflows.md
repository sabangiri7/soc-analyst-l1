# Golden workflows

The four canonical end-to-end flows every major release must keep working.
Each maps human language → a deterministic tool chain and ends with evidence
the user can act on (or a proposal to approve).

## 1. "Investigate the top attacking IPs against my web servers in the last 24 hours"

```
investigate_top_attacking_ips(group="web", time_range="-24h")
  └─ indexer aggregation on wazuh-alerts-*: top src_ip buckets
     with max level, first/last seen, rule groups, top rules, agents
  └─ per IP (optional): investigate_ip → archives search, MITRE, timeline
  └─ why_did_alert_trigger(alert_id) ties a single alert back to its rule
     + surrounding context events
```

READ-level, executes immediately. Every number (counts, levels, groups,
rules) comes from the indexer response — never invented. If the `web` group
has no rows the engine falls back to the `attack` group and says which it
used.

## 2. "Create a Wazuh rule detecting repeated SSH failures"

```
develop_wazuh_rule(rule_xml, positive_samples, negative_samples, reason)
  ├─ static validation (wazuh rule RF): id/level/description required,
  │    frequency/timeframe/divide are ATTRIBUTES, freq rules need
  │    <if_matched_sid> parent
  ├─ pre-flight: rule id free? parent rule exists?
  ├─ overlap check against the live ruleset
  ├─ logtest baseline (positives/negatives) + proposed XML diff
  └─ PROPOSE → Approval Center  (payload = {rule_xml, overwrite, reason})

after approval, execution PUTs local_rules.xml → "Rule was successfully
uploaded" → restart manager (separate approval) → verify with
verify_rule_deployment(rule_id, positives, negatives):
    plain rules  : every positive fires the new id, negatives don't
    freq rules   : one logtest session; baseline fires the parent,
                   the Nth (threshold) sample fires the new id → 1/N
                   positive ratio is EXPECTED, verified=True is the signal
```

## 3. "Create a dashboard for web server attacks"

```
design_detection_dashboard(title, focus="web", description, time_range, reason)
  ├─ field_caps the indexer schema
  ├─ deterministic panel plan (alert volume, trend, top src IPs, groups,
  │    rules, level distribution, agents — degraded if fields missing)
  ├─ verify EACH panel query against the real indexer (size-0 count)
  ├─ build vis states + panelsJSON bundle
  └─ PROPOSE → Approval Center (payload = the tool's own input params)

approved execution re-runs the workflow, creates each visualization
(saved-objects API), maps real ids into the grid, creates the dashboard, and
reports only the server-confirmed ids.
```

## 4. "Find detection gaps in my web server telemetry"

```
analyze_detection_gaps(target="web", time_range="-7d")
  ├─ page the manager ruleset once, bucket by category via regex
  ├─ indexer counts per category: alerts (wazuh-alerts-*) + raw activity
  │    (wazuh-archives-*)
  └─ 5-state coverage table + gap_candidates (gap/partial rows) to feed
     develop_wazuh_rule
```

## How to verify after a release

The offline test suite pins these flows end-to-end with a mocked
`ToolContext` (`tests/test_engine_tools.py` — engines called via `run()`
directly) plus a registry-layer test (approvals/audit patched so `data/*` is
never written from tests). Live verification against a dev Wazuh stack:
propose → approve → execute → restart → verify → delete → restart → verify
gone → confirm the audit trail has every step and `local_rules.xml` is
pristine again.