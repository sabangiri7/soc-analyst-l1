---
name: wazuh-rule-authoring
description: Develop, validate, and verify Wazuh detection rules - ids, levels, frequency rules, logtest baselines, and the approval lifecycle.
version: 1.0.0
---
# Wazuh rule authoring

Follow this workflow when developing or verifying detection rules. Rules are
never written to the manager on your say-so: generating a rule produces a
validation proposal for the operator.

## Rule anatomy (hard constraints, all live-verified)

- Local rules MUST use an id >= 100000. `level` is 0-15; a `description`
  child is required.
- `frequency`, `timeframe`, and `divide` MUST be rule *attributes*, never child
  elements - the manager rejects a child with "Invalid option 'frequency' for
  rule".
- A `frequency`/`divide` rule MUST reference its parent with
  `<if_matched_sid>…</if_matched_sid>`, NOT `<if_sid>` (the manager errors
  "Invalid use of frequency/context options. Missing if_matched on rule").
  The canonical SSH-failure parent is rule 5760.

## Workflow for "create a rule that detects X"

1. Understand the log source and behaviour; pull sample events with
   `search_wazuh_alerts` / `search_wazuh_events` before writing anything.
2. Check for overlaps: `get_wazuh_rules` on the target group / matching
   decoders first. Never reinvent a rule that already exists.
3. Draft the rule XML with id >= 100000, correct level, and the most specific
   MITRE technique id (see the `mitre-mapping` skill): Wazuh encodes MITRE as
   `<mitre><id>T1110</id></mitre>`.
4. Call `develop_wazuh_rule(rule_xml, positive_samples, negative_samples,
   reason)` - it statically validates, pre-flights (id free? parent exists?),
   and runs a logtest baseline over your samples.
5. Report the proposal id + diff to the operator; a manager restart is needed
   (a separate approval) before the rule loads. Never claim the rule exists
   until the manager confirmed the upload.

## Verifying a deployed rule

Use `verify_rule_deployment(rule_id, positive_samples, negative_samples)`:

- Plain rules: every positive must fire the new id; negatives must fire
  something else (fresh logtest session).
- Frequency rules: keep ONE logtest session. With `frequency=N`, the first N-1
  samples fire the PARENT rule (expected), the Nth fires the new rule. A
  positive ratio of 1/N for freq=N is EXPECTED - `verified=True` is the
  meaningful signal, not the per-sample ratio.
- A sample that decodes to nothing (`no_decode`) is useless - replace it with
  a realistic line and re-run.

## Gotchas

- Manager readiness after restart: use `get_wazuh_manager_status` and require
  the core daemons (wazuh-analysisd, wazuh-db, wazuh-remoted, wazuh-authd,
  wazuh-modulesd, wazuh-apid) all "running". wazuh-agentlessd/csyslogd/
  integratord/maild may legitimately be stopped.
- Rules are uploaded as `local_rules.xml`; a missing file on a fresh manager
  reads as "not found" - treat it as empty.
- Prefer recalling the snapshot: `retrieve_wazuh_docs` surfaces the ingested
  ruleset (kind=wazuh-rule) so you can check existing ids offline.