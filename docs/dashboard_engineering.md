# Dashboard engineering

How `design_detection_dashboard(title, focus, description, time_range,
reason)` turns **"create a dashboard for web server attacks"** into an
evidence-backed, human-approvable bundle (PROPOSE), and how approved
execution creates it for real.

## Planning (no writes)

1. **Schema** — `field_caps` on the indexer tells the engine which fields
   exist (`data.srcip`, `agent.name`, `rule.groups`, `rule.level`, …). A
   schema read failure aborts the design ("Cannot read indexer schema …") —
   no guessing.
2. **Panel plan** — deterministic per focus (`web` / `ssh` / `network` /
   `general`): alert volume, alert trend, top source IPs, top rule groups,
   top rules, level distribution, top agents. Panels referencing missing
   fields are dropped, not fabricated.
3. **Evidence** — every panel's OpenSearch query is run against the real
   indexer (`size: 0` count) and reported `valid` / degraded. A panel whose
   query fails to match is flagged in the proposal's validation, never hidden.
4. **Bundle** — agg-based `visState` per visualization + `panelsJSON` grid,
   proposed with `{action: design_detection_dashboard, payload: <the tool's
   own input params>, generated_config, validation}`.

`_find_index_pattern` discovers the Wazuh alert index-pattern id
best-effort and falls back to the conventional `wazuh-alerts-*` id.

## Execution (approved only)

The stored payload re-runs the design workflow, then writes via the
OpenSearch Dashboards saved-objects API (`POST /api/saved_objects/
visualization` then `…/dashboard`):

- each visualization is created and its real id captured;
- real ids are mapped into the grid (rows that failed to create are skipped
  — the dashboard is built from what actually exists);
- the dashboard is created and the result reports only
  server-confirmed ids (visualizations, dashboard id, panels created).

The dashboards server is best-effort by design: the engine never claims a
dashboard exists unless the API returned the saved object.

## Query rules (shared with every engine)

- structured bool clauses only (`term` / `terms` / `match` / `match_phrase`
  / `range` / `date_histogram`);
- no `query_string`-style filters (7.10.2 500s on `/`, `<`, `=`, `..`);
- count verification with `"size": 0` reading `hits.total.value`;
- `wazuh-alerts-*` for triggered alerts, `wazuh-archives-*` for raw activity.