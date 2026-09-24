# Detection gap analysis

How `analyze_detection_gaps(target, time_range)` answers **"find detection
gaps in my web server telemetry"** with facts, not guesses.

## Inputs (all real)

- the manager ruleset, paged once (`GET /rules?limit=500`)
- alerts seen in the window (`wazuh-alerts-*` counts)
- raw archive activity in the window (`wazuh-archives-*` counts)

Each category is defined by a regex against the ruleset blob (which rule
names/details imply this category?) plus a structured bool spec for the
indexer (which ALERTS count toward it? which raw activity counts?).
Queries are deterministic `term` / `match_phrase` / `match` bool clauses —
never `query_string`, whose special characters (`/`, `<`, `=`, `..`) 500
older Elasticsearch parsers.

## The 5-state coverage model

Per category, given `rules_exist`, `alerts_seen`, `events_seen`:

| State | Rules | Alerts | Raw events | Meaning |
|---|---|---|---|---|
| `detected` | yes | yes | any | Rules exist and are actually firing |
| `partial` | yes | no | yes | Rule exists but is too narrow / wrong group / needs tuning — likely missed detections |
| `covered_no_events` | yes | no | no | Rules exist; either no such traffic or event capture is off |
| `gap` | no | no | yes | Clear gap: activity exists but no rule covers it |
| `unknown` | no | no | no | Cannot tell yet — no rules and no observed activity |

Rows in `{gap, partial}` are the `gap_candidates` — the feed for
`develop_wazuh_rule` proposals.

## Built-in categories (web target)

`probes_scanning`, `sql_injection`, `xss`, `path_traversal_lfi`,
`sensitive_urls`, `login_bruteforce`, `log4j_jndi`, `webshell_upload` —
each with its rule regex and alert/archive query spec. Targets beyond `web`
extend the same table. MITRE technique mapping used during follow-up rule
work: `wazuh_docs/mitre-attack-mapping.md`.

## Output

A coverage table (category, rules, alerts, events, state), the
`gap_candidates` list, and a summary line like
`"N category/categories need attention"`. Nothing is written — the run is
READ-only; rule creation is a separate PROPOSE step.