# Rule engineering

The detection surface: authoring, validation, deployment, and post-deploy
verification against a Wazuh manager. Grounded in live-verified 4.14 behavior
(see `wazuh_docs/wazuh-rules.md` and `wazuh_docs/wazuh-logtest.md` — both are
seeded into the RAG store).

## develop_wazuh_rule (PROPOSE)

`develop_wazuh_rule(rule_xml, positive_samples, negative_samples, reason)`:

1. **Static validation** — `tools/wazuh/validation.py`:
   - required attributes: `id` (>= 100000 for local rules) and `level`
     (0–15); `description` child required.
   - `frequency` / `timeframe` / `divide` **must be rule attributes** —
     child elements are rejected with a corrective error (the manager itself
     errors "Invalid option 'frequency' for rule").
   - a `frequency`/`divide` rule must reference its parent via
     `<if_matched_sid>…</if_matched_sid>` (`<if_sid>` fails the manager with
     "Invalid use of frequency/context options. Missing if_matched on rule").
     The canonical SSH-failure parent is rule **5760**.
2. **Pre-flight** — the proposed id is free (`get_rules(q=id=…)`), the parent
   rule exists, and the proposed XML doesn't overlap existing rules.
3. **Logtest baseline** — positives/negatives run through `run_logtest` and
   classified (fired-new-id / fired-other / no-decode / clean).
4. **Proposal** — `{action: create_wazuh_rule, payload: {rule_xml, overwrite:
   false, reason}, generated_config: <merged local_rules.xml diff>, …}`.

Execution (approved) merges the rule into `local_rules.xml`, PUTs it
(octet-stream), and reports the manager's "Rule was successfully uploaded"
message. A manager **restart** (separate approval) is needed before rules
load — `RestartWazuhManager`.

## verify_rule_deployment (READ)

`verify_rule_deployment(rule_id, positive_samples, negative_samples)`:

- plain rules: every positive must fire the new id; negatives must fire
  something else.
- **frequency rules**: one logtest session (token threaded through all
  positives). With `frequency=N`, the first N-1 samples fire the **parent**
  rule — expected — and the Nth fires the new rule. `positive_pass` reads
  `1/3` for frequency=3 by design; `verified=True` is the meaningful signal.
  A clean, logged-out sample classifies `no_decode` and makes the sample
  useless (replace with a realistic line).
- negatives run in their own fresh session and must never fire the new id.

## Rule lifecycle (CRUD)

`CreateWazuhRule` / `UpdateWazuhRule` / `DeleteWazuhRule` follow the same
payload round-trip (stored payload → deterministic execution →
API-confirmed result). Delete is EXECUTE: requires approval + `confirm`, and
only reports success after the manager confirms the rule is gone.

## Gotchas (all live-verified)

- `GET /manager/info` returns 200 while daemons restart — readiness is
  `GET /manager/status` with all core daemons (wazuh-analysisd, wazuh-db,
  wazuh-remoted, wazuh-authd, wazuh-modulesd, wazuh-apid) == "running".
  wazuh-agentlessd / csyslogd / integratord / maild may legitimately be
  stopped.
- Rules PUT as octet-stream; a missing `local_rules.xml` on a fresh manager
  reads as "not found" → treat as empty.
- Never run `query_string`-style indexer filters (see
  `docs/dashboard_engineering.md` / `wazuh_docs/wazuh-indexer.md`).