# Permissions & the approval model

**The single most important safety document in this project.** Read it before
deploying the AI SOC Engineer anywhere with write access.

## The three levels

| Level | Meaning | Executes when |
|---|---|---|
| `READ` | Query-only: search alerts/events, list rules/decoders/agents, status, schema, logtest analysis, RAG retrieval **and rule-snapshot ingest** (`ingest_wazuh_rules` — pulls manager rules READ-only into the local RAG, never modifies the manager) | Immediately, every call |
| `PROPOSE` | The tool *plans* and validates a concrete change (rule XML, decoder, dashboard bundle) but performs no write | Only after a human approves the plan in the Approval Center |
| `EXECUTE` | High-risk: delete rule/decoder, restart manager, disable agent, active response | Only after approval **and** an explicit `confirm` flag |

## What "planning" means for PROPOSE tools

Calling a PROPOSE tool without an approved proposal runs the full analysis
(merge with the current `local_rules.xml`, validation, logtest baseline,
dashboard panel verification) and then raises `ApprovalRequired` with a
proposal. The proposal is:

- `action`          — the exact tool invocation (`create_wazuh_rule`, …)
- `payload`         — the tool's **own input parameters**, so execution is a
  deterministic re-run of the same call (never a display snapshot)
- `generated_config`— the validated artifact for human review (rule XML / vis
  bundle), shown in the Approval Center
- `validation`      — evidence: what was checked and the results

Nothing is written to Wazuh during planning. The `approval_required` outcome
lands in the Approval Center (`data/approvals.json`).

## Enforcement (in code, not in prompts)

Enforcement is in `tools/registry.py`, plus defense-in-depth inside every
write tool:

1. `registry.execute(ctx, name, params)` validates params against the tool
   schema; bad params → `{"status": "error"}` and are audited as `rejected`.
2. `ctx.approval is None` for a PROPOSE/EXECUTE tool → the tool's own
   `approve_or_raise()` raises `ApprovalRequired` → the registry persists the
   proposal and returns `{"status": "approval_required"}`.
3. With an approved proposal, `approve_or_raise()` checks the **action**
   matches (`Approval mismatch` → denied). Execution then runs the stored
   payload deterministically — no LLM involved in the execution step.
4. EXECUTE-level tools additionally require `confirm: true` in the execute
   request body (dashboard enforces this with a 400 otherwise).
5. The LLM can never bypass any of this by rephrasing — the gate is the tool
   itself and the registry, not the system prompt.

## Failure honesty

- An approved execution is only `ok` if the tool ran **and** reported the
  API-confirmed outcome (e.g. the manager's `"Rule was successfully
  uploaded"` message, saved-object ids from the dashboards server).
- Both a raised exception and `result.status == "error"` are treated as
  failures, are audited with `execution_status="failed"`, and are reported —
  never silently converted into success.

## Audit

Every registry call writes a row to `data/audit_log.jsonl`: tool, redacted
params, permission level, approval status, execution status, and a small
result summary (never the full blob). Human actions in the Approval Center
(approve / reject / execute) are audited too, with `permission="human"`.

Both operator faces go through this same gate. The terminal agent
(`scripts_engineer_cli.py`) makes the same registry calls, and its human
actions (`/approve` `/reject` `/execute`) resolve through the same
`approvals.py` + `approval_executor.py` code with identical audit rows. Its
operator identity is `--user` with `identity_verified=False` (trusted local
machine only); the dashboard center uses token-verified identities.

See also: `docs/approval_center.md` (the lifecycle + UI), `docs/architecture.md`
(the full surface), `docs/prompt_injection_defense.md` (why tool results are
wrapped as UNTRUSTED DATA before they reach the LLM).
