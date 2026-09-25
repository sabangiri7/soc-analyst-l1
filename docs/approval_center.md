# Approval Center

Where every PROPOSE/EXECUTE proposal lives until a human decides. Backed by
`data/approvals.json` (gitignored); store access goes through `approvals.py`.

## Lifecycle

```
tool raises ApprovalRequired
  → registry persists proposal: action, reason, payload (tool's own params),
    permission, generated_config, validation, user, agent
  → status = pending            (data/approvals.json)
  → UI lists it (redacted: raw payloads are never shown in list views)

human:
  ├─ approve   → status = approved   (POST /api/proposals/<id>/approve)
  ├─ reject    → status = rejected   (POST /api/proposals/<id>/reject)
  └─ execute   → status = executing→done/failed
                  (POST /api/proposals/<id>/execute
                   EXECUTE-level tools require ?/confirm=true, else 400)
```

## Deterministic execution

Approve → execute does **not** re-prompt the LLM. The execute endpoint calls
`registry.execute(ctx, action, stored_payload)` with `ctx.approval` set; the
tool re-runs with its own stored input params:

- rules   → merge + PUT `local_rules.xml` → report the manager's "Rule was
  successfully uploaded" message
- dashboard → re-verify panel queries, create visualizations + dashboard via
  the saved-objects API → report only server-confirmed ids
- delete/restart/disable → only with `confirm`, then the API confirmation

Success is only claimed when the tool ran AND the API confirmed. Both
exceptions and `result.status == "error"` are failures.

## Audit

Approval Center human actions write audit rows with `permission="human"`
(`data/audit_log.jsonl`); registry execution rows carry the proposal id. That
includes `proposal_rejected` (rejections record the reason) and the CLI's
`/approve` `/reject` `/execute` — same rows, same store.

## Terminal (CLI) operator face

The terminal agent (`scripts_engineer_cli.py`) is a second face on **this
same** lifecycle — the CLI calls the same `approvals.py` functions the
dashboard endpoints call:

- `/proposals [status]` lists the store; `/proposals <id>` prints the full
  `public_view` (generated config diff, validation evidence, approvals,
  status) for review before signing.
- `/approve <id>`, `/reject <id> [reason]`, and `/execute <id> --confirm`
  resolve through `approvals.approve` / `approvals.reject` and
  `approval_executor.execute_proposal` — EXECUTE-level tools still require the
  explicit `--confirm`, and execution is still the deterministic stored-payload
  re-run. Nothing is written on the agent's say-so.
- The operator's identity is `--user` (default engine user) with
  `identity_verified=False` — no dashboard token involved, so this face is
  only appropriate on a trusted local machine. The web center remains the
  path for token-verified remote approvers.
- After every REPL turn the CLI prints `N approval(s) pending - /proposals
  pending to review`, reading the same live store; stale `pending` proposals
  are expired on read by `list_proposals`.

## Why payload round-tripping matters

The stored payload is the tool's own input params (e.g. `{rule_xml,
overwrite, reason}`) — *not* a pre-merged display blob. That is what makes
execution a true re-run: the same validation, pre-flight, and merge logic
applies at execution time, so what takes effect is the reviewed artifact, in
the shape the tool guarantees. (This invariant is enforced by tests — see
`tests/test_engine_tools.py`.)
