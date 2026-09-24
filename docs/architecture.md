# Architecture

How the AI SOC Engineer fits together, and where it sits relative to the base
triage agent this repo started as.

## Two agents, one codebase

- **Triage agent** (`agent/triage_agent.py`, `agent/chat_agent.py`): the
  original L1 alert triage / conversational assistant over SIEM + CrowdStrike
  connectors. Unchanged by the engineer work.
- **AI SOC Engineer** (`agent/soc_engineer.py`): a conversational detection /
  investigation / dashboard engineer for Wazuh, driving the **typed tool
  layer** (`tools/`) through the same bounded tool-use loop, with a
  READ / PROPOSE / EXECUTE approval model.

```
user ──▶ dashboard POST /api/engineer/chat ──▶ SOCEngineer (LLM tool-use loop)
                                                  │
                                                  ▼
        tools/registry.execute(ctx, name, params)   ← ONE gate for everything
          ├─ schema validation + audit row
          ├─ permission gate (README short)
          │    READ → run now
          │    PROPOSE/EXECUTE without approval → tool raises ApprovalRequired
          │                                  → proposal persisted (approvals.py)
          ├─ run tool  (engines below)
          └─ guard.limit_result_size → wrap as UNTRUSTED DATA → back to LLM

  engines (each a BaseWazuhTool, registered in tools/registry.py):
    tools/investigate   top_attacking_ips / investigate_ip / why_did_alert_trigger
    tools/detection     develop_wazuh_rule / verify_rule_deployment (+ rule CRUD)
    tools/dashboard     design_detection_dashboard
    tools/gaps          analyze_detection_gaps
    tools/wazuh         rules / decoders / agents / logtest / config / status
    tools/indexer       search alerts/events / schema / verify query
    tools/rag           retrieve_wazuh_docs (playbooks/cases/lessons/wazuh_docs)

  context: ToolContext(wazuh=WazuhManagerAPI(), indexer=IndexerClient(),
                       approval=<human-approved proposal> | None)
```

## Key modules

| Module | Role |
|---|---|
| `agent/soc_engineer.py` | Bounded LLM tool-use loop; builds a fresh `ToolContext` per `chat()`; surfaces proposals + proposal ids; hard rules (data vs instructions, no fabricated success) in prompt and code |
| `tools/base.py` | `Permission`, `ToolContext`, `BaseWazuhTool` interface, `Approve_or_raise`, error types |
| `tools/registry.py` | The single execution gate: schema validation → permission gate → run → audit → DATA-wrapping |
| `tools/api_client.py` | Wazuh manager REST client (JWT auth, rules/decoders/agents/logtest/status) |
| `tools/indexer_client.py` | Indexer client over the existing `WazuhConnector` HTTP path |
| `approvals.py` | Proposal store: create / list / approve / reject / execute, re-run with the stored payload |
| `audit.py` | Append-only JSONL audit log |
| `guard.py` | Prompt-injection defense: DATA markers, sanitize, size caps (see `docs/prompt_injection_defense.md`) |
| `rag/knowledge_base.py` | Local ChromaDB store: playbooks / cases / lessons / wazuh_docs |
| `wazuh_docs/` + `scripts_ingest_wazuh_docs.py` | Curated engineering reference seeded into RAG |
| `dashboard.py` | Web UI incl. the Approval Center (`/api/proposals…`) and the engineer chat (`/api/engineer/chat`) |

## Data flow guarantees

- **Deterministic execution**: approved proposals store the tool's own input
  params; execution re-runs the same call — no LLM in the execution step.
- **Evidence before claims**: investigation/detection/gap/dashboard numbers
  come from real manager + indexer responses; nothing is guessed.
- **Safe by construction**: writes only happen through PROPOSE→approve→EXECUTE;
  the gate is code, not prompt wording.

See also: `docs/permissions.md` (the approval model), `docs/golden_workflows.md`
(the canonical end-to-end flows), `docs/approval_center.md` (the UI).