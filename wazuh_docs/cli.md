# Terminal agent: `scripts_engineer_cli.py`

The AI SOC engineer as a terminal agent - interactive REPL, one-shot prompts,
JSON output, persisted sessions, skill packs, and proposal approval. It drives
the **same** bounded tool-use engine as the dashboard (`agent/soc_engineer.py`)
with the same safety model, so there is exactly one agent, two faces.

```
python scripts_engineer_cli.py                        # interactive REPL
python scripts_engineer_cli.py -m "analyze rule 100001"
python scripts_engineer_cli.py -m "…" --json          # machine-readable
python scripts_engineer_cli.py --session web -m "…"   # persisted turn
python scripts_engineer_cli.py --session web --resume # continue the REPL
python scripts_engineer_cli.py --list-sessions
python scripts_engineer_cli.py --with-skill wazuh-rule-authoring -m "…"
python scripts_engineer_cli.py --list-skills
python scripts_engineer_cli.py --list-proposals pending
python scripts_engineer_cli.py --approve appr-abc123
python scripts_engineer_cli.py --execute appr-abc123 --confirm
```

Exit codes: `0` ok, `1` usage/data error, `2` LLM outage or tool-budget
exhaustion (still emits the JSON payload in `--json` mode, so pipelines can
distinguish a real answer from a failure).

## Safety model (identical to the dashboard)

- **READ** tools execute immediately (search/get/retrieve/ingest).
- **PROPOSE** tools raise `approval_required`; the agent reports the proposal
  id + diff. Nothing is written on the agent's say-so.
- **EXECUTE** (delete, restart, disable) needs `/approve` then
  `/execute <id> --confirm` - the CLI reuses the dashboard's exact single-use
  claim + stored-payload executor (`approval_executor.execute_proposal`).
- The CLI creates **no new write path** and gives the agent **no
  shell/filesystem tools**. A proposal payload can only be `approve`d/`execute`d
  from the operator's terminal, not by the agent itself.
- Local-operator trust boundary: the CLI identifies the operator via
  `--user` (default engine user) with `identity_verified=False` - no
  dashboard token is involved, so it is only appropriate on a trusted local
  machine. The web Approval Center remains the path for token-verified remote
  approvers.
- Every tool call and each session/skill action is audited to
  `data/audit_log.jsonl`.

## Skills ("add capabilities to the agent")

Skills are directories under `skills/` - a `SKILL.md` with YAML frontmatter
(`name`, `description`, `version`) plus an instruction body, and optional
co-located resource files:

```
skills/
  wazuh-rule-authoring/
    SKILL.md
  incident-triage/
    SKILL.md
  mitre-mapping/
    SKILL.md
```

- `--with-skill <name>` (repeatable) or `/use <name>` / `/unuse <name>` in the
  REPL activate packs for the session.
- Active skills are injected into the model's **system prompt** inside
  explicit `<SKILL name='…' role='instruction'>` markers, so the model can
  always tell trusted operator instructions from retrieved Wazuh content.
  Logs/RAG documents remain UNTRUSTED DATA and can never override them; the
  skill loader sanitizes bodies and neutralizes marker-shaped text, and never
  reads skill content from Wazuh.
- The active set is audited with every turn.
- To add your own skill: copy the pack pattern, keep the name lowercase
  (`[a-z0-9-]`), match the directory name to the frontmatter `name`, and
  re-run `--list-skills` to confirm it loads. A malformed pack is skipped when
  listing but rejected loudly when explicitly requested.

## REPL slash commands

```
/help                this help
/skills              list installed skill packs (+ which are active)
/use <name>          activate a skill pack for this session
/unuse <name>        deactivate a skill pack
/new                 reset conversation history
/proposals [status]  list proposals (default: pending)
/approve <id>        approve a pending proposal
/execute <id> [--confirm]   execute an approved proposal (--confirm for EXECUTE-level)
/audit [limit]       tail the audit log (default 10)
/exit, /quit         leave the REPL
```

## Sessions

`--session NAME` persists each turn (message, reply, data, proposals, skills,
full message list) as one JSON line per turn in `data/engineer_sessions/`.
`--resume` continues from the last turn's message list; `--list-sessions`
shows them. Sessions are a convenience for long investigations - the auth of
record remains the audit log.

## Notes

- One-shot `-m` with `--json` suppresses live step rendering and prints a
  single JSON object `{reply, data, proposals, transcript, session, skills}`.
- The REPL renders each tool call live (`→ get_wazuh_rules {…}`) before it
  runs; the final `answer_user` step is shown too.
- Related: `wazuh_docs/wazuh-rules.md` (RAG rule snapshots), the Approval
  Center flow in `docs/approval_center.md`, and `docs/permissions.md` for the
  READ/PROPOSE/EXECUTE model.