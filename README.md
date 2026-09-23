# SOC L1 Triage Agent (multi-SIEM + CrowdStrike, self-improving RAG)

A working prototype of an agentic L1 SOC analyst: it pulls alerts from **any
of several SIEM platforms** (Splunk, IBM QRadar, Elastic Security, Microsoft
Sentinel, Wazuh, or a mock), retrieves your playbooks and past case history,
enriches with CrowdStrike/Splunk, and produces a structured, cited verdict —
with a human-gated self-improvement loop that turns analyst corrections into
permanent memory.

Runs entirely on your own machine. Only outbound calls are to the LLM API of
your choice (Anthropic / OpenAI-compatible / Google / FreeLLMAPI), your SIEM
instance(s), and your CrowdStrike tenant. A small web dashboard
(`dashboard.py`) lets you connect to and manage multiple SIEM providers at
once.

## Architecture

```
 Alert from any SIEM ──▶ TriageAgent (Claude, tool-use loop)
                        │
        ┌───────────────┼────────────────────┐
        ▼               ▼                    ▼
   RAG retrieval   Enrichment tools     submit_verdict
   (playbooks,     (SIEM correlation,  (structured JSON:
   cases, lessons)  CrowdStrike host/     verdict, confidence,
   ChromaDB, local  process/detection)    action, rationale,
                                          evidence cited)
                        │
                        ▼
              data/triage_log.jsonl (audit trail)
                        │
                        ▼
              feedback_cli.py review   ◀── analyst confirms/corrects
                        │
                        ▼
              MemoryStore.capture_feedback
                 - logs raw feedback
                 - stores closed case → RAG 'cases' collection (immediate)
                        │
                        ▼ (batch, e.g. nightly)
              feedback_cli.py distill
                 - Claude looks for recurring patterns in corrections
                 - proposes "lessons"
                 - YOU approve each one  ◀── human checkpoint
                        │
                        ▼
              RAG 'lessons' collection
              (retrieved by the agent on future triage)
```

**Why the self-improvement loop is split into two steps (capture vs.
distill), and why distillation needs human approval:** writing memory live,
in the same loop that's making decisions, lets one noisy or wrong correction
immediately corrupt future triage. Batching it and requiring a person to
approve each distilled "lesson" before it goes live is the checkpoint that
catches that before it does damage.

## Guardrails (read before pointing this at production)

- **The agent never executes containment actions.** `isolate_host` and
  similar always go through `DRY_RUN_ACTIONS=true` by default — the agent
  can only *recommend* isolation/account-disable, logged for a human to
  execute manually. Only flip this once you trust the agent's precision on
  your environment, and even then, start with reversible actions.
- **Low-confidence and destructive-action verdicts always route to a
  human** — see the `needs_human_review` logic in `main.py`. Don't remove
  this without a lot of production data behind you.
- **Full audit trail** — every tool call and result is logged with each
  case in `data/triage_log.jsonl`, tied to the alert ID.
- **Self-improvement never writes to memory unattended** — `distill_lessons`
  only proposes; a human approves via `feedback_cli.py distill`.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
```

### 1. Try it in mock mode first (no real Splunk/CrowdStrike needed)

Edit `.env`:
```
ANTHROPIC_API_KEY=sk-ant-...   # required, real key
MOCK_MODE=true
```

Ingest the seed playbooks into the local RAG store (one-time; downloads a
small local embedding model on first run):
```bash
python scripts_ingest_seed.py
```

Run the agent against the three sample alerts in `seed_data/mock_alerts.json`:
```bash
python main.py demo
```

You'll see each alert triaged with a verdict, confidence, recommended
action, and cited rationale, logged to `data/triage_log.jsonl`.

#### No API key yet? Use the offline `mock` provider

The LLM backend is pluggable (see "LLM providers" below). For a
fully-offline demo with **no API key at all**, use the deterministic mock
LLM (dev/CI/reference example):
```bash
python main.py demo --provider mock
# or set LLM_PROVIDER=mock in .env
```
It drives the real agent loop — RAG retrieval → enrichment → structured
verdict → audit log — with scripted reasoning per alert type, so you can
exercise the whole architecture before wiring credentials.

## LLM providers (bring your own)

The triage reasoning runs on a pluggable LLM layer in `llm/`:

| `LLM_PROVIDER` | Backend | Env vars |
|---|---|---|
| `anthropic` (default) | Claude | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` |
| `openai` | Any OpenAI-compatible `/chat/completions` endpoint: OpenAI, OpenRouter, Ollama, vLLM, LM Studio, DeepSeek, ... | `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL` |
| `google` | Gemini | `GOOGLE_API_KEY`, `GOOGLE_MODEL` |
| `freellmapi` | FreeLLMAPI gateway — one unified key for dozens of free LLM providers (https://freellmapi.co) | `FREELLMAPI_API_KEY`, `FREELLMAPI_BASE_URL`, `FREELLMAPI_MODEL` |
| `mock` | Deterministic offline script (no key) | — |

Any `<PROVIDER>_MODEL` you leave unset falls back to `AGENT_MODEL`. You can
override the provider per run without touching `.env`:
```bash
python main.py demo --provider openai
python feedback_cli.py distill                 # uses LLM_PROVIDER from .env
```

**Using FreeLLMAPI's unified key:** run the FreeLLMAPI gateway (self-hosted,
defaults to `http://localhost:3001/v1`), paste your provider keys into its
dashboard once, copy your unified `freellmapi-...` key, then:
```
LLM_PROVIDER=freellmapi
FREELLMAPI_API_KEY=freellmapi-your-unified-key
# FREELLMAPI_BASE_URL=http://localhost:3001/v1   (default)
# FREELLMAPI_MODEL=auto                           (default - the gateway routes)
```
`model: "auto"` lets the gateway pick the best available model and fail over
across providers automatically. Tool calling (used by the triage loop) is
supported over the same OpenAI-compatible surface, and each response's
`X-Routed-Via` header is printed so you can see which upstream actually served
the call.

**Adding a new LLM provider:** implement `llm/base.LLMProvider` (one method —
`chat(system, messages, tools, max_tokens)` returning `LLMResponse` with
`content` + `tool_calls`), then register it in `_PROVIDERS` in
`llm/__init__.py`. Tool definitions are in one canonical shape
(`{name, description, input_schema}`); each provider translates that and the
normalized message format (see `llm/base.py` docstring) to its own wire
format. `llm/mock_provider.py` is the smallest working example;
`llm/freellmapi_provider.py` is the smallest useful one (subclass of the
OpenAI-compatible provider).

### 2. Review and correct verdicts (closes the feedback loop)

```bash
python feedback_cli.py review
```

Walks through cases flagged `needs_human_review`, asks you to confirm or
correct each verdict. Every response is immediately stored into the RAG
`cases` collection, so a near-identical future alert can retrieve it.

### 3. Distill lessons from accumulated corrections (run periodically)

```bash
python feedback_cli.py distill
```

Looks for recurring patterns across your corrections (needs a handful of
disagreements to find something generalizable — this won't produce much
after only 2-3 reviews). Proposes short "lessons"; you approve each one
before it's written to memory.

### 4. Go live against your SIEM(s) + CrowdStrike

Fill in the rest of `.env`, pick your default SIEM platform with
`SIEM_PROVIDER` (splunk | qradar | elastic | sentinel | wazuh | mock), and set
the matching credentials:
```
MOCK_MODE=false
SIEM_PROVIDER=splunk
SPLUNK_HOST=https://splunk.yourcorp.local:8089
SPLUNK_TOKEN=...
SPLUNK_SEARCH=search index=notable status=new | head 20
FALCON_CLIENT_ID=...
FALCON_CLIENT_SECRET=...
```

```bash
python main.py live
```

Point this at a cron/scheduler to run periodically. Keep `DRY_RUN_ACTIONS=true`
until you've reviewed enough cases to trust the agent's precision on your
specific environment.

### 5. Connect multiple SIEMs with the dashboard

`dashboard.py` is a small web UI for managing SIEM connections — add any
number of providers across platforms, test them, pull their alerts, and run
the triage agent on them:

```bash
pip install -r requirements.txt   # includes flask
python dashboard.py                # open http://127.0.0.1:5001
```

From the dashboard you can:
- **Add a provider** — name + platform (Splunk / IBM QRadar / Elastic
  Security / Microsoft Sentinel / Wazuh / Mock) + connection details. Stored in
  `data/siem_providers.json`; env-seeded connections (from `.env`) are always
  listed too and can't be accidentally deleted.
- **Test** — lightweight reachability + auth check per connection.
- **Alerts** — pull the latest alerts from any provider (normalized to the
  same shape the agent expects).
- **Run triage** — triage that provider's newest alerts with the agent; each
  verdict is written to `data/triage_log.jsonl` tagged with the provider.

To run the agent against a specific connection from the CLI:

```bash
python main.py live --siem env-qradar        # a dashboard/env provider id
python main.py live --siem wazuh             # any platform (uses its .env creds)
```

**Wazuh** ships as a ready-made docker-compose stack in `wazuh/` (manager +
indexer + dashboard, official 6.0.0 images) - see `wazuh/README.md`. Once it's
up, point the `wazuh` provider at the indexer (`WAZUH_HOST=https://localhost:9200`,
default `admin`/`admin`) and the agent reads alerts straight from the
`wazuh-alerts-*` index.

See `connectors/siem/` for how a new platform plugs in (Splunk, QRadar,
Elastic, Sentinel, and Wazuh are implemented; each is just a class
implementing `SIEMConnector`).

## File guide

| File | Purpose |
|---|---|
| `agent/triage_agent.py` | Core tool-use loop — the actual triage reasoning |
| `agent/memory.py` | Feedback capture + lesson distillation (self-improvement) |
| `rag/knowledge_base.py` | ChromaDB wrapper: playbooks / cases / lessons collections |
| `connectors/siem/` | Plugable SIEM layer: `base.py` (interface) + splunk / qradar / elastic / sentinel / wazuh / mock providers, selected by `SIEM_PROVIDER` |
| `wazuh/` | Docker-compose Wazuh 6.0 stack (manager + indexer + dashboard) the `wazuh` connector reads from |
| `connectors/crowdstrike_connector.py` | Real CrowdStrike Falcon API calls (EDR enrichment, independent of which SIEM feeds alerts) |
| `connectors/mock_connectors.py` | Canned responses for `MOCK_MODE=true` testing |
| `siem_providers.py` | JSON-backed store of SIEM provider connections; merges env-seeded + dashboard-added providers |
| `dashboard.py` | Flask dashboard - add/test/review multiple SIEM connections, view alerts, run triage |
| `templates/index.html` | Dashboard UI (single self-contained page) |
| `llm/` | Pluggable LLM backend: `base.py` (interface) + anthropic / openai-compatible / google / freellmapi / mock providers, selected by `LLM_PROVIDER` |
| `seed_data/playbooks/*.md` | Starter SOPs — **replace these with your org's real playbooks** |
| `main.py` | Orchestrator: pull alerts, run triage, log results |
| `feedback_cli.py` | Analyst review + lesson distillation CLI |

## Stay on it through the night: `run.py`

`run.py` is the single entrypoint that runs the **actual SOC analyst** against
your live Wazuh stack in a long-running watch loop — exactly the process you
leave running overnight from the dashboard and shut off from the dashboard
when you're done:

```bash
python run.py                       # watch mode - polls SIEM on an interval
python run.py --interval 120        # tune the poll cadence (seconds)
python run.py --exit-after 50       # stop cleanly after 50 poll cycles
python run.py --siem wazuh          # pin which dashboard provider to watch
python run.py --provider mock       # offline LLM for dev/CI (no key)
```

- **Graceful shutdown** — `Ctrl+C`, `SIGTERM`, the dashboard's **Stop agent**
  button, or creating the stop file (`data/agent_stop.txt`). All exit `0` so
  cron/systemd see a clean stop.
- **Heartbeat** — each cycle appends to `data/agent_heartbeat.json` with
  status / cycle / last-triggered alert id and timestamp, so the dashboard
  shows "running / last seen Ns ago" without you SSH'ing in.
- **Audit trail** — every verdict is appended to `data/triage_log.jsonl`
  (same JSONL the dashboard history panel reads).
- **Resilient** — a single bad alert never kills the watch; the SIEM pull and
  the per-alert triage are each wrapped so one failure logs and continues.

## Chat with the agent (conversational SOC assistant)

The dashboard has a chat panel backed by `agent/chat_agent.py` — same bounded
tool-use loop as triage, but conversational. Ask it things like:

- «what's the status of alert SPLK-10231?»   (get_alert_status)
- «show me jsmith's recent events»            (get_user_details / search_related_events)
- «add 185.220.101.7 to the watchlist»        (R/W lookup tables)
- «close SPLK-10245 as a false positive»      (R/W alerts via close_notable)
- «list my SIEM providers / add Splunk»       (R/W dashboard providers)
- «what do we know about the MOB malware?»    (web search / OSINT)
- «what's 8.8.8.8's reputation?»              (web search)

It reads/writes the same stores the dashboard manages (alerts, providers,
lookup tables) and writes the full transcript to `data/chat_log.jsonl` for
the audit trail. You can also run it as a REPL:

```bash
python run.py chat      # or: python -c "from agent.chat_agent import ChatAgent; ..."
```

### Lookup tables (R/W, JSON-backed)

`lookup_tables.py` gives you persistent allowlists / watchlists / threat-intel
stores, editable from the dashboard **and** from the chat agent:
`list/read/create/upsert/delete_lookup_table`, `upsert_lookup_entry`,
`search_lookup`. Tables live in `data/lookup_tables.json` (gitignored).

### Web search (OSINT, no API key required)

The `web_search` tool queries **DuckDuckGo instant-answer** first, falls back
to **SearXNG** (`SEARXNG_URL`), and returns a graceful offline result when
neither is reachable — no API key, never blocks triage. Set `WEB_SEARCH_ENABLED=false`
to disable entirely.

## LLM resilience: retry with backoff

Every LLM provider (`llm/openai_compat_provider.py` and everything that
subclasses it, incl. FreeLLMAPI) retries transient **429 / 5xx / network**
failures with exponential backoff + jitter instead of aborting a whole batch —
so a free-gateway rate limit never kills your overnight run:

```bash
LLM_MAX_RETRIES=5            # attempts after the first (0 disables retry)
LLM_RETRY_BACKOFF_BASE=1.5   # backoff multiplier between attempts
LLM_RETRY_BACKOFF_MAX=30     # cap on each backoff step (seconds)
```

## Extending this

- **More alert types**: add playbooks to `seed_data/playbooks/` and re-run
  `scripts_ingest_seed.py` — no code changes needed, the agent retrieves
  whatever's relevant.
- **Another SIEM platform**: implement `connectors/siem/base.SIEMConnector`
  (4 methods: `get_new_alerts`, `search_related_events`, `close_notable`,
  `_ping`), drop it in `connectors/siem/`, and register it in
  `SIEM_PLATFORMS` + `PLATFORM_FIELDS` in `connectors/siem/__init__.py`.
  The agent, dashboard, and `main.py --siem` pick it up automatically.
- **Ticketing integration**: have `main.py` open/update a ticket (Jira,
  ServiceNow) instead of / in addition to the JSONL log.
- **More enrichment tools**: add a method to a connector + an entry in the
  `TOOLS` list and `_execute_tool` dispatch in `triage_agent.py` — e.g. a
  VirusTotal hash lookup, or a DNS history tool.
- **Metrics**: track precision/recall per detection rule from
  `data/triage_log.jsonl` vs. analyst corrections over time — this is what
  tells you when it's safe to raise `AUTO_CLOSE_CONFIDENCE_THRESHOLD` or
  flip `DRY_RUN_ACTIONS`.
