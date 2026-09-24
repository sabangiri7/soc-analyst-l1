**SOC L1 Triage Agent (multi-SIEM + CrowdStrike, self-improving RAG)**  
A working prototype of an agentic L1 SOC analyst: it pulls alerts from **any**  
 **  
 of several SIEM platforms** (Splunk, IBM QRadar, Elastic Security, Microsoft  
   
 Sentinel, Wazuh, or a mock), retrieves your playbooks and past case history,  
   
 enriches with CrowdStrike/Splunk, and produces a structured, cited verdict —  
   
 with a human-gated self-improvement loop that turns analyst corrections into  
   
 permanent memory.  
Runs entirely on your own machine. Only outbound calls are to the LLM API of  
   
 your choice (Anthropic / OpenAI-compatible / Google / FreeLLMAPI), your SIEM  
   
 instance(s), your CrowdStrike tenant, and (one-time, on first use) a small  
   
 embedding-model download for the local RAG store - see "Offline/air-gapped  
   
 RAG" below if even that isn't an option. A small web dashboard  
   
 (dashboard.py) lets you connect to and manage multiple SIEM providers at  
   
 once; its Metrics panel loads Chart.js from a CDN (cdnjs.cloudflare.com),  
   
 the one part of the dashboard itself that isn't fully self-contained.  
**Architecture**  
 Alert from any SIEM ──▶ TriageAgent (Claude, tool-use loop)  
                         │  
         ┌───────────────┼────────────────────┐  
         ▼               ▼                    ▼  
    RAG retrieval   Enrichment tools     submit_verdict  
    (playbooks,     (SIEM correlation,  (structured JSON:  
    cases, lessons)  CrowdStrike host/     verdict, confidence,  
    ChromaDB, local  process/detection)    action, rationale,  
                                           evidence cited)  
                         │  
                         ▼  
               data/triage_log.jsonl (audit trail)  
                         │  
                         ▼  
               feedback_cli.py review   ◀── analyst confirms/corrects  
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
                  - YOU approve each one  ◀── human checkpoint  
                         │  
                         ▼  
               RAG 'lessons' collection  
               (retrieved by the agent on future triage)  
   
**Why the self-improvement loop is split into two steps (capture vs.**  
 **  
 distill), and why distillation needs human approval:** writing memory live,  
   
 in the same loop that's making decisions, lets one noisy or wrong correction  
   
 immediately corrupt future triage. Batching it and requiring a person to  
   
 approve each distilled "lesson" before it goes live is the checkpoint that  
   
 catches that before it does damage.  
**Guardrails (read before pointing this at production)**  
- **The agent never executes containment actions.**isolate_host and  
   
 similar always go through DRY_RUN_ACTIONS=true by default — the agent  
   
 can only *recommend* isolation/account-disable, logged for a human to  
   
 execute manually. Only flip this once you trust the agent's precision on  
   
 your environment, and even then, start with reversible actions.  
- **Low-confidence and destructive-action verdicts always route to a**  
 **  
 human** — see the needs_human_review logic in main.py. Don't remove  
   
 this without a lot of production data behind you.  
- **Full audit trail** — every tool call and result is logged with each  
   
 case in data/triage_log.jsonl, tied to the alert ID.  
- **Self-improvement never writes to memory unattended** — distill_lessons  
   
 only proposes; a human approves via feedback_cli.py distill.  
**Setup**  
pip install -r requirements.txt  
 cp .env.example .env  
   
**1. Try it in mock mode first (no real Splunk/CrowdStrike needed)**  
Edit .env:  
ANTHROPIC_API_KEY=sk-ant-...   # required, real key  
 MOCK_MODE=true  
   
Ingest the seed playbooks into the local RAG store (one-time; downloads a  
   
 small local embedding model on first run - see "Offline/air-gapped RAG"  
   
 below if that download isn't possible in your environment):  
python scripts_ingest_seed.py  
   
Run the agent against the three sample alerts in seed_data/mock_alerts.json:  
python main.py demo  
   
You'll see each alert triaged with a verdict, confidence, recommended  
   
 action, and cited rationale, logged to data/triage_log.jsonl.  
***No API key yet? Use the offline *** *mock* *** provider***  
The LLM backend is pluggable (see "LLM providers" below). For a  
   
 fully-offline demo with **no API key at all**, use the deterministic mock  
   
 LLM (dev/CI/reference example):  
python main.py demo --provider mock  
 # or set LLM_PROVIDER=mock in .env  
   
It drives the real agent loop — RAG retrieval → enrichment → structured  
   
 verdict → audit log — with scripted reasoning per alert type, so you can  
   
 exercise the whole architecture before wiring credentials.  
   
**LLM providers (bring your own)**  
The triage reasoning runs on a pluggable LLM layer in llm/:  
| | | |  
|-|-|-|  
| **LLM_PROVIDER** | **Backend** | **Env vars** |   
| anthropic (default) | Claude | ANTHROPIC_API_KEY, ANTHROPIC_MODEL |   
| openai | Any OpenAI-compatible /chat/completions endpoint: OpenAI, OpenRouter, Ollama, vLLM, LM Studio, DeepSeek, ... | OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL |   
| google | Gemini | GOOGLE_API_KEY, GOOGLE_MODEL |   
| freellmapi | FreeLLMAPI gateway — one unified key for dozens of free LLM providers ([https://freellmapi.co)](https://freellmapi.co "https://freellmapi.co") | FREELLMAPI_API_KEY, FREELLMAPI_BASE_URL, FREELLMAPI_MODEL |   
| mock | Deterministic offline script (no key) | — |   
   
Any <PROVIDER>_MODEL you leave unset falls back to AGENT_MODEL. You can  
   
 override the provider per run without touching .env:  
python main.py demo --provider openai  
 python feedback_cli.py distill                 # uses LLM_PROVIDER from .env  
   
**Using FreeLLMAPI's unified key:** run the FreeLLMAPI gateway (self-hosted,  
   
 defaults to http://localhost:3001/v1), paste your provider keys into its  
   
 dashboard once, copy your unified freellmapi-... key, then:  
LLM_PROVIDER=freellmapi  
 FREELLMAPI_API_KEY=freellmapi-your-unified-key  
 # FREELLMAPI_BASE_URL=http://localhost:3001/v1   (default)  
 # FREELLMAPI_MODEL=auto                           (default - the gateway routes)  
   
model: "auto" lets the gateway pick the best available model and fail over  
   
 across providers automatically. Tool calling (used by the triage loop) is  
   
 supported over the same OpenAI-compatible surface, and each response's  
   
 X-Routed-Via header is printed so you can see which upstream actually served  
   
 the call.  
**Adding a new LLM provider:** implement llm/base.LLMProvider (one method —  
   
 chat(system, messages, tools, max_tokens) returning LLMResponse with  
   
 content + tool_calls), then register it in _PROVIDERS in  
   
 llm/__init__.py. Tool definitions are in one canonical shape  
   
 ({name, description, input_schema}); each provider translates that and the  
   
 normalized message format (see llm/base.py docstring) to its own wire  
   
 format. llm/mock_provider.py is the smallest working example;  
   
 llm/freellmapi_provider.py is the smallest useful one (subclass of the  
   
 OpenAI-compatible provider).  
**2. Review and correct verdicts (closes the feedback loop)**  
python feedback_cli.py review  
 python feedback_cli.py review --analyst jsmith    # or set ANALYST_NAME in .env  
   
Walks through cases flagged needs_human_review, asks you to confirm or  
   
 correct each verdict. Every response is immediately stored into the RAG  
   
 cases collection, so a near-identical future alert can retrieve it.  
   
 --analyst (or the ANALYST_NAME env var, or an interactive prompt if  
   
 neither is set) tags every correction with who made it - this is a single  
   
 free-text name recorded in data/feedback_log.jsonl, not an account system  
   
 (see "Dashboard auth" above for why this project doesn't do full  
   
 multi-user auth). metrics.py's analyst_agreement breaks agreement rate  
   
 down per analyst once more than one has reviewed cases.  
**3. Distill lessons from accumulated corrections (run periodically)**  
python feedback_cli.py distill  
 python feedback_cli.py distill --analyst jsmith  
   
Looks for recurring patterns across your corrections (needs a handful of  
   
 disagreements to find something generalizable — this won't produce much  
   
 after only 2-3 reviews). Proposes short "lessons"; you approve each one  
   
 before it's written to memory - --analyst records who approved it in the  
   
 lesson's approved_by metadata.  
**4. Go live against your SIEM(s) + CrowdStrike**  
Fill in the rest of .env, pick your default SIEM platform with  
   
 SIEM_PROVIDER (splunk | qradar | elastic | sentinel | wazuh | mock), and set  
   
 the matching credentials:  
MOCK_MODE=false  
 SIEM_PROVIDER=splunk  
 SPLUNK_HOST=https://splunk.yourcorp.local:8089  
 SPLUNK_TOKEN=...  
 SPLUNK_SEARCH=search index=notable status=new | head 20  
 FALCON_CLIENT_ID=...  
 FALCON_CLIENT_SECRET=...  
   
python main.py live  
   
Point this at a cron/scheduler to run periodically. Keep DRY_RUN_ACTIONS=true  
   
 until you've reviewed enough cases to trust the agent's precision on your  
   
 specific environment.  
**5. Connect multiple SIEMs with the dashboard**  
dashboard.py is a small web UI for managing SIEM connections — add any  
   
 number of providers across platforms, test them, pull their alerts, and run  
   
 the triage agent on them:  
pip install -r requirements.txt   # includes flask  
 python dashboard.py                # open http://127.0.0.1:5001  
   
From the dashboard you can:  
- **Add a provider** — name + platform (Splunk / IBM QRadar / Elastic  
   
 Security / Microsoft Sentinel / Wazuh / Mock) + connection details. Stored in  
 data/siem_providers.json; env-seeded connections (from .env) are always  
   
 listed too and can't be accidentally deleted.  
- **Test** — lightweight reachability + auth check per connection.  
- **Alerts** — pull the latest alerts from any provider (normalized to the  
   
 same shape the agent expects).  
- **Run triage** — triage that provider's newest alerts with the agent; each  
   
 verdict is written to data/triage_log.jsonl tagged with the provider.  
To run the agent against a specific connection from the CLI:  
python main.py live --siem env-qradar        # a dashboard/env provider id  
 python main.py live --siem wazuh             # any platform (uses its .env creds)  
   
**Wazuh** ships as a ready-made docker-compose stack in wazuh/ (manager +  
   
 indexer + dashboard, official 6.0.0 images) - see wazuh/README.md. Once it's  
   
 up, point the wazuh provider at the indexer (WAZUH_HOST=https://localhost:9200,  
   
 default admin/admin) and the agent reads alerts straight from the  
   
 wazuh-alerts-* index.  
See connectors/siem/ for how a new platform plugs in (Splunk, QRadar,  
   
 Elastic, Sentinel, and Wazuh are implemented; each is just a class  
   
 implementing SIEMConnector).  
**File guide**  
| | |  
|-|-|  
| **File** | **Purpose** |   
| agent/triage_agent.py | Core tool-use loop — the actual triage reasoning |   
| agent/memory.py | Feedback capture + lesson distillation (self-improvement) |   
| rag/knowledge_base.py | ChromaDB wrapper: playbooks / cases / lessons collections |   
| connectors/siem/ | Plugable SIEM layer: base.py (interface) + splunk / qradar / elastic / sentinel / wazuh / mock providers, selected by SIEM_PROVIDER |   
| wazuh/ | Docker-compose Wazuh 6.0 stack (manager + indexer + dashboard) the wazuh connector reads from |   
| connectors/crowdstrike_connector.py | Real CrowdStrike Falcon API calls (EDR enrichment, independent of which SIEM feeds alerts) |   
| connectors/mock_connectors.py | Canned responses for MOCK_MODE=true testing |   
| siem_providers.py | JSON-backed store of SIEM provider connections; merges env-seeded + dashboard-added providers |   
| rules.py | Local alert-rules engine: condition/threshold evaluation + CRUD + backtesting, backed by data/rules.json and data/rule_state.json |   
| notify.py | Outbound webhook notifications for rules.pyaction.notify, logged to data/notifications.jsonl regardless of whether a webhook is configured |   
| metrics.py | Read-only aggregate metrics over data/triage_log.jsonl (+ analyst agreement from data/feedback_log.jsonl) for the dashboard's Metrics panel |   
| cases.py | Read-only clustering of data/triage_log.jsonl alerts by shared host/user within a time window, for the dashboard's Cases panel |   
| digest.py | Periodic summary (built from metrics.py/cases.py) sent via notify.py - the piece a scheduler/cron calls |   
| log_rotation.py | Size/age-based rotation + gzip archiving for the project's JSONL logs (triage_log, chat_log, notifications, feedback_log) |   
| rag/embeddings.py | Deterministic offline embedding fallback (KB_EMBEDDING_MODE=hashing) for rag/knowledge_base.py - no download, no network |   
| dashboard.py | Flask dashboard - add/test/review multiple SIEM connections, view alerts, run triage |   
| templates/index.html | Dashboard UI (single self-contained page) |   
| llm/ | Pluggable LLM backend: base.py (interface) + anthropic / openai-compatible / google / freellmapi / mock providers, selected by LLM_PROVIDER |   
| seed_data/playbooks/*.md | Starter SOPs — **replace these with your org's real playbooks** |   
| main.py | Orchestrator: pull alerts, run triage, log results |   
| feedback_cli.py | Analyst review + lesson distillation CLI |   
   
**Stay on it through the night: **run.py  
run.py is the single entrypoint that runs the **actual SOC analyst** against  
   
 your live Wazuh stack in a long-running watch loop — exactly the process you  
   
 leave running overnight from the dashboard and shut off from the dashboard  
   
 when you're done:  
python run.py                       # watch mode - polls SIEM on an interval  
 python run.py --interval 120        # tune the poll cadence (seconds)  
 python run.py --exit-after 50       # stop cleanly after 50 poll cycles  
 python run.py --siem wazuh          # pin which dashboard provider to watch  
 python run.py --provider mock       # offline LLM for dev/CI (no key)  
   
- **Graceful shutdown** — Ctrl+C, SIGTERM, the dashboard's  **Stop agent**  
   
 button, or creating the stop file (data/agent_stop.txt). All exit 0 so  
   
 cron/systemd see a clean stop.  
- **Heartbeat** — each cycle appends to data/agent_heartbeat.json with  
   
 status / cycle / last-triggered alert id and timestamp, so the dashboard  
   
 shows "running / last seen Ns ago" without you SSH'ing in.  
- **Audit trail** — every verdict is appended to data/triage_log.jsonl  
   
 (same JSONL the dashboard history panel reads).  
- **Resilient** — a single bad alert never kills the watch; the SIEM pull and  
   
 the per-alert triage are each wrapped so one failure logs and continues.  
**Chat with the agent (conversational SOC assistant)**  
The dashboard has a chat panel backed by agent/chat_agent.py — same bounded  
   
 tool-use loop as triage, but conversational. Ask it things like:  
- «what's the status of alert SPLK-10231?»   (get_alert_status)  
- «show me jsmith's recent events»            (get_user_details / search_related_events)  
- «add 185.220.101.7 to the watchlist»        (R/W lookup tables)  
- «close SPLK-10245 as a false positive»      (R/W alerts via close_notable)  
- «list my SIEM providers / add Splunk»       (R/W dashboard providers)  
- «what do we know about the MOB malware?»    (web search / OSINT)  
- «what's 8.8.8.8's reputation?»              (web search)  
It reads/writes the same stores the dashboard manages (alerts, providers,  
   
 lookup tables) and writes the full transcript to data/chat_log.jsonl for  
   
 the audit trail. You can also run it as a REPL:  
python run.py chat      # or: python -c "from agent.chat_agent import ChatAgent; ..."  
   
**Lookup tables (R/W, JSON-backed)**  
lookup_tables.py gives you persistent allowlists / watchlists / threat-intel  
   
 stores, editable from the dashboard **and** from the chat agent:  
   
 list/read/create/upsert/delete_lookup_table, upsert_lookup_entry,  
   
 search_lookup. Tables live in data/lookup_tables.json (gitignored).  
**Alert rules (local correlation, before the LLM ever sees the alert)**  
rules.py gives you deterministic, zero-cost pre-filtering/correlation  
   
 evaluated against every alert right after it's pulled from the SIEM and  
   
 before TriageAgent spends any tool calls on it — the same role a SIEM's  
   
 own correlation search plays, but running locally so it never depends on  
   
 LLM availability. A rule is a condition tree (field/op/value, combined  
   
 all/any) plus an optional threshold (e.g. "5 matching alerts for the  
   
 same src_ip within 15 minutes", counted in data/rule_state.json across  
   
 polls) and an action (tag, escalate, notify). Conditions can  
   
 reference a lookup table via op: "in_lookup", so watchlists you build from  
   
 the dashboard/chat agent feed straight into rules. A triggered rule with  
   
 escalate: true forces needs_human_review, same as a low-confidence LLM  
   
 verdict — see the rule_matches field main.py/run.py/the dashboard's  
   
 triage route all now write into data/triage_log.jsonl.  
   
 CRUD: list/read/create/update/delete_rule; evaluate with evaluate_all  
   
 (persists threshold state) or evaluate_rule(..., dry_run=True) (doesn't —  
   
 used by the dashboard's "test rule" action). Manage rules from the  
   
 dashboard's 🧩 **Alert Rules** panel, or directly against data/rules.json.  
**Rule import/export**  
Share a baseline rule set across environments the same way seed_data/playbooks/  
   
 shares SOPs - seed_data/rules/baseline_rules.json is a starter set:  
python rules.py export --out my-rules.json     # portable JSON - no id/created/updated  
 python rules.py import seed_data/rules/baseline_rules.json  
 python rules.py import my-rules.json --overwrite   # update existing rules with matching names in place  
   
Rules match across an import by **name** (ids won't line up between  
   
 environments); by default a name collision is skipped, leaving the existing  
   
 rule untouched - pass --overwrite to update it in place instead. The  
   
 dashboard's 🧩 Alert Rules panel has matching **Export all as JSON** /  
   
 **Import from file…** buttons (GET /api/rules/export, POST /api/rules/import).  
**Rule backtesting**  
Before enabling a rule live, see how often it would have fired historically:  
python rules.py list  
 python rules.py backtest rule-3c42ccde06 --limit 200  
   
rules.backtest_rule() dry-runs the rule against data/triage_log.jsonl -  
   
 it never touches the real threshold-window state, so trying a rule out  
   
 doesn't perturb its actual counters. Only run.py's watch-loop entries carry  
   
 a real timestamp ("ts"); main.py/the dashboard's on-demand entries don't,  
   
 so threshold windows during a backtest fall back to treating consecutive  
   
 matched alerts as one second apart where no "ts" is available - enough to  
   
 see the rough shape ("this would have fired ~14 times"), not to reproduce  
   
 exact historical timing. The dashboard's 🧩 Alert Rules panel has a  
   
 **Backtest** button per rule that calls the same thing via POST /api/rules/<id>/backtest.  
**Notifications (rules.py action.notify)**  
notify.py fires when a triggered rule's action.notify field (see "Alert  
   
 rules" above) is set to something non-empty. It POSTs a Slack-incoming-webhook-  
   
 compatible {"text": "..."} body to NOTIFY_WEBHOOK_URL (works as-is for  
   
 Slack, Mattermost, and most "generic webhook" Teams/Discord connectors); with  
   
 no webhook configured it still logs every notification locally to  
   
 data/notifications.jsonl, so there's an audit trail from day one. A broken  
   
 or unreachable webhook never blocks or kills a triage run - send_notification()  
   
 catches its own errors and always returns a result dict rather than raising.  
**Case/incident grouping**  
cases.py clusters alerts from data/triage_log.jsonl by shared host or  
   
 user within a time window (default 30 minutes), so a flurry of related  
   
 alerts shows up as one case instead of unconnected rows. Two alerts link  
   
 when they share a non-empty host OR user (not necessarily both) and fall  
   
 within the window; a chain (A-B share a host, B-C share a user) merges into  
   
 one case via union-find even when A and C share nothing directly. Read-only  
- like metrics.py, this is just a different view over the same log,  
   
 nothing is written.  
python cases.py                                 # default 30-minute window  
 python cases.py --window-minutes 60 --min-alerts 2   # only show actual clusters  
   
The dashboard's 🗂️ Cases panel calls the same thing via GET /api/cases  
   
 (query params: window_minutes, limit, min_alerts) - it's on-demand  
   
 (click **Load cases**) rather than loading automatically, since grouping is  
   
 O(n²) over however many log entries you scan.  
**Metrics**  
GET /api/metrics (metrics.py) aggregates data/triage_log.jsonl into:  
   
 verdict counts by day, a confidence-score histogram, the overall  
   
 needs_human_review rate, alert volume and needs-review rate per SIEM  
   
 provider, and which rules trigger most often alongside their true-positive  
   
 rate (how often a rule's trigger actually lined up with a true_positive  
   
 verdict) - plus, once you've run feedback_cli.py review a few times, the  
   
 analyst-agreement rate from data/feedback_log.jsonl. Nothing here is  
   
 cached or persisted; it's always a live read of the current logs. The  
   
 dashboard's 📊 Metrics panel renders this with Chart.js.  
**Scheduled digest reports**  
digest.py builds a periodic summary from metrics.py's aggregates  
   
 (verdict totals, needs-review rate, top triggered rules, per-provider  
   
 breakdown, and notable host/user clusters from cases.py) and sends it  
   
 through notify.py's webhook - point cron/a scheduler at it:  
python digest.py --period daily --dry-run          # print without sending  
 python digest.py --period daily --target "#soc-daily"  
 python digest.py --period weekly  
   
Like the rest of the timestamp-dependent tooling in this project  
   
 (cases.py, rules.py's backtest, metrics.py), period filtering  
   
 (daily/weekly) only counts log entries that carry a real "ts" field -  
   
 today, only run.py's watch-loop entries do. If you're only running  
   
 main.py/the dashboard's on-demand triage, use --period all to see  
   
 everything regardless of timestamp; the digest text says so explicitly when  
   
 a period comes back empty for this reason.  
**Log rotation**  
triage_log.jsonl, chat_log.jsonl, notifications.jsonl, and  
   
 feedback_log.jsonl are all append-only and grow forever otherwise -  
   
 none of the writers rotate on their own. Run this periodically (cron, or by  
   
 hand):  
python log_rotation.py                                    # default: rotate anything >100MB or >30 days old  
 python log_rotation.py --max-bytes 50000000 --max-age-days 14  
 python log_rotation.py --prune-archives-older-than-days 365  # also delete old .jsonl.gz archives  
   
A rotated log is gzip-compressed to data/archive/<name>.<timestamp>.jsonl.gz  
   
 and the original file is truncated to empty (not deleted - every writer  
   
 assumes the file exists). Pruning archives is opt-in and separate from  
   
 rotation itself - nothing is ever deleted unless you ask for it.  
**Offline/air-gapped RAG**  
By default rag/knowledge_base.py downloads a small sentence-transformer  
   
 model the first time it's used (needs internet; everything after that is  
   
 fully offline). If that download isn't an option - air-gapped deployment,  
   
 locked-down CI, no network at all - set:  
KB_EMBEDDING_MODE=hashing  
   
This switches to a deterministic, dependency-free bag-of-words embedding  
   
 (rag/embeddings.py) - no download, no model file, no network, ever.  
   
 Retrieval quality is noticeably worse (it only picks up literal shared  
   
 words between texts, with no notion of meaning), so use it only when you  
   
 can't use the default. MOCK_MODE=true selects this automatically, which  
   
 is how the test suite exercises the full TriageAgent tool-use loop  
   
 (playbook retrieval included) without needing network access.  
A Chroma collection's embedding function is fixed at creation time in its  
   
 on-disk data; if CHROMA_DB_PATH already has data created under a  
   
 different mode, KnowledgeBase falls back to whatever's actually persisted  
   
 there rather than erroring, so flipping MOCK_MODE on an existing data  
   
 directory degrades gracefully instead of crashing.  
**Web search (OSINT, no API key required)**  
The web_search tool queries **DuckDuckGo instant-answer** first, falls back  
   
 to **SearXNG** (SEARXNG_URL), and returns a graceful offline result when  
   
 neither is reachable — no API key, never blocks triage. Set WEB_SEARCH_ENABLED=false  
   
 to disable entirely.  
**LLM resilience: retry with backoff**  
Every LLM provider (llm/openai_compat_provider.py and everything that  
   
 subclasses it, incl. FreeLLMAPI) retries transient **429 / 5xx / network**  
   
 failures with exponential backoff + jitter instead of aborting a whole batch —  
   
 so a free-gateway rate limit never kills your overnight run:  
LLM_MAX_RETRIES=5            # attempts after the first (0 disables retry)  
 LLM_RETRY_BACKOFF_BASE=1.5   # backoff multiplier between attempts  
 LLM_RETRY_BACKOFF_MAX=30     # cap on each backoff step (seconds)  
   
**Extending this**  
- **More alert types**: add playbooks to seed_data/playbooks/ and re-run  
 scripts_ingest_seed.py — no code changes needed, the agent retrieves  
   
 whatever's relevant.  
- **Another SIEM platform**: implement connectors/siem/base.SIEMConnector  
   
 (4 methods: get_new_alerts, search_related_events, close_notable,  
 _ping), drop it in connectors/siem/, and register it in  
 SIEM_PLATFORMS + PLATFORM_FIELDS in connectors/siem/__init__.py.  
   
 The agent, dashboard, and main.py --siem pick it up automatically.  
- **Ticketing integration**: have main.py open/update a ticket (Jira,  
   
 ServiceNow) instead of / in addition to the JSONL log.  
- **More enrichment tools**: add a method to a connector + an entry in the  
 TOOLS list and _execute_tool dispatch in triage_agent.py — e.g. a  
   
 VirusTotal hash lookup, or a DNS history tool.  
- **Metrics**: track precision/recall per detection rule from  
 data/triage_log.jsonl vs. analyst corrections over time — this is what  
   
 tells you when it's safe to raise AUTO_CLOSE_CONFIDENCE_THRESHOLD or  
   
 flip DRY_RUN_ACTIONS.  
**Dashboard panels**  
The Flask dashboard (dashboard.py, port 5001) now exposes seven new panels beyond the SIEM provider cards:  
- **📊 Metrics** (GET /api/metrics) — verdict counts by day, a confidence histogram, needs-review rate overall and per provider, and top triggered rules with their true-positive rate, rendered with Chart.js. See "Metrics" above.  
- **🗂️ Cases** (GET /api/cases) — alerts clustered by shared host/user within a time window, on-demand. See "Case/incident grouping" above.  
- **💬 SOC Chat Assistant** (POST /api/chat, GET /api/chat/history) — a conversational L1 analyst that can answer questions about alerts, look up user/host enrichment, manage lookup tables, and optionally connect to a SIEM for live alert context. Every exchange is appended to data/chat_log.jsonl for audit.  
- **📋 Lookup Tables** (GET/POST /api/lookup-tables, GET/DELETE /api/lookup-tables/<name>, POST/DELETE /api/lookup-tables/<name>/entries/<key>) — full CRUD for threat-intel / watchlist stores backed by data/lookup_tables.json. The chat agent calls these same primitives via its write_lookup_table tool.  
- **🧩 Alert Rules** (GET/POST /api/rules, GET/PATCH/DELETE /api/rules/<id>, POST /api/rules/<id>/test, POST /api/rules/<id>/backtest, POST /api/rules/preview, GET/POST /api/rules/export|import, GET /api/rules/ops) — a rule builder (condition rows + optional threshold/grouping + tag/escalate/notify action) backed by data/rules.json, with dry-run "test against a sample alert", "backtest against history", and JSON export/import actions. Test/backtest never touch the real threshold counters in data/rule_state.json. Rules run automatically before every triage — see "Alert rules" above.  
- **🤖 Overnight Watcher** (GET/POST /api/agent, POST /api/agent/start|stop) — controls run.py's overnight triage loop. Start spawns python run.py in a detached session and writes an initial heartbeat; stop writes the stop-file kill switch (data/agent_stop.txt) and best-effort SIGTERMs the watcher PID. Status reports running/stopped, last heartbeat age, current cycle count, and whether the stop file is present. Poll every 2–5 s from the UI.  
**Dashboard auth**  
Every route above is open by default (fine for strictly local use on  
   
 127.0.0.1). Set DASHBOARD_TOKEN in .env before binding --host to  
   
 anything else — every route (including ones that write to the SIEM,  
   
 start/stop the overnight watcher, and CRUD lookup tables/rules) is otherwise  
   
 unauthenticated. With a token set, open the dashboard once as  
   
 http://<host>:5001/?token=<your token>; the page reads it off the URL,  
   
 stores it in sessionStorage, strips it from the address bar, and attaches  
   
 it as Authorization: Bearer <token> on every API call from then on. The  
   
 token is also accepted directly as ?token=... on any API request (e.g. for  
   
 curl).  
