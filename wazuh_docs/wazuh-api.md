# Wazuh manager API facts

Live-verified behavior of the manager API this agent talks to (4.14.x).

## Connectivity / auth

- Base URL: `https://<manager>:55000`. The API needs the CA certificate
  verified - the bundled stack's `wazuh-api` uses its own CA.
- Auth is `Authorization: Basic base64(user:pass)` + `run_as: true` headers.
  No OAuth, no API-key scheme by default.
- The auth endpoint itself (GET /security/user/authenticate) doubles as the
  health check; a 200 with an authorization token means the API is up. Do not
  use GET /system/status - it 404s.

## Read endpoints

- `GET /rules?limit=..&offset=..` lists the ruleset. `q=id=NNN` filters by
  exact id (used by rule pre-flight checks). The response wraps items in
  `data.affected_items` and reports `data.total_affected_items`.
- `GET /rules/files/...` returns a specific rules file. When the file does
  not exist yet the API reports "not found" - for `local_rules.xml` on a
  fresh manager that simply means the file is empty.
- `GET /agents`, `GET /manager/status`, `GET /cluster/status` follow the same
  `data.affected_items` envelope.

## Writes

- Rules files are PUT as octet-stream bodies (`Content-Type: application/octet-stream`).
  On acceptance the manager returns `message: "Rule was successfully
  uploaded"` with `data.affected_items: ["local_rules.xml"]`. That message is
  the ONLY signal that the file was validated and accepted.
- Never assume a silent success: if the response lacks the upload message,
  the write did not happen.

## Readiness / restart

- `GET /manager/status` -> `data.affected_items[0]` maps daemon -> state.
  The manager is READY only when all CORE daemons are `running`:
  wazuh-analysisd, wazuh-db, wazuh-remoted, wazuh-authd, wazuh-modulesd,
  wazuh-apid.
- These may legitimately be `stopped`/`failed` and must NOT block readiness:
  wazuh-agentlessd, wazuh-csyslogd, wazuh-integratord, wazuh-maild.
- `/manager/info` returns 200 even while daemons are restarting - it is NOT a
  readiness gate. Use /manager/status only.
- A manager restart takes minutes; daemons come up at different speeds, so
  poll /manager/status until the core set is running before relying on new
  rules.

## Search quirks

- The `search` param on list endpoints is literal text matching - a legal,
  reliable filter.
- Avoid `query_string`-style filters entirely: characters like `/`, `<`, `=`,
  `..` can 500 the indexer. Use deterministic bool clauses instead.