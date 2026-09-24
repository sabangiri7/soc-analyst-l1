# Wazuh logtest analysis workflow

How runtime verification of a new rule works, and the exact semantics of the
logtest API - ground truth for the `verify_rule_deployment` tool.

## Logtest session

- `POST /logtest` with a log line starts a session and returns a `token`.
  All samples tested against the SAME ruleset state (including newly uploaded
  rules after a restart).
- Subsequent samples are sent with `token=<session token>` to keep the same
  session - this is what makes frequency rules testable: the occurrence
  counter lives in the session.
- A fresh session (no token) is a clean slate. End sessions with
  `DELETE /logtest?token=...` when done.

## Response shape

The API answers with an `output` object containing the matched `rule`
(id, level, description, groups) and the matched `decoder` (name). An
unmatched sample returns a rule id of 0/empty. Treat the manager's answer as
the only source of truth when verifying.

## Frequency-rule verification (the important part)

When the rule under test uses `frequency` (an attribute, see wazuh-rules.md):

- With frequency=3, the rule fires only on the 3rd occurrence IN THE SAME
  SESSION. The first (frequency-1) samples will match the PARENT rule instead
  - that is expected and correct.
- Verification seeds one session, sends (frequency-1) baseline positives
  (expect parent rule), then the decisive positive (expect the new rule id).
  All of these share one token.
- The negatives run in their own fresh session (they must not contribute to
  the counter and must never fire the new rule).
- `verified=True` for a frequency rule means: one session, the threshold
  sample fired the new rule id, and no negative fired it. The per-sample
  positive pass ratio is expected to be 1/N - that is NOT a failure.

## Plain (non-frequency) rules

Each positive sample must fire the new rule id on its own; negatives must
fire something else (a different id, often the underlying base rule or the
generic event rule). No session threading is needed.

## Practical notes

- If a sample fires rule 5715 "sshd: authentication succeeded." that is the
  SUCCESS event - a positive sample firing it means the log line decodes as
  a success, not a failure.
- Rule 5760 "sshd: authentication failed." is the parent that frequency SSH
  rules count on (groups: authentication_failures).
- "no_decode" means the log line did not decode - the sample is useless for
  verification and should be replaced with a realistic line the decoder
  actually processes.