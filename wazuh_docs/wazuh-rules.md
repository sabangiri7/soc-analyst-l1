# Wazuh rule authoring (local rules)

Factual reference for writing and deploying Wazuh alert rules. Ground truth
for the `develop_wazuh_rule` tool and for any rule work on a Wazuh manager.

## Rule numbering

- Rules with id >= 100000 are local rules (the manager's `local_rules.xml`).
  Use free ids in 100000..120000 for new local rules; check the existing
  ruleset first (GET /rules?q=id=..., or the tool's own pre-flight check).
- Never reuse an id that already exists in the core ruleset (id < 100000) -
  the upload will replace/conflict with the existing rule.
- Core SSH authentication failures are rule 5760 "sshd: authentication
  failed." (groups: authentication_failures). It is the canonical parent for
  SSH brute-force detection.

## Minimal valid rule XML

    <rule id="105563" level="10" frequency="3" timeframe="60">
      <if_matched_sid>5760</if_matched_sid>
      <description>Repeated SSH authentication failures</description>
    </rule>

- `id` and `level` are REQUIRED attributes. level is 0-15; anything above 15
  is rejected by the manager.
- `description` is required - the alert text analysts read.
- `frequency`, `timeframe`, and `divide` MUST be rule ATTRIBUTES. Putting them
  as child elements is rejected by Wazuh 4.14+ with "Invalid option
  'frequency' for rule".
- A frequency/divide rule MUST reference its parent rule by id with
  `<if_matched_sid>...</if_matched_sid>`. Using `<if_sid>` instead fails with
  "Invalid use of frequency/context options. Missing if_matched on rule".

## frequency / timeframe semantics

- `frequency="N"`: the rule fires once the parent rule (if_matched_sid) has
  matched N times within the window.
- `timeframe="S"`: the window in seconds. When omitted, Wazuh defaults to 60
  seconds.
- Verification consequence: with frequency=3/timeframe=60, the first few
  positive samples must NOT fire the new rule - it only fires on the Nth
  (threshold) occurrence. A verification run therefore seeds the session with
  (frequency-1) baseline positives before the decisive sample.

## Deployment flow (what actually happens on the manager)

1. Upload the merged `local_rules.xml` (PUT, octet-stream). The manager
   replies "Rule was successfully uploaded" when it accepted and validated
   the file.
2. Restart the manager (`restart`) - `local_rules.xml` is only applied on
   restart. A restart takes minutes and does not need `confirm` unless the
   tool requires it; treat daemon startup lag as normal.
3. Confirm the new rule with the logtest analysis workflow (see
   wazuh-logtest.md) - positive samples must fire the new rule id, negative
   samples must not.

See also: wazuh-api.md for endpoint facts, wazuh-logtest.md for verification.