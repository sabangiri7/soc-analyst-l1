# MITRE ATT&CK mapping for web / SSH / network detections

Reference mapping used by detection work (rule development, gap analysis,
investigation annotations). Alerts carry technique ids in
`rule.mitre.id` (array) and `rule.details.mitre.id[]`.

## Techniques that map to the web rule groups

| Technique | Name                                  | Typical rule group | What an alert looks like |
|-----------|---------------------------------------|--------------------|--------------------------|
| T1190     | Exploit Public-Facing Application     | web / attack       | sqlmap, app exploit payloads in URI |
| T1505.003 | Web Shell                              | web / attack       | webshell uploads, cmd=.php execution |
| T1059     | Command and Scripting Interpreter     | web / attack       | RCE attempts in query params |
| T1189     | Drive-by Compromise                   | web                | exploit kit activity |
| T1068     | Exploitation for Privilege Escalation | attack             | privilege escalation payloads |

## Techniques relevant to SSH / authentication

| Technique | Name                               | Typical rule group          | What an alert looks like |
|-----------|------------------------------------|-----------------------------|--------------------------|
| T1110     | Brute Force                        | authentication_failures     | repeated failed logins (rule 5760 parent) |
| T1078     | Valid Accounts                    | authentication_failures     | many failures then a success |
| T1021.001 | Remote Services: SSH              | authentication_failures     | interactive login from odd source |
| T1110.001 | Brute Force: Password Guessing    | authentication_failures     | single-user password spray |

## Network-adjacent

| Technique | Name                            | Typical rule group | What an alert looks like |
|-----------|---------------------------------|--------------------|--------------------------|
| T1046     | Network Service Discovery       | attack             | masscan/nmap-style port sweeps |
| T1018     | Remote System Discovery         | attack             | repeated connections to many hosts |
| T1571     | Non-Standard Port               | attack             | services on unusual ports |

## Using the mapping

- When developing a rule for a detection gap, attach the most specific
  technique id to the rule (Wazuh encodes MITRE in `<mitre><id>T1110</id></mitre>`).
- When annotating an investigation, face OWASP-level detail (SQLi vs XSS)
  with the technique that describes the ATT&CK tactic, e.g. T1190 for
  exploit-front-door attacks.
- Rule groups are the reliable join key: `rule.groups` on the alert,
  `groups` in the ruleset. Coverage analysis buckets rules by these groups
  and by MITRE id.