---
name: mitre-mapping
description: ATT&CK technique mapping reference for web, SSH/auth, and network detections - rule MITRE tagging and investigation annotation.
version: 1.0.0
---
# MITRE ATT&CK mapping

Reference for attaching technique ids to rules and annotating investigations.
Alerts carry technique ids in `rule.mitre.id` (array) and
`rule.details.mitre.id[]`; Wazuh encodes MITRE in rules as
`<mitre><id>T1110</id></mitre>`.

## Web / attack detections

| Technique | Name | Typical group | What an alert looks like |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | web / attack | sqlmap, app exploit payloads in URI |
| T1505.003 | Web Shell | web / attack | webshell uploads, cmd=.php execution |
| T1059 | Command and Scripting Interpreter | web / attack | RCE attempts in query params |
| T1189 | Drive-by Compromise | web | exploit kit activity |
| T1068 | Exploitation for Privilege Escalation | attack | privilege escalation payloads |

## SSH / authentication

| Technique | Name | Typical group | What an alert looks like |
|---|---|---|---|
| T1110 | Brute Force | authentication_failures | repeated failed logins (rule 5760 parent) |
| T1078 | Valid Accounts | authentication_failures | many failures then a success |
| T1021.001 | Remote Services: SSH | authentication_failures | interactive login from odd source |
| T1110.001 | Brute Force: Password Guessing | authentication_failures | single-user password spray |

## Network-adjacent

| Technique | Name | Typical group | What an alert looks like |
|---|---|---|---|
| T1046 | Network Service Discovery | attack | masscan/nmap-style port sweeps |
| T1018 | Remote System Discovery | attack | repeated connections to many hosts |
| T1571 | Non-Standard Port | attack | services on unusual ports |

## Using the mapping

- **Rule development**: attach the most specific technique id for the
  behaviour. A detection gap analysis (see `analyze_detection_gaps`) can be
  fed straight into rule development with the technique pre-attached.
- **Investigation annotation**: face OWASP-level detail (SQLi vs XSS) with the
  technique that names the ATT&CK tactic, e.g. T1190 for exploit-front-door
  attacks, T1110.001 for a single-account password spray.
- **Coverage analysis**: `rule.groups` on alerts and `groups` in the ruleset
  are the reliable join key - bucket rules by group and MITRE id.
- When asked to map an alert, always confirm the rule's own MITRE field first
  and only fall back to the tables above when it is missing.