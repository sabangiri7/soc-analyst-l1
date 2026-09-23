# Playbook: Brute Force / Credential Stuffing

**Alert types:** repeated auth failures, impossible travel, new-country login

## Triage steps
1. Count failed attempts and source IP(s) - single IP hammering vs distributed
   (credential stuffing pattern, many IPs/ASNs, low attempts each).
2. Check if the account eventually succeeded. If yes, this is now an
   account-compromise investigation, not just brute force.
3. Check source IP reputation (known VPN/Tor exit, hosting provider ASN vs
   residential ISP).
4. Check if MFA was required and whether it was satisfied or bypassed
   (MFA fatigue pattern = many push prompts in short window).
5. Check if this account is a service account (no interactive login expected -
   any auth attempt is suspicious) vs a human user.

## Verdict criteria
- **False positive**: known scanner/pentest source IP (check allowlist),
  or misconfigured internal service retrying with stale credentials.
- **True positive - monitor**: failed attempts only, no success, source IP
  now blocked at perimeter. Log and close, note pattern for the lessons store.
- **True positive - contain**: successful auth following failures, especially
  with impossible travel or from a source IP with bad reputation. Recommend
  password reset + session revocation, escalate to L2 for scope (lateral
  movement check).

## Escalate to L2 if
- Successful login after failures (potential compromise).
- Service account or privileged/admin account involved.
- MFA fatigue pattern detected (signals active human attacker, not automated scan).
