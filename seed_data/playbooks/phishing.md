# Playbook: Suspected Phishing Email

**Alert types:** email gateway flag, user-reported phishing, suspicious link click

## Triage steps
1. Pull the message headers: sender domain, SPF/DKIM/DMARC result, reply-to mismatch.
2. Check sender domain age and reputation (WHOIS + VirusTotal domain report).
3. If a link was clicked: check EDR for any process spawned in the browser
   right after click time (downloads, script execution).
4. If a credential entry page: check identity provider logs for a login from
   the reported user around/after the click time, especially from a new
   ASN/country.
5. Check if other users received the same sender/subject in the last 24h
   (mass-phishing vs targeted).

## Verdict criteria
- **False positive**: internal sender, passed SPF/DKIM/DMARC, known marketing
  or newsletter domain, no link click follow-through.
- **True positive - contain**: credential page + subsequent anomalous login,
  OR malicious attachment executed (EDR shows spawned process from
  Outlook/Chrome matching known loader behavior).
- **True positive - monitor**: link clicked but domain sinkholed/dead, or
  attachment did not execute (blocked by EDR). Still escalate to confirm no
  secondary vector.

## Escalate to L2 if
- Credentials confirmed entered AND anomalous login followed.
- Executive/privileged account targeted, regardless of outcome.
- More than 5 users received the same lure (mass campaign - needs comms + blocklist).
