# The threat-to-detection playbook

Threat intelligence → adversary behaviour → detection hypotheses → evidence → validated detections → defensive action.

The method is vendor-independent. The session demonstrates it in Splunk; the steps work with any SIEM.

## 01 Understand the threat

- Read the advisory. Name the adversary, its objectives, its techniques and the affected technologies.
- Write each behaviour as one sentence, with the advisory text that supports it.
- Separate what the advisory says from what you infer (AA26-281A describes automation; it does not attribute AI use).

## 02 Map your exposure

- List the affected assets, vulnerabilities, identities, infrastructure and business services.
- Include the edge: VPNs, firewalls, web servers and remote-access devices. They often sit outside the SOC's richest telemetry.
- Report exposure in five states, not two:

| State | Means | Lab example |
|---|---|---|
| Vulnerable | A known weakness exists | GIT01, LEGACY01: known CVEs, internal only |
| Suspicious activity | Activity consistent with the threat, not proven | VPN01, FTP01: scanned by the actor's scanner |
| Confirmed malicious | Activity proven to be the adversary's | WS-0417: a disguised VPN with three signals |
| Confirmed compromise | The adversary achieved access or an objective | j.citizen's mailbox, read from outside |
| Unknown | No telemetry to decide | Linux servers; DCSync |

A vulnerable server is not proof of compromise. An indicator match is not proof of intrusion. Finding nothing is not proof you
are safe.

## 03 Establish visibility

- Discover what you actually have: indexes or tables, sources, fields and retention. Don't assume.
- For each hypothesis, name the telemetry it needs and whether it exists, with the fields populated, for long enough.
- State gaps as findings: "We cannot see X, because Y is missing; the fix is Z, owned by W."

## 04 Build and validate

- One hypothesis per behaviour: "A [entity] that [evidence], [in context], may indicate [behaviour]." (01-hypothesis-worksheet.md)
- Prepare three outcomes for every detection: a positive that fires, a negative that stays silent, and a visibility gap.
- Tune with exception registers (host plus path, with an owner and review date), not by weakening the logic.
- Use indicators and behaviour together. Enrich every indicator with its source, confidence, last-seen date and expiry.
- AI can draft hypotheses and queries. AI-generated SPL is not a validated detection until it passes the tests.

## 05 Operationalise

- Every detection carries an ID, behaviour, ATT&CK techniques, data and fields, logic, severity and risk, false positives, tests,
  owner, review date and response instructions (02-detection-catalogue.md, detections/*.yml).
- Score risk against entities so weak signals add up, and escalate with human approval for containment.
- Measure readiness as validated hypotheses over relevant hypotheses, and state the denominator (08-readiness-method.md).
- Revalidate on a schedule: data sources change under you.

## In Defence, plan for

- Air-gapped networks and local distribution of threat intelligence
- Data sovereignty, and locally hosted models for any AI step
- Delayed or limited telemetry
- Detection content deployed and versioned as code
- Human approval for every containment action

## Your first 48 hours

Take one recent advisory and operationalise at least one detection hypothesis with this playbook (10-exercise.md). The goal is to
start, and to make the gaps visible.
