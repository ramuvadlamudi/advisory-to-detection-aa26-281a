# Detection readiness: coverage and confidence

This is the presenter's proposed operational method, not a MITRE, ASD or Splunk standard. Use it to brief one advisory, not to
grade a SOC.

## The headline number

Detection readiness = validated hypotheses ÷ total relevant hypotheses × 100

A hypothesis is validated when its telemetry covers the whole attack surface and the detection passes a positive and a negative
test. In the lab: 3 of 7 = 43%. Report each behaviour in one of three states:

- **Available**: sufficient telemetry exists, and the detection is tested
- **Partial**: some evidence exists, but coverage is incomplete
- **Missing**: the required telemetry is unavailable

## Measure the outcome, not the activity

| Metric | What it tells you | Lab |
|---|---|---|
| Technique coverage | Which behaviours have detections | 7 of 7 have detection logic |
| Telemetry coverage | Whether the required logs exist | 3 full, 3 partial, 1 missing |
| Detection effectiveness | Whether the detection finds test activity | 16 of 17 detections fire on the simulated attack |
| False-positive rate | Whether legitimate activity creates noise | Approved lookalikes silent after tuning |
| Detection latency | How quickly the SOC identifies activity | Scheduled every 30 to 60 minutes |
| Investigation readiness | Whether analysts have context to respond | Owner and priority for every lab asset and user |

## The refinement: weights and partial credit

The headline counts partial coverage as zero and treats every behaviour as equally important. The refinement fixes both.

**Coverage: can we see it?** For each behaviour in scope, v is the share of its attack surface where telemetry and a detection
both exist (0 to 1). Weight w reflects the impact of missing it for this adversary: 3 reaches the objective (mail, credentials,
persistence), 2 enables it, 1 is a precursor.

Weighted coverage = Σ wᵢvᵢ / Σ wᵢ × 100

**Confidence: would it work?** The maturity state of each detection:

1. Telemetry available: the data is there, with the fields populated
2. Detection implemented: the logic is deployed and scheduled
3. Detection tested: positive and negative tests pass on representative data
4. Detection operationally effective: tuned, owned, wired to response, and proven in an exercise or a real case

**The denominator.** The behaviours you decide are relevant from the advisory: here, seven. Change the scope and the number
changes, so always state the denominator.

| Behaviour | w | v | Maturity | Evidence |
|---|---|---|---|---|
| Scanning | 1 | 1.0 | tested | Firewall covers every internet-facing address |
| Web enumeration | 1 | 1.0 | tested | IIS on both web servers |
| Exchange spraying | 2 | 1.0 | tested | All ten Exchange interfaces in IIS |
| SoftEther persistence | 3 | 0.5 | tested | Sysmon on Windows only; Linux installs invisible |
| Mail collection | 3 | 0.6 | tested | EWS fully; MailItemsAccessed on 30 of 120 mailboxes |
| Staging and exfiltration | 2 | 0.5 | tested | EDR files and firewall; no web proxy |
| DCSync | 3 | 0.0 | none | Rule deployed but blind: no 4662 events (no SACL) |

Unweighted: 3 of 7 behaviours fully covered and tested = 43%. It treats scanning and DCSync as equally important and partial
coverage as zero.

Weighted coverage: 8.3 / 15 = 55%. Confidence: 6 of 7 tested in the lab; none yet operationally effective.

Fastest gains: the replication audit SACL (DCSync from 0 to 1, +20 points), MailItemsAccessed for every mailbox, Sysmon for Linux.
