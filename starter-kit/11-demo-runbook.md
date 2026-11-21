# Presenter runbook: From Advisory to Detection (AA26-281A)

The v7 deck (45 minutes of talk) tells the story as an incident investigation, with **no live demo**. Every Splunk view on stage is a screenshot of
the Integrity Tech Detections app and Enterprise Security on the lab instance; describe it as a guided, end-to-end investigation
walkthrough, and don't promise a live demo. This runbook covers what each screenshot shows, how to refresh the screenshots, and how to answer
questions. Every number on the screenshots is checked by `labctl.py validate` (31 saved reports) and `labctl.py backtest`
(18 detections).

Lab only. The data is synthetic: hosts, users and addresses are fictional (`lab.example`, 203.0.113.0/24, 198.51.100.0/24,
192.0.2.0/24). The exploit requests carry the shape of the public exploits but no working payload. Never point the lab at
production, and never exploit real systems.

## The shape of the talk

The audience should feel three things, in order:

| Part | Slides | Minutes | What they should feel |
|---|---|---|---|
| Concern | 2 to 13 | 17 | The adversary is real, patient and aimed at organisations like theirs; what telemetry it takes to see it |
| Discovery | 14 to 22 | 15.5 | An analyst can find this intrusion, step by step, with evidence |
| Confidence | 23 to 30 | 12 | How to avoid being the next victim, and how to run the same method on their next advisory, this week |

The slide notes add up to 44.5 minutes. Don't rush slides 3 to 10; spend the most time on 14 to 22; make slide 18 a real
show of hands and slide 21 the climax; finish on the 48-hour challenge (slide 29).

The opening question is the spine: "What if this adversary was already inside your environment? Could your SOC find them before
they take your data?" The storyline slide (21) answers it: partly, and late.

## What's on the lab

| Component | What it holds |
|---|---|
| `TA-aa26-281a-lab` 1.3.0 | The synthetic data and indexes (388,653 events), and saved reports "AA26 01" to "AA26 31" pinned to the scenario window |
| `integrity_tech_detections` 1.1.0 | 18 detections (17 behaviours plus the finding), macros, lookups, the catalogue, the readiness register, the response actions and controls, and 10 dashboards |
| Enterprise Security 8.5.1 | Risk data model and the analyst queue, holding two findings: j.citizen (200, 6 tactics) and a.lim (100, 3) |

## The investigation (slides 14 to 22, about 15 minutes)

| Slide | Clock | Screenshot | The analyst's question | Callouts | Detail slide |
|---|---|---|---|---|---|
| 14 | 00:00 | `itd_overview` | What does our environment already know? | 16 of 17 detection rules fired (17 behaviour rules covering 7 behaviours, plus 1 correlation finding); say the title's time is the replay clock; 2 entities over threshold; 43% ready ("would you brief your commander on that?") | Operationalise |
| 15 | 01:30 | `itd_exposure` (top) | Are we exposed, and would we see it? | 5 of 8 CVEs on our assets; NO LOGS; one source tried 7 techniques | Exploit attempts; Vulnerable is not exploited |
| 16 | 03:00 | `itd_recon` | Who scanned us, what did they try, did anyone get in? | Scanned then signed in; exploit sweep; the IIS and 4624 events for j.citizen at 11:58:07 | Password spraying; Reconnaissance |
| 17 | 05:30 | `itd_persistence` | Stolen password, or still inside? | conhost.exe is vpnbridge.exe; three signals; hourly tunnel | SoftEther ① to ③ |
| 18 | 07:30 | none | Your call: A block the IP, B ignore, C correlate then investigate, D isolate without approval | Show of hands; don't reveal | |
| 19 | 09:00 | none | The answer is C | Why not A, B, D (premature isolation can disrupt evidence collection; follow the IR process); what correlating found; then a person decides | SoftEther ③ |
| 20 | 10:00 | `itd_collection` | What did they take, and how do we know? | 2,400 EWS calls; the secret added at 22:10:37; seven mailboxes read, event by event | Mail collection |
| 21 | 11:30 | `itd_storyline` + `es_findings` | Six separate incidents, or one intrusion? | First signal 28 Sep 09:12, 9 days 22 hours before the advisory; 7 detections; DCSync can't be seen; one finding per entity | Correlate; Risk; analyst's view |
| 22 | 14:00 | `itd_response` (top) | What do we do, who owns it, who approves? | A workflow backed by editable lookups, not an automated response engine: 6 of 8 need approval; 2 visibility gaps; evidence on every row | |

Slide 13 (minimum telemetry) sets up the investigation: seven sources plus context, with the lab's gaps. Slide 24 (don't be next) turns the mitigations into this week, this month and this quarter. Slide 23 (defence by stage) is the same table as the bottom of the action centre, drawn natively. The detail section keeps the
readiness screenshot (`itd_readiness`) and the analyst queue with the investigate dashboard (`es_findings`, `itd_investigate`).

Not used on slides: `itd_detections`, `search_recon`, `search_softether`, `search_ews`, `search_dcsync`, `search_ai_draft`,
`search_spray`. Don't use `search_discovery`: the lab is a shared server, and that search lists other teams' indexes, which
contradicts "no Linux telemetry".

## The day before

1. Prove the lab still matches the slides:

   ```
   cd demo-lab
   export SPLUNK_MGMT=https://<lab-splunk>:8089 SPLUNK_USERNAME=<user> SPLUNK_PASSWORD=<password>
   python3 labctl.py validate     # expect 31/31
   python3 labctl.py backtest     # expect 18/18, run from the detection app
   ```

2. Open the PDF on the presentation laptop and check the screenshots are legible on the venue projector. Nothing on stage
   needs the network.
3. Check the QR code on slide 29 opens the session page on a phone.

## Refreshing the screenshots

Only needed if the lab, the dashboards or the dates change.

1. Rebuild and install the detection app:

   ```
   python3 build_detection_app.py      # writes integrity_tech_detections/ and dist/integrity_tech_detections.tgz
   SPLUNK_PASSWORD=... python3 upload_app.py https://<host>:8000 --app integrity_tech_detections --no-restart
   ```

2. Make sure ES has the findings: `python3 labctl.py findings`. It runs the behaviour-chain finding over the scenario window
   with its actions on, once, and skips if `index=notable` already holds it.
3. Set the capture user's time zone to Australia/Sydney and the theme to dark (**Preferences**), so times and colours match.
4. Capture (needs Playwright and Chrome):

   ```
   SPLUNK_WEB=https://<host>:8000 SPLUNK_USERNAME=<user> SPLUNK_PASSWORD=<password> python3 capture_screenshots.py
   ```

   This writes 17 PNGs, 3200 px wide, to `screenshots/` (all ten dashboards, the ES analyst queue and six searches). Pass view
   names to capture only some, for example `capture_screenshots.py itd_recon itd_exposure`. Check each one, then rebuild the
   deck (`python3 build_aa26_281a_deck_v7.py`) so the slides pick them up. If you move panels, check the callout positions on
   slides 14 to 22.

## Three outcomes for every detection

| Detection | Positive: fires | Negative: stays silent | Visibility gap |
|---|---|---|---|
| Password spraying | 203.0.113.47 sprays 64 accounts; j.citizen succeeds | Background failed logons in 24 days of data produce no other rows | Spraying through a VPN or IdP that does not log here |
| Reconnaissance | 203.0.113.47: external, all six ports, then signs in | 10.20.0.50, the approved internal scanner; 198.51.100.77, background | Edge devices send no logs of their own |
| Exploit attempts | 203.0.113.47: seven techniques against WEB01 | 10.20.0.50 (approved, four techniques); 198.51.100.77 (one probe) | ProFTPD, BIND and Pulse Secure exploits against the appliances themselves: no appliance logs |
| VPN persistence | WS-0417: renamed vpnbridge.exe, autostart service, SoftEther DNS | WS-0404: approved SoftEther in Program Files; WS-0433: Lenovo service | Linux servers: no endpoint telemetry |
| Exchange collection | j.citizen: 2,400 EWS calls in an hour; Project Mail Archiver reads 7 mailboxes | svc-crm: 160 calls every hour; the approved backup app | 90 of 120 mailboxes have no MailItemsAccessed audit |
| DCSync | n/a | n/a | No event 4662: the replication SACL is not set |

## Honest answers to likely questions

- **Is this live?** No. It's a guided, end-to-end investigation walkthrough in screenshots from the lab instance, running the app on synthetic data. You
  can install the same app and data from the session page and get the same numbers.
- **The CVEs are old. Why does this matter now?** Automation makes old exploits free to try; edge and legacy systems outlive
  their patches and often send no logs; and five of the eight were only added to CISA's KEV catalogue with this advisory, so
  exploitation is recent. Two of them (ProFTPD, BIND) can never appear in a web log: only inventory finds them.
- **Did the XSS requests really get a 200?** In the synthetic data, yes, on two pages: that's why "Web input handling" is on
  the action list as "to verify". Nothing was exploited; no real system was touched.
- **Does the advisory say these actors use AI?** No. It describes automation (MicroScan, EBurst, a botnet). The AI slide is the
  direction of travel, with Anthropic's November 2025 GTG-1002 report as the observed example.
- **Is the AI example real?** The searches are real and run on the lab; the first draft is a representative draft reconstructed
  for the talk, not captured from a specific model. Nothing AI runs live on stage; the MCP workflow and a local model are not
  demonstrated. The lab runs ES 8.5.1, so the ES 8.8 agents are not shown.
- **Does the action centre contain anything automatically?** No. It's a workflow: a lookup of ranked actions with owners and
  approvals, joined to live risk. Six of eight actions need a named approver; containment follows the IR process.
- **What's the minimum telemetry?** Firewall or flow logs; DNS queries; web server or WAF logs; Exchange IIS or IdP sign-ins;
  Sysmon or EDR with the original file name; Windows 4624, 4625, 7045 and 4662 with the replication SACL; Microsoft 365 audit
  with MailItemsAccessed on every mailbox. Plus context: assets, identities, vulnerabilities and approved tools.
- **Why were the risk events seeded?** The scheduled detections look at recent time and the lab data is historical, so
  `labctl.py seed` writes the scenario's risk events once per detection, each with its detection's name as the source.
- **Why is 203.0.113.47 not a finding?** It scores 90 across three tactics (the scan, the exploit attempts, the spray and
  the sign-in), just under the threshold of 100. Its activity reaches j.citizen because the same source then signed in as her.
- **Is the readiness metric a standard?** No. It is the presenter's proposed operational metric; always state the denominator.
- **16 of 17, or 43%?** Different questions. 16 of 17 detection rules fired in a synthetic replay: the logic works on data
  where we know the answer. 3 of 7 behaviours have full telemetry and validated coverage: whether we would see each behaviour
  in this environment. Only the second goes to the commander.
- **How do we avoid being compromised?** This week: hunt before you patch, patch or isolate the eight CVEs, enforce
  phishing-resistant MFA on every Exchange protocol, and turn on 4662 replication auditing and MailItemsAccessed. This month:
  shrink the internet surface, application control, govern app consent, filter look-alike domains. This quarter: retire
  end-of-life edge devices, tier admin accounts, filter egress, and re-test every quarter.
- **Does this need ES?** The hunts are plain SPL on CIM data models; risk aggregation and findings need ES.
- **Does it work on a disconnected network?** Yes. Everything ships as files (two app packages, CSV lookups, synthetic data);
  nothing calls out at run time. Updates come across through the normal import process and are tested on a lab copy first.
- **Can I see a real Defence system?** No: lab only, synthetic data.
