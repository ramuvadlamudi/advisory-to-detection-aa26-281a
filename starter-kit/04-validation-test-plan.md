# Validation test plan

Every detection gets three outcomes. Positive: it fires on controlled, harmless test activity. Negative: it stays quiet during normal work. Gap: it cannot be tested because telemetry is missing, and that is recorded, not hidden.

Use replayed synthetic logs (this lab), Splunk Attack Range or Atomic Red Team in an isolated lab. Never exploit real systems.

| ID | Positive test | Negative test | Lab result |
|---|---|---|---|
| AA26-D01 | Replay of the lab spray (64 mailboxes, 104 failures, 4 interfaces from 203.0.113.47) fires once | Monday-morning logon surge and the mobile gateway's routine failures stay silent | 1 rows |
| AA26-D02 | j.citizen: failed once from 203.0.113.47 during the spray, then 200s from the same address: fires once | Users who succeed from the gateway during a spray without first failing from it stay silent | 1 rows |
| AA26-D03 | 203.0.113.47 (41 hosts, 6 ports) fires; so does the internet background scanner, at low score | The internal vulnerability scanner 10.20.0.50 is excluded by the lookup | 3 rows |
| AA26-D04 | 203.0.113.47's 450 missing script paths in ten minutes fire once | Normal 404s from broken links stay silent | 1 rows |
| AA26-D17 | 203.0.113.47: 7 techniques (six advisory CVEs plus XSS), 15 requests, 2 answered: fires once | The approved scanner 10.20.0.50 (4 techniques) and a one-technique background probe stay silent | 1 rows |
| AA26-D05 | WS-0417: conhost.exe in C:\ProgramData\USOShared with original file name vpnbridge.exe fires once | WS-0404's approved SoftEther VPN Client in Program Files and every real conhost.exe in System32 stay silent | 1 rows |
| AA26-D06 | WS-0417 resolving vpn583920174.softether.net (18 lookups) fires once | Hosts without SoftEther never resolve these names | 1 rows |
| AA26-D07 | 'Console Host Service' running C:\ProgramData\USOShared\conhost.exe on WS-0417 fires | The approved SoftEther client's service (Program Files) stays silent | 2 rows |
| AA26-D08 | j.citizen: 2,400 EWS calls in one hour from 203.0.113.52 with no user agent (typical 3) fires once | svc-crm's steady 160 calls an hour stays silent | 1 rows |
| AA26-D09 | The rogue app owned by j.citizen reading 7 mailboxes fires once | The approved backup app reading every audited mailbox stays silent | 1 rows |
| AA26-D10 | j.citizen adding a secret to the rogue app the night before collection fires once | Scheduled rotation by the integration team, with a change record, is closed as expected | 1 rows |
| AA26-D11 | Cannot be tested in the lab: no 4662 events, because the SACL was never set. Record it as a gap | Domain controller computer accounts (ending in $) replicating normally stay silent | 0 rows |
| AA26-D12 | The staged files on WS-0417 fire | Ordinary image and script files with other names stay silent | 3 rows |
| AA26-D13 | Outlook > PowerShell > .vbe in %temp% > wscript on WS-0458 fires (2 rows) | PowerShell without a .vbe in temp stays silent | 2 rows |
| AA26-D14 | WS-0458 resolving fym.linkedinns.net (DOJ seizure list, high confidence) fires once | The j.citizen intrusion's new infrastructure matches nothing: the behavioural detections caught it | 1 rows |
| AA26-D15 | WS-0458 uploading 186 MB to 207.148.92.220 fires once (a low-confidence indicator that still matched) | No other lab host touches the list | 1 rows |
| AA26-D16 | WS-0417 (5 hours through the tunnel) and WS-0458 (186 MB FishHub upload): 6 rows | Workstations' normal download-heavy traffic stays silent | 6 rows |
| AA26-C01 | j.citizen (identity) 200 across six tactics, and a.lim 100 across three: 2 findings | WS-0417 (host, 80) and 203.0.113.47 (90) stay below 100 on their own | 2 rows |

Re-run after every change to data sources, add-ons or thresholds, and at each review date. `labctl.py backtest` automates it for the lab.