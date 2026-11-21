# AA26-281A demo lab

Synthetic telemetry and a detection app for "From Advisory to Detection: Hunting Integrity Tech (AA26-281A) in Splunk". Every search and screenshot in the deck shows the result you get here. Hosts, users and internal addresses are fictional (`lab.example`, plus the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24). The indicator lookups hold the real AA26-281A domains and IPs from CISA's STIX file, plus the seven domains and the MicroScan server from the DOJ seizure of 8 Oct 2026. The FishHub part of the scenario uses two of those real indicators (`fym.linkedinns.net` and 207.148.92.220) so the sweeps have something to find; no traffic is ever sent to them.

**Lab only.** The app creates indexes, and `labctl.py load` adds them to the admin role's default search indexes, because data model searches read only those. The detection app installs 18 scheduled detections. Never install either on production.

## Run it

1. In Splunk Web, go to **Apps > Manage Apps > Install app from file**, upload `dist/TA-aa26-281a-lab.tgz`, and restart. The app bundles its data and indexes it on its own: about 390,000 events.
2. Install `dist/integrity_tech_detections.tgz` the same way. This is the Integrity Tech Detections app: the 18 detections, macros, indicator and approved lookups, the detection catalogue, the readiness register, the response actions and controls, and ten dashboards (overview, incident storyline, four hunts including exposure, investigate, the Defender action centre, readiness and the detection library).
3. Follow `DEMO_SEARCHES.md`. It covers seeding the risk events once, then every SPL search in demo order with its expected result. The searches are also saved reports, "AA26 01" to "AA26 31", pinned to the scenario window. `DEMO_RUNBOOK.md` is the presenter's script for the screenshot walkthrough: what each screenshot shows, pre-flight checks and how to recapture.

To change the dates, run `python3 generate_lab_data.py --day0 YYYY-MM-DD --hunt YYYY-MM-DDTHH:MM`. That rebuilds the data, the saved reports, the document and the package. On a local instance, `python3 labctl.py all` installs the app, waits for indexing, seeds the risk events, checks all 31 reports, backtests the 18 detections and raises the two ES findings. For a remote instance, install both packages through Splunk Web (or `SPLUNK_PASSWORD=... python3 upload_app.py https://<host>:8000`, adding `--app integrity_tech_detections` for the detection app) and set `SPLUNK_MGMT=https://<host>:8089`, then run `labctl.py load`, `seed`, `validate`, `backtest` and `findings`.

Splunk Cloud won't accept an app that monitors bundled files. There, upload the files in `TA-aa26-281a-lab/data/` with the index, sourcetype, source and host listed in `output/manifest.json`, through a forwarder or HEC. Splunk Web's upload page can't set `source`, and the Sysmon add-on depends on it.

Requirements on the Splunk side:
- Splunk Enterprise with Enterprise Security 8.x (for the Risk data model and the shipped ESCU detection).
- The Splunk Add-on for Microsoft Windows, the Splunk Add-on for Microsoft Office 365, and Splunk_SA_CIM. The Splunk Add-on for Sysmon is optional: without it, the app supplies the Sysmon CIM fields itself.
- ES Content Update (ESCU), for the `sysmon`, `wineventlog_security` and `wineventlog_system` macros.

## The scenario

The window runs from Monday 14 September to Thursday 8 October 2026, 09:00, in Sydney time. The advisory "lands" at the end of the window. Change the dates with `--day0` and `--hunt`.

| When (Sydney time) | What happens | Where it shows up |
|---|---|---|
| Day 0, 09:12 | 203.0.113.47 scans 41 public hosts on ports 21, 22, 53, 80, 443 and 1080 | `firewall` |
| Day 0, 09:20 | dirsearch-style burst: 450 PHP and ASP.NET 404s on WEB01 | `web` |
| Day 0, 09:41 | Exploit sweep against WEB01: Shellshock, Struts, Pulse Secure traversal, GitLab, ONLYOFFICE, Strapi and three XSS payloads (15 requests; two XSS pages answer 200) | `web` (`iis_web01_v3.log`) |
| Day 0, 11:40 | Spray: 64 mailboxes, 1–2 attempts each, across EWS, ActiveSync, Autodiscover and MAPI | `exchange`, 4625 on MAIL01 |
| Day 0, 11:58 | j.citizen's password works over EWS | `exchange`, 4624 type 8 |
| Day 0, 15:20 | live700_v1.exe drops DiagTrack.exe on WS-0417, which beacons hourly | `sysmon`, `dns` |
| Day 1, 02:10–02:15 | PowerShell fetches 001.gif and Include.png, copies 001.gif to conhost.exe (SoftEther vpnbridge.exe), installs an autostart service, then tunnels to vpn583920174.softether.net | `sysmon`, 7045, `dns`, `firewall` |
| Day 2, 07:58 | Reboot: the fake conhost.exe starts again | `sysmon` |
| Day 2, 10:41 | FishHub-style spear-phish on WS-0458 (a.lim): Outlook starts PowerShell, which saves a .vbe in %temp% after resolving fym.linkedinns.net; wscript.exe runs it; documents are listed, zipped and 186 MB is uploaded to 207.148.92.220 | `sysmon`, `dns`, `firewall` |
| Day 2, 22:10 | A secret is added to "Project Mail Archiver", an app j.citizen owns | `o365` |
| Day 3, 03:05 | 2,400 EWS calls as j.citizen from 203.0.113.52, with no user agent | `exchange` |
| Day 4, 01:00 | The app reads seven mailboxes | `o365` |

These gaps are deliberate, because the talk calls them out:
- There are no 4662 events, because replication auditing is off. That makes DCSync invisible.
- There's no Linux telemetry.
- MailItemsAccessed is audited for only 30 of the 120 mailboxes.

There's also realistic noise to tune out:
- An internal vulnerability scanner (10.20.0.50).
- An internet scanner (198.51.100.77).
- A phone stuck on an old password.
- An integration account that makes about 160 EWS calls an hour.
- An approved backup app that reads every audited mailbox each night.
- A legitimate `Css.js` file on WEB01.

## Risk

`seed_risk.spl` holds ten searches, one per detection, each using that detection's name as its source. They write the scenario's intermediate findings to `index=risk` with `| collect` and the marker `aa26_lab=1`. The risk slide then shows two findings: j.citizen at 200 across six ATT&CK tactics, and a.lim at 100 across three. They're seeded rather than produced by the scheduled detections, because those only look at recent time and the lab data is historical. Seeding is per detection: `labctl.py seed` skips any detection whose risk events are already in `index=risk`, so adding a detection seeds only the new one. Pass `--force` to write them all again. 203.0.113.47 ends at 90, just under the finding threshold.

## Detections

The detection app (`integrity_tech_detections`, built by `build_detection_app.py`) installs 17 behaviour detections and one finding, "AA26-281A - Integrity Tech behaviour chain - Rule", as Enterprise Security 8 detections. They are enabled and scheduled; each writes risk, and the finding fires at risk 100 across three tactics. `labctl.py backtest` runs each one over the scenario window with its actions off and checks the row count. `labctl.py findings` runs the finding once over the window with its actions on, so the ES analyst queue shows the two findings; it skips if they're already there. Section 4 of `DEMO_SEARCHES.md` lists them. Adjust the `aa26_iis` and `aa26_o365` macros and the `aa26_approved_scanners` lookup for your environment.

## Rehearsal tips

- Set your Splunk user time zone to Australia/Sydney so times match the slides.
- Open the saved reports ("AA26 01" to "AA26 31") in the Search app in the order listed in `DEMO_RUNBOOK.md`. They're pinned to the scenario window.
- Install the package once. Re-uploading it can make Splunk read a data file a second time; `labctl.py load` warns if any index holds more events than expected. To update an instance that already has the data, upload without the indexed files: `upload_app.py <url> --skip-data dns.log firewall.log iis_mail01.log iis_web01.log o365_management_activity.json windows_security.xml windows_sysmon.xml windows_system.xml windows_sysmon_v2.xml windows_system_v2.xml` (add `iis_web01_v3.log` once 1.3 is indexed).
- Version 1.2 adds two small files, `windows_sysmon_v2.xml` and `windows_system_v2.xml`: an approved SoftEther VPN Client on WS-0404, the false positive the SoftEther tuning removes. Their monitor stanzas set `crcSalt = <SOURCE>`, because they begin with the same bytes as the v1 files and Splunk would otherwise skip them. It also adds four context lookups (assets, identities, vulnerabilities, approved remote access) used by AA26 22 to 28. AA26 29 (scanner profile: direction, baseline and what the source did next) needs no new data.
- Version 1.3 adds `iis_web01_v3.log`: the actor's exploit sweep against WEB01 for the advisory's CVEs and XSS, the approved scanner's weekly checks, and a background probe. It has its own random seed and `crcSalt`, so the older files are byte-identical. It also adds `aa26_advisory_cves.csv` (the eight exploited CVEs, with the KEV flag), AA26 30 (exploit attempts by source), AA26 31 (the advisory's CVEs in our estate) and the detection "Exploit attempts for advisory CVEs".
- If only saved reports changed, push them over REST instead of re-uploading the app: `python3 push_searches.py`, then `labctl.py validate`.
- `labctl.py reset` empties the lab indexes. The seeded risk events stay until you delete them as a user with `can_delete`.
- After changing the detection app, run `python3 build_detection_app.py`, then `upload_app.py <url> --app integrity_tech_detections`.

## Screenshots

`capture_screenshots.py` logs in to Splunk Web with Playwright (Chrome, headless) and saves 17 PNGs to `screenshots/`: the ten dashboards, the ES analyst queue and six searches (pass view names to capture only some). Set `SPLUNK_WEB`, `SPLUNK_USERNAME` and `SPLUNK_PASSWORD`. Set the capture user's time zone to Australia/Sydney and the theme to dark first. The v6 deck builds its investigation slides from these files.
