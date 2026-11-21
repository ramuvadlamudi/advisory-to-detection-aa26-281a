# AA26-281A demo: synthetic data and SPL searches

Scenario window: **Mon 14 Sep 2026 00:00** to **Thu 08 Oct 2026 09:00**, Australia/Sydney (epoch 1789308000 to 1791410400). Day 0 is Mon 28 Sep 2026.

## 1. Load it

1. In Splunk Web: **Apps > Manage Apps > Install app from file**, choose `dist/TA-aa26-281a-lab.tgz`, then restart when prompted. The app creates the indexes, parses the data, maps it to CIM, adds the lookups and saved reports, and indexes the bundled data automatically (about 388,653 events, usually under five minutes). Install `dist/integrity_tech_detections.tgz` the same way: it holds the detections and dashboards.
2. Set your user time zone to Australia/Sydney (**Preferences > Time zone**) so times match the slides.
3. Run the 10 risk-seeding searches in section 2 **once**.
4. Open the saved reports **AA26 01** to **AA26 31** in the Search app. They are pinned to the scenario window, so you don't need to touch the time picker. If you paste the SPL below instead, set the time picker to the scenario window first.

Requires Splunk Enterprise with Enterprise Security 8.x, Splunk_SA_CIM, and the Splunk add-ons for Microsoft Windows, Sysmon and Microsoft Office 365 (the app maps Sysmon itself if that add-on is missing). Lab only: `labctl.py load` adds the lab indexes to the admin role's default search indexes, because data model searches read only those.

Check it landed (time picker: All time):

```
| tstats count where index IN (exchange, web, o365, wineventlog, sysmon, firewall, dns) by index sourcetype
```

| index | sourcetype | events |
|---|---|---|
| exchange | ms:iis:auto | 247,418 |
| web | ms:iis:auto | 14,269 |
| firewall | lab:firewall | 62,358 |
| dns | lab:dns | 46,987 |
| o365 | o365:management:activity | 3,730 |
| wineventlog | XmlWinEventLog | 2,159 |
| sysmon | XmlWinEventLog | 11,732 |

## 2. Seed the risk events (once)

Scheduled detections only look at recent time, so these 10 searches write the intermediate findings the lab's detections (section 4) would have raised over the scenario. Each search is one detection and uses that detection's name as its source. They need the `risk` index, which Enterprise Security provides. Running them twice doubles the scores; check first with `index=risk aa26_lab=1 | stats count`.

**1. AA26-281A - Scanning on advisory ports - Rule**

```
| makeresults | eval _time=1790550723, risk_object="203.0.113.47", risk_object_type="system", risk_score=10, risk_message="203.0.113.47 scanned 41 hosts on the AA26-281A ports; the same source later authenticated as j.citizen", threat_object="203.0.113.47", threat_object_type="ip_address", search_name="AA26-281A - Scanning on advisory ports - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1595.002\"], \"mitre_attack.mitre_technique_id\": [\"T1595.002\"], \"mitre_attack.mitre_tactic_id\": [\"TA0043\"], \"mitre_attack.mitre_tactic\": [\"reconnaissance\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" | append [ | makeresults | eval _time=1790550723, risk_object="j.citizen", risk_object_type="user", risk_score=10, risk_message="203.0.113.47 scanned 41 hosts on the AA26-281A ports; the same source later authenticated as j.citizen", threat_object="203.0.113.47", threat_object_type="ip_address", search_name="AA26-281A - Scanning on advisory ports - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1595.002\"], \"mitre_attack.mitre_technique_id\": [\"T1595.002\"], \"mitre_attack.mitre_tactic_id\": [\"TA0043\"], \"mitre_attack.mitre_tactic\": [\"reconnaissance\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" ] | fields - _raw | collect index=risk source="AA26-281A - Scanning on advisory ports - Rule" marker="aa26_lab=1"
```

**2. AA26-281A - Exploit attempts for advisory CVEs - Rule**

```
| makeresults | eval _time=1790552470, risk_object="203.0.113.47", risk_object_type="system", risk_score=20, risk_message="203.0.113.47 tried 6 of the advisory's CVEs and XSS payloads against WEB01", threat_object="203.0.113.47", threat_object_type="ip_address", search_name="AA26-281A - Exploit attempts for advisory CVEs - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1190\"], \"mitre_attack.mitre_technique_id\": [\"T1190\"], \"mitre_attack.mitre_tactic_id\": [\"TA0001\"], \"mitre_attack.mitre_tactic\": [\"initial-access\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" | fields - _raw | collect index=risk source="AA26-281A - Exploit attempts for advisory CVEs - Rule" marker="aa26_lab=1"
```

**3. AA26-281A - Exchange password spray - Rule**

```
| makeresults | eval _time=1790559602, risk_object="203.0.113.47", risk_object_type="system", risk_score=20, risk_message="203.0.113.47 sprayed 64 mailboxes across 4 Exchange interfaces", threat_object="203.0.113.47", threat_object_type="ip_address", search_name="AA26-281A - Exchange password spray - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1110.003\"], \"mitre_attack.mitre_technique_id\": [\"T1110.003\"], \"mitre_attack.mitre_tactic_id\": [\"TA0006\"], \"mitre_attack.mitre_tactic\": [\"credential-access\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" | append [ | makeresults | eval _time=1790559602, risk_object="j.citizen", risk_object_type="user", risk_score=20, risk_message="203.0.113.47 sprayed 64 mailboxes across 4 Exchange interfaces", threat_object="203.0.113.47", threat_object_type="ip_address", search_name="AA26-281A - Exchange password spray - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1110.003\"], \"mitre_attack.mitre_technique_id\": [\"T1110.003\"], \"mitre_attack.mitre_tactic_id\": [\"TA0006\"], \"mitre_attack.mitre_tactic\": [\"credential-access\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" ] | fields - _raw | collect index=risk source="AA26-281A - Exchange password spray - Rule" marker="aa26_lab=1"
```

**4. AA26-281A - Spray source authenticated - Rule**

```
| makeresults | eval _time=1790560687, risk_object="203.0.113.47", risk_object_type="system", risk_score=40, risk_message="j.citizen authenticated over EWS from spray source 203.0.113.47", threat_object="203.0.113.47", threat_object_type="ip_address", search_name="AA26-281A - Spray source authenticated - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1078\"], \"mitre_attack.mitre_technique_id\": [\"T1078\"], \"mitre_attack.mitre_tactic_id\": [\"TA0001\"], \"mitre_attack.mitre_tactic\": [\"initial-access\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" | append [ | makeresults | eval _time=1790560687, risk_object="j.citizen", risk_object_type="user", risk_score=40, risk_message="j.citizen authenticated over EWS from spray source 203.0.113.47", threat_object="203.0.113.47", threat_object_type="ip_address", search_name="AA26-281A - Spray source authenticated - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1078\"], \"mitre_attack.mitre_technique_id\": [\"T1078\"], \"mitre_attack.mitre_tactic_id\": [\"TA0001\"], \"mitre_attack.mitre_tactic\": [\"initial-access\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" ] | fields - _raw | collect index=risk source="AA26-281A - Spray source authenticated - Rule" marker="aa26_lab=1"
```

**5. AA26-281A - SoftEther masquerading as Windows binary - Rule**

```
| makeresults | eval _time=1790612042, risk_object="WS-0417", risk_object_type="system", risk_score=60, risk_message="conhost.exe on WS-0417 has OriginalFileName vpnbridge.exe and runs as an autostart service; WS-0417 is assigned to j.citizen", threat_object="C:\\ProgramData\\USOShared\\conhost.exe", threat_object_type="process", search_name="AA26-281A - SoftEther masquerading as Windows binary - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1133\"], \"mitre_attack.mitre_technique_id\": [\"T1133\"], \"mitre_attack.mitre_tactic_id\": [\"TA0003\"], \"mitre_attack.mitre_tactic\": [\"persistence\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" | append [ | makeresults | eval _time=1790612042, risk_object="j.citizen", risk_object_type="user", risk_score=60, risk_message="conhost.exe on WS-0417 has OriginalFileName vpnbridge.exe and runs as an autostart service; WS-0417 is assigned to j.citizen", threat_object="C:\\ProgramData\\USOShared\\conhost.exe", threat_object_type="process", search_name="AA26-281A - SoftEther masquerading as Windows binary - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1133\"], \"mitre_attack.mitre_technique_id\": [\"T1133\"], \"mitre_attack.mitre_tactic_id\": [\"TA0003\"], \"mitre_attack.mitre_tactic\": [\"persistence\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" ] | fields - _raw | collect index=risk source="AA26-281A - SoftEther masquerading as Windows binary - Rule" marker="aa26_lab=1"
```

**6. AA26-281A - SoftEther dynamic DNS - Rule**

```
| makeresults | eval _time=1790612100, risk_object="WS-0417", risk_object_type="system", risk_score=20, risk_message="WS-0417 resolved vpn583920174.softether.net and holds a tunnel to 203.0.113.88:443", threat_object="vpn583920174.softether.net", threat_object_type="domain", search_name="AA26-281A - SoftEther dynamic DNS - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1572\"], \"mitre_attack.mitre_technique_id\": [\"T1572\"], \"mitre_attack.mitre_tactic_id\": [\"TA0011\"], \"mitre_attack.mitre_tactic\": [\"command-and-control\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" | append [ | makeresults | eval _time=1790612100, risk_object="j.citizen", risk_object_type="user", risk_score=20, risk_message="WS-0417 resolved vpn583920174.softether.net and holds a tunnel to 203.0.113.88:443", threat_object="vpn583920174.softether.net", threat_object_type="domain", search_name="AA26-281A - SoftEther dynamic DNS - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1572\"], \"mitre_attack.mitre_technique_id\": [\"T1572\"], \"mitre_attack.mitre_tactic_id\": [\"TA0011\"], \"mitre_attack.mitre_tactic\": [\"command-and-control\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" ] | fields - _raw | collect index=risk source="AA26-281A - SoftEther dynamic DNS - Rule" marker="aa26_lab=1"
```

**7. AA26-281A - EWS volume far above normal - Rule**

```
| makeresults | eval _time=1790789400, risk_object="j.citizen", risk_object_type="user", risk_score=50, risk_message="2,400 EWS calls as j.citizen in one hour from 203.0.113.52 with no user agent", threat_object="203.0.113.52", threat_object_type="ip_address", search_name="AA26-281A - EWS volume far above normal - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1114.002\"], \"mitre_attack.mitre_technique_id\": [\"T1114.002\"], \"mitre_attack.mitre_tactic_id\": [\"TA0009\"], \"mitre_attack.mitre_tactic\": [\"collection\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" | fields - _raw | collect index=risk source="AA26-281A - EWS volume far above normal - Rule" marker="aa26_lab=1"
```

**8. AA26-281A - FishHub-style script stager - Rule**

```
| makeresults | eval _time=1790728872, risk_object="WS-0458", risk_object_type="system", risk_score=40, risk_message="PowerShell started from Outlook on WS-0458 downloaded a .vbe into %temp% and wscript.exe ran it; WS-0458 is assigned to a.lim", threat_object="shnmpmbxwylismvb.vbe", threat_object_type="file_name", search_name="AA26-281A - FishHub-style script stager - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1059.005\"], \"mitre_attack.mitre_technique_id\": [\"T1059.005\"], \"mitre_attack.mitre_tactic_id\": [\"TA0002\"], \"mitre_attack.mitre_tactic\": [\"execution\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" | append [ | makeresults | eval _time=1790728872, risk_object="a.lim", risk_object_type="user", risk_score=40, risk_message="PowerShell started from Outlook on WS-0458 downloaded a .vbe into %temp% and wscript.exe ran it; WS-0458 is assigned to a.lim", threat_object="shnmpmbxwylismvb.vbe", threat_object_type="file_name", search_name="AA26-281A - FishHub-style script stager - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1059.005\"], \"mitre_attack.mitre_technique_id\": [\"T1059.005\"], \"mitre_attack.mitre_tactic_id\": [\"TA0002\"], \"mitre_attack.mitre_tactic\": [\"execution\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" ] | fields - _raw | collect index=risk source="AA26-281A - FishHub-style script stager - Rule" marker="aa26_lab=1"
```

**9. AA26-281A - Known-bad domain resolved - Rule**

```
| makeresults | eval _time=1790728868, risk_object="a.lim", risk_object_type="user", risk_score=30, risk_message="WS-0458 (a.lim) resolved fym.linkedinns.net, a FishHub domain seized by the FBI on 8 Oct 2026", threat_object="fym.linkedinns.net", threat_object_type="domain", search_name="AA26-281A - Known-bad domain resolved - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1105\"], \"mitre_attack.mitre_technique_id\": [\"T1105\"], \"mitre_attack.mitre_tactic_id\": [\"TA0011\"], \"mitre_attack.mitre_tactic\": [\"command-and-control\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" | fields - _raw | collect index=risk source="AA26-281A - Known-bad domain resolved - Rule" marker="aa26_lab=1"
```

**10. AA26-281A - Connection to known-bad IP - Rule**

```
| makeresults | eval _time=1790728926, risk_object="a.lim", risk_object_type="user", risk_score=30, risk_message="WS-0458 (a.lim) uploaded 186 MB to 207.148.92.220, the FishHub collection server named in the seizure affidavit", threat_object="207.148.92.220", threat_object_type="ip_address", search_name="AA26-281A - Connection to known-bad IP - Rule", savedsearch_description="AA26-281A demo lab finding", annotations="{\"mitre_attack\": [\"T1041\"], \"mitre_attack.mitre_technique_id\": [\"T1041\"], \"mitre_attack.mitre_tactic_id\": [\"TA0010\"], \"mitre_attack.mitre_tactic\": [\"exfiltration\"], \"analytic_story\": [\"AA26-281A Integrity Tech\"]}" | fields - _raw | collect index=risk source="AA26-281A - Connection to known-bad IP - Rule" marker="aa26_lab=1"
```

## 3. The searches, in demo order

### AA26 01 - Telemetry discovery (Act 2)

What data do we have, and how far back?

```
| tstats count min(_time) as first max(_time) as last
    where index=* by index sourcetype
| eval days_retained=round((last-first)/86400)
| sort - count
```

**Expected:** Your instance's other indexes appear too. The lab rows match the table in section 1. Point out that there is no 4662 data and no Linux source.

### AA26 02 - Are the fields we need populated (Act 2)

Are the fields we need populated?

```
index=exchange sourcetype=ms:iis:auto
| fieldsummary
| search field IN (c_ip cs_username cs_uri_stem
                   sc_status cs_User_Agent)
| table field count distinct_count
```

**Expected:** All five fields populated across hundreds of thousands of events.

### AA26 03 - Detection 1 - Exchange password spray (Act 3)

Detection 1: password spraying across Exchange.

```
index=exchange sourcetype=ms:iis:auto
    cs_uri_stem IN ("/EWS/*","/owa/*","/ecp/*","/oab/*",
      "/mapi/*","/rpc/*","/autodiscover/*","/powershell*",
      "/Microsoft-Server-ActiveSync*","/api/*")
| eval interface=lower(mvindex(split(cs_uri_stem,"/"),1))
| bin _time span=30m
| stats count(eval(sc_status=401)) as fails
    count(eval(sc_status=200)) as wins values(interface) as ifs
    by _time c_ip cs_username
| eventstats sum(fails) as failures dc(ifs) as interfaces
    dc(eval(if(fails>0,cs_username,null()))) as users by _time c_ip
| where users>=10 AND failures/users<=3
| stats max(failures) as failures max(users) as users
    max(interfaces) as interfaces
    values(eval(if(fails>0 AND wins>0,cs_username,null()))) as ok
    by _time c_ip
| eval verdict=if(isnotnull(ok),"SPRAY + SUCCESS","SPRAY")
```

**Expected:** Remember the name j.citizen. 'ok' lists only accounts the source failed against and then got into, in the same window.

| _time | c_ip | failures | users | interfaces | ok | verdict |
|---|---|---|---|---|---|---|
| 2026-09-28 11:30 | 203.0.113.47 | 104 | 64 | 4 | j.citizen | SPRAY + SUCCESS |

### AA26 04 - Detection 2 - Network scanning (Act 3)

Detection 2: scanning on the advisory's ports.

```
| tstats dc(All_Traffic.dest) as hosts
    dc(All_Traffic.dest_port) as ports
    from datamodel=Network_Traffic
    where All_Traffic.dest_port IN (21,22,53,80,443,1080)
    by All_Traffic.src _time span=1h
| where hosts>=25
| sort - hosts
```

**Expected:** 10.20.0.50 is the internal vulnerability scanner: allow-list it. 198.51.100.77 is internet background noise. 203.0.113.47 is the actor: 41 hosts, all six advisory ports.

| _time | src | hosts | ports |
|---|---|---|---|
| 2026-09-20 01:00 | 10.20.0.50 | 100 | 5 |
| 2026-09-20 02:00 | 10.20.0.50 | 100 | 5 |
| 2026-09-27 01:00 | 10.20.0.50 | 100 | 5 |
| 2026-09-27 02:00 | 10.20.0.50 | 100 | 5 |
| 2026-10-04 01:00 | 10.20.0.50 | 100 | 5 |
| 2026-10-04 03:00 | 10.20.0.50 | 100 | 5 |
| 2026-09-28 09:00 | 203.0.113.47 | 41 | 6 |
| 2026-09-19 14:00 | 198.51.100.77 | 30 | 2 |
| 2026-10-03 05:00 | 198.51.100.77 | 30 | 2 |

### AA26 05 - Detection 2 - Web enumeration (Act 3)

Detection 2: dirsearch-style web enumeration.

```
| tstats count dc(Web.uri_path) as paths
    from datamodel=Web
    where Web.status=404
      (Web.uri_path="*.php" OR Web.uri_path="*.asp*")
    by Web.src Web.http_user_agent _time span=10m
| where paths>=200
```

**Expected:** Same source as the scan, ten minutes later.

| _time | src | http_user_agent | paths |
|---|---|---|---|
| 2026-09-28 09:20 | 203.0.113.47 | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 | 450 |

### AA26 06 - Detection 3 - SoftEther process (Act 3)

Detection 3: a VPN bridge pretending to be Windows.

```
| tstats count min(_time) as first_seen
    values(Processes.process_path) as path
    values(Processes.parent_process_name) as parent
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("conhost.exe","dllhost.exe")
      NOT Processes.process_path IN ("C:\\Windows\\System32\\*",
                                     "C:\\Windows\\SysWOW64\\*"))
      OR Processes.original_file_name IN ("vpnclient*","vpnbridge*")
    by Processes.dest Processes.process_name
       Processes.original_file_name Processes.process_hash
| convert ctime(first_seen)
```

**Expected:** The attacker's copy on WS-0417 started twice: at install (Day 1) and after a reboot (Day 2). WS-0404 is the IT team's approved SoftEther VPN Client in Program Files: the false positive that AA26 23 tunes out.

| dest | process_name | original_file_name | count | first_seen | path | parent |
|---|---|---|---|---|---|---|
| WS-0417.lab.example | conhost.exe | vpnbridge.exe | 2 | 2026-09-29 02:14 | C:\ProgramData\USOShared\conhost.exe | services.exe |
| WS-0404.lab.example | vpnclient_x64.exe | vpnclient_x64.exe | 15 | 2026-09-18 07:45 | C:\Program Files\SoftEther VPN Client\vpnclient_x64.exe | services.exe |

### AA26 07 - Detection 3 - SoftEther DNS (Act 3)

Detection 3: SoftEther dynamic DNS.

```
| tstats count from datamodel=Network_Resolution
    where DNS.query IN ("*.softether.net","*.vpnazure.net")
    by DNS.src DNS.query
```

**Expected:** 10.20.4.17 is WS-0417.

| src | query | count |
|---|---|---|
| 10.20.4.17 | vpn583920174.softether.net | 18 |

### AA26 08 - Shipped ES detection - SoftEther masquerading (Act 3)

The shipped ES detection, run ad hoc.

```
`sysmon` EventID=1 process IN ("*conhost.exe*","*dllhost.exe*")
    (Company="*SoftEther*" OR OriginalFileName="vpnbridge*.exe")
| stats count min(_time) as firstTime
    by dest process original_file_name Company parent_process_name user
| convert ctime(firstTime)
```

**Expected:** This is the search behind ESCU's 'Windows SoftEther VPN Masquerading as Legitimate Binary'. It is scheduled over the last hour, so run it ad hoc over historical data.

| dest | count |
|---|---|
| WS-0417.lab.example | 2 |

### AA26 09 - Detection 4 - EWS volume (Act 3)

Detection 4: EWS volume far above the user's normal.

```
index=exchange sourcetype=ms:iis:auto sc_status=200
    cs_uri_stem="/EWS/Exchange.asmx"
| bin _time span=1h
| stats count as calls values(cs_User_Agent) as agents
    by _time cs_username c_ip
| eventstats median(calls) as typical count as active_hours
    by cs_username
| where active_hours>=24 AND calls>=500 AND calls>=10*typical
```

**Expected:** svc-crm makes about 160 EWS calls every hour and never alerts: the per-user baseline is doing its job. Users with fewer than 24 active hours are skipped, because a median of two or three hours is not a baseline.

| _time | cs_username | c_ip | calls | typical | agents |
|---|---|---|---|---|---|
| 2026-10-01 03:00 | j.citizen | 203.0.113.52 | 2400 | 3.0 | - |

### AA26 10 - Detection 4 - Unapproved app reading mailboxes (Act 3)

Detection 4: unapproved app reading many mailboxes.

```
index=o365 Operation=MailItemsAccessed
| stats dc(MailboxOwnerUPN) as mailboxes count by AppId
| lookup approved_mail_apps AppId OUTPUT owner
| where mailboxes>=5 AND isnull(owner)
```

**Expected:** 'Project Mail Archiver', owned by j.citizen, reading from 203.0.113.52. The backup app reads every audited mailbox nightly but is approved. Only 30 of 120 mailboxes are audited: the 'partial' in Act 2.

| AppId | mailboxes | count |
|---|---|---|
| 5c1e7a42-93d8-4f0b-b2a6-0e4d8f17c3a9 | 7 | 7 |

### AA26 11 - Detection 4 - New app secrets and consents (Act 3)

Detection 4: new app secrets and consents.

```
index=o365 Operation IN ("Add service principal credentials*",
    "*Certificates and secrets*","Consent to application*")
| table _time UserId Operation ObjectId
```

**Expected:** The secret was added the night before the app read the mail.

| _time | UserId | Operation | ObjectId |
|---|---|---|---|
| 2026-09-30 22:10 | j.citizen@lab.example | Add service principal credentials. | 5c1e7a42-93d8-4f0b-b2a6-0e4d8f17c3a9 |

### AA26 12 - Detection 5 - DCSync (Act 3)

Detection 5: DCSync.

```
`wineventlog_security` EventCode=4662 AccessMask=0x100
    Properties IN (
      "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*",
      "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*",
      "*89e95b76-444d-4c62-991a-0facbeda640c*")
    NOT SubjectUserName="*$"
| stats count min(_time) as first
    by SubjectUserName Computer
```

**Expected:** Zero events, because the replication audit SACL was never set. The gap from Act 2, now proven.

_No results. That is the expected outcome._

### AA26 13 - Detection 5 - Staging file names (Appendix)

Detection 5: the advisory's decoy file names.

```
| tstats count from datamodel=Endpoint.Filesystem
    where Filesystem.file_name IN ("001.gif","Css.js",
      "M2k*.js","Include.png","All_scanner_v*.pl.gz",
      ".sess.zip")
    by Filesystem.dest Filesystem.file_path
       Filesystem.file_name
```

**Expected:** WEB01's Css.js is a legitimate deployment: filter by path and host role.

| dest | file_path | file_name |
|---|---|---|
| WEB01.lab.example | C:\inetpub\wwwroot\assets\Css.js | Css.js |
| WS-0417.lab.example | C:\ProgramData\USOShared\001.gif | 001.gif |
| WS-0417.lab.example | C:\ProgramData\USOShared\Include.png | Include.png |

### AA26 14 - Step 4 - Risk (Act 4)

Step 4: six quiet signals, one loud finding.

```
| tstats sum(All_Risk.calculated_risk_score) as risk
    dc(All_Risk.annotations.mitre_attack.mitre_tactic_id) as tactics
    from datamodel=Risk.All_Risk
    by All_Risk.risk_object All_Risk.risk_object_type
| where risk>=100 AND tactics>=3
```

**Expected:** Two findings: j.citizen (the advisory's Exchange-to-SoftEther chain) and a.lim (the FishHub chain from the seizure affidavit). Without the threshold: j.citizen 200 (6 tactics); a.lim 100 (3 tactics); 203.0.113.47 90 (3 tactics); WS-0417 80 (2 tactics); WS-0458 40 (1 tactics).

| risk_object | risk | tactics | detections |
|---|---|---|---|
| j.citizen | 200 | 6 | 6 |
| a.lim | 100 | 3 | 3 |

### AA26 15 - A1 - CIM Authentication spray (Appendix)

Spraying seen in directory authentication.

```
| tstats dc(Authentication.user) as users
    count as failures
    from datamodel=Authentication
    where Authentication.action=failure
    by Authentication.src _time span=30m
| where users>=10 AND failures/users<=3
```

**Expected:** The same spray in the 4625 events, but the source is MAIL01, not 203.0.113.47: for Exchange logons the Windows add-on maps CIM src to the workstation name, which is the Exchange server itself. The attacker's address is only in IpAddress. That is why the IIS log is the better source for spray detection.

| _time | src | users | failures |
|---|---|---|---|
| 2026-09-28 11:30 | MAIL01 | 64 | 104 |

### AA26 16 - A2 - New services outside system paths (Act 3)

New autostart services outside system paths.

```
`wineventlog_system` EventCode=7045
    NOT ImagePath IN ("*\\Windows\\System32\\*","*\\Program Files*")
| table _time Computer ServiceName ImagePath StartType
```

**Expected:** The Lenovo service is benign. 'Console Host Service' is SoftEther.

| _time | Computer | ServiceName | ImagePath |
|---|---|---|---|
| 2026-09-22 11:02 | WS-0433.lab.example | Lenovo Vantage Service | C:\ProgramData\Lenovo\Vantage\Addins\LenovoVantageService.exe |
| 2026-09-29 02:13 | WS-0417.lab.example | Console Host Service | C:\ProgramData\USOShared\conhost.exe /service |

### AA26 17 - A3 - Upload-heavy hosts (Appendix)

Hours in which a host uploads far more than it downloads.

```
| tstats sum(All_Traffic.bytes_out) as bytes_out
    sum(All_Traffic.bytes_in) as bytes_in
    from datamodel=Network_Traffic
    by All_Traffic.src _time span=1h
| where bytes_out > 5*bytes_in AND bytes_out > 100000000
| eval MB_out=round(bytes_out/1e6)
```

**Expected:** 10.20.4.17 (WS-0417) through the SoftEther tunnel, and 10.20.4.58 (WS-0458) uploading the FishHub archive.

| _time | src | MB_out |
|---|---|---|
| 2026-09-29 03:00 | 10.20.4.17 | 226 |
| 2026-09-29 04:00 | 10.20.4.17 | 263 |
| 2026-09-30 10:00 | 10.20.4.58 | 186 |
| 2026-09-30 23:00 | 10.20.4.17 | 229 |
| 2026-10-01 00:00 | 10.20.4.17 | 247 |
| 2026-10-01 01:00 | 10.20.4.17 | 227 |

### AA26 18 - A4 - Indicator sweep (Appendix)

Sweep the advisory's domains across retention.

```
| tstats count from datamodel=Network_Resolution
    by DNS.src DNS.query
| lookup aa26_281a_domains domain AS DNS.query
    OUTPUT ioc_source confidence last_seen expires
| where isnotnull(ioc_source) AND confidence!="invalid"
    AND strptime(expires,"%Y-%m-%d")>now()
```

**Expected:** One hit, and it is not from the advisory. The j.citizen intrusion used new infrastructure (vpn583920174.softether.net, update.diagtrack-cloud.example), so the advisory's 227 domains never appear. 10.20.4.58 (WS-0458) resolved fym.linkedinns.net, one of the FishHub domains the FBI seized on 8 Oct 2026; six of the seven seized domains are not in the advisory's indicator list. Fresh indicators help; old ones rarely do; the behavioural searches found both intrusions anyway.

| src | query | ioc_source |
|---|---|---|
| 10.20.4.58 | fym.linkedinns.net | DOJ seizure warrant, 8 Oct 2026 |

### AA26 19 - Pivot - What happened on WS-0417 (Act 5)

Pivot: how did SoftEther get onto WS-0417?

```
`sysmon` Computer="WS-0417*" EventCode IN (1,11)
| eval detail=coalesce(TargetFilename, OriginalFileName)
| table _time EventCode Image ParentImage detail CommandLine
| sort _time
```

**Expected:** Saved report is pinned to Day 0 15:00 to Day 1 02:20. live700_v1.exe (the advisory's fake-login payload) drops DiagTrack.exe, which later launches the PowerShell that fetches SoftEther.

| _time | EventCode | Image | ParentImage | detail |
|---|---|---|---|---|
| 2026-09-28 15:20:11 | 11 | msedge.exe |  | C:\Users\j.citizen\Downloads\live700_v1.exe |
| 2026-09-28 15:20:30 | 1 | live700_v1.exe | explorer.exe | live700_v1.exe |
| 2026-09-28 15:20:32 | 11 | live700_v1.exe |  | C:\Users\Public\Libraries\DiagTrack.exe |
| 2026-09-28 15:20:34 | 1 | DiagTrack.exe | live700_v1.exe | DiagTrack.exe |
| 2026-09-29 02:10:51 | 1 | powershell.exe | DiagTrack.exe | PowerShell.EXE |
| 2026-09-29 02:11:02 | 11 | powershell.exe |  | C:\ProgramData\USOShared\001.gif |
| 2026-09-29 02:11:40 | 11 | powershell.exe |  | C:\ProgramData\USOShared\Include.png |
| 2026-09-29 02:12:29 | 1 | cmd.exe | powershell.exe | Cmd.Exe |
| 2026-09-29 02:12:30 | 11 | cmd.exe |  | C:\ProgramData\USOShared\conhost.exe |
| 2026-09-29 02:14:02 | 1 | conhost.exe | services.exe | vpnbridge.exe |

### AA26 20 - Detection 5 - FishHub-style stager (Appendix)

Detection 5: a script stager dropped into %temp%.

```
| tstats count min(_time) as first_seen
    values(Processes.process) as command
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("wscript.exe",
      "cscript.exe","powershell.exe")
      Processes.process="*temp*.vbe*"
    by Processes.dest Processes.user
       Processes.parent_process_name Processes.process_name
| convert ctime(first_seen)
```

**Expected:** Outlook starts PowerShell, which saves shnmpmbxwylismvb.vbe into %temp% (the exact pattern in the FBI's FishHub affidavit); wscript.exe runs it. The follow-on commands list documents, zip them and upload 186 MB.

| dest | user | parent_process_name | process_name | count |
|---|---|---|---|---|
| WS-0458.lab.example | LAB\a.lim | OUTLOOK.EXE | powershell.exe | 1 |
| WS-0458.lab.example | LAB\a.lim | powershell.exe | wscript.exe | 1 |

### AA26 21 - A4 - Known-bad IP sweep (Appendix)

Sweep the advisory's and the seizure's IP addresses.

```
| tstats count sum(All_Traffic.bytes_out) as bytes_out
    from datamodel=Network_Traffic
    by All_Traffic.src All_Traffic.dest
| lookup aa26_281a_ips ip AS All_Traffic.dest
    OUTPUT ioc_source confidence last_seen expires
| where isnotnull(ioc_source) AND confidence!="invalid"
    AND strptime(expires,"%Y-%m-%d")>now()
```

**Expected:** 10.20.4.58 uploading to 207.148.92.220, the FishHub collection server. This address is in the advisory's STIX file, so here the advisory's indicators do match: the FishHub operators reused known infrastructure.

| src | dest |
|---|---|
| 10.20.4.58 | 207.148.92.220 |

### AA26 22 - SoftEther - Evidence correlated by host (Act 3)

SoftEther: process, service and DNS evidence on one host.

```
| tstats count from datamodel=Endpoint.Processes
    where Processes.original_file_name IN ("vpnclient*","vpnbridge*")
    by Processes.dest
| eval host=upper(mvindex(split('Processes.dest',"."),0)),
    signal="process: SoftEther metadata"
| append [search `wineventlog_system` EventCode=7045
    NOT ImagePath IN ("*\\Windows\\System32\\*","*\\Program Files*")
  | eval host=upper(mvindex(split(Computer,"."),0)),
      signal="service: autostart outside system paths"]
| append [| tstats count from datamodel=Network_Resolution
    where DNS.query IN ("*.softether.net","*.vpnazure.net") by DNS.src
  | lookup aa26_lab_assets ip AS DNS.src OUTPUT host
  | eval signal="dns: SoftEther dynamic DNS"]
| stats dc(signal) as signals values(signal) as evidence by host
| sort - signals
```

**Expected:** WS-0417 has all three signals: process metadata, an autostart service outside system paths, and SoftEther dynamic DNS. WS-0404 has one (its service is in Program Files and it uses no dynamic DNS). One signal is a question; three is a finding.

| host | signals | evidence |
|---|---|---|
| WS-0417 | 3 | dns: SoftEther dynamic DNS, process: SoftEther metadata, service: autostart outside system paths |
| WS-0404 | 1 | process: SoftEther metadata |
| WS-0433 | 1 | service: autostart outside system paths |

### AA26 23 - SoftEther - Tuned detection (Act 3)

SoftEther: the tuned detection that ships.

```
| tstats count min(_time) as first_seen
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("conhost.exe","dllhost.exe")
      NOT Processes.process_path IN ("C:\\Windows\\System32\\*",
                                     "C:\\Windows\\SysWOW64\\*"))
      OR Processes.original_file_name IN ("vpnclient*","vpnbridge*")
    by Processes.dest Processes.process_name
       Processes.original_file_name Processes.process_path
| rename Processes.* as *
| eval dest=upper(mvindex(split(dest,"."),0))
| lookup aa26_approved_remote_access dest process_path
    OUTPUT approved_by
| where isnull(approved_by)
| convert ctime(first_seen)
```

**Expected:** Only WS-0417. The approved install on WS-0404 is removed by the approved remote-access register (host plus path, with an owner and review date), not by weakening the logic.

| dest | process_name | original_file_name | process_path |
|---|---|---|---|
| WS-0417 | conhost.exe | vpnbridge.exe | C:\ProgramData\USOShared\conhost.exe |

### AA26 24 - Investigate - Risk events for j.citizen (Act 4)

Investigation: every risk event behind the finding.

```
index=risk risk_object="j.citizen"
| table _time source risk_score risk_message threat_object
| sort _time
```

**Expected:** The six risk events behind j.citizen's 200, in order: scan, spray, spray success, SoftEther, dynamic DNS, EWS collection. Every point traces to a named detection and a message.

### AA26 25 - Investigate - Where j.citizen signs in from (Act 5)

Investigation: is this really j.citizen?

```
index=exchange sourcetype=ms:iis:auto
    cs_username="j.citizen" sc_status=200
| stats count min(_time) as first max(_time) as last
    values(cs_User_Agent) as agents by cs_username c_ip
| lookup aa26_lab_identities identity AS cs_username
    OUTPUT office_ip home_ip mobile_ip
| eval seen_before=case(c_ip==office_ip,"office", c_ip==home_ip,"home",
    c_ip==mobile_ip,"mobile gateway", true(),"NEVER")
| table c_ip seen_before count first last agents
| convert ctime(first) ctime(last)
| sort - count
```

**Expected:** Two addresses she has never used: 203.0.113.47 (the spray source) and 203.0.113.52 (2,400 EWS calls an hour, no user agent).

| c_ip | seen_before | count | agents |
|---|---|---|---|
| 203.0.113.52 | NEVER | 2400 | - |
| 10.20.4.17 | office | 885 | Microsoft+Office/16.0+(Windows+NT+10.0;+Microsoft+Outlook+16.0.17928;+Pro), Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/129.0.0.0+Safari/537.36+Edg/129.0.0.0 |
| 198.51.100.20 | mobile gateway | 675 | Apple-iPhone16C1/2201.80 |
| 203.0.113.47 | NEVER | 35 | ExchangeServicesClient/15.00.0913.015 |

### AA26 26 - Investigate - Identity and asset context (Act 5)

Investigation: who and what is at risk?

```
| inputlookup aa26_lab_identities.csv
| search identity IN ("j.citizen","a.lim")
| lookup aa26_lab_assets host AS workstation
    OUTPUT ip priority AS host_priority
| table identity display title department workstation ip
    priority host_priority
```

**Expected:** Both are high-priority identities. This is the context that decides how fast the analyst escalates.

### AA26 27 - Exposure - Vulnerable vs targeted (Exposure)

Vulnerable is not exploited: correlate inventory with telemetry.

```
| inputlookup aa26_lab_vulns.csv
| join type=left public_ip
    [| tstats count from datamodel=Network_Traffic
        where All_Traffic.dest_port IN (21,22,53,80,443,1080)
        by All_Traffic.src All_Traffic.dest
     | eventstats dc(All_Traffic.dest) as reach by All_Traffic.src
     | where reach>=25
     | stats values(All_Traffic.src) as scanned_by by All_Traffic.dest
     | rename All_Traffic.dest as public_ip]
| eval state=case(isnotnull(scanned_by),"Targeted: scanned",
    internet_facing=="yes","Exposed: internet-facing",
    true(),"Vulnerable: internal only")
| table host product cve criticality public_ip scanned_by state
```

**Expected:** Five vulnerable assets, three different states. Patch order follows the state, not just the CVSS score.

| host | cve | public_ip | scanned_by | state |
|---|---|---|---|---|
| VPN01 | CVE-2019-11510 | 192.0.2.22 | 198.51.100.77, 203.0.113.47 | Targeted: scanned |
| FTP01 | CVE-2015-3306 | 192.0.2.10 | 198.51.100.77, 203.0.113.47 | Targeted: scanned |
| NS01 | CVE-2015-5477 | 192.0.2.45 |  | Exposed: internet-facing |
| GIT01 | CVE-2021-22205 |  |  | Vulnerable: internal only |
| LEGACY01 | CVE-2014-6278 |  |  | Vulnerable: internal only |

### AA26 28 - AI - First draft with assumed fields (AI)

AI's first draft, run as written.

```
index=exchange sourcetype=ms:iis:auto action=failure
| bin _time span=30m
| stats dc(user) as users count by _time src_ip
| where users>=10
```

**Expected:** Zero results. The draft assumed fields this data does not have: src_ip (the IIS field is c_ip) and action=failure (in this data action is only allowed or blocked). Filtering on sc_status=401 and grouping by c_ip finds the spray: 64 users, 104 failures from 203.0.113.47.

_No results. That is the expected outcome._

### AA26 29 - Recon - Scanner profile (Act 3)

Who is scanning: direction, baseline and what they did next.

```
| tstats dc(All_Traffic.dest) as hosts dc(All_Traffic.dest_port) as ports
    from datamodel=Network_Traffic
    where All_Traffic.dest_port IN (21,22,53,80,443,1080)
    by All_Traffic.src _time span=1h
| rename All_Traffic.src as src
| where hosts>=25
| stats max(hosts) as hosts max(ports) as ports count as scan_hours
    dc(eval(strftime(_time,"%Y-%m-%d"))) as scan_days min(_time) as first_scan by src
| eval direction=if(cidrmatch("10.0.0.0/8",src),"internal","external")
| lookup aa26_approved_scanners src OUTPUT reason as approved
| join type=left src
    [search `aa26_iis` sc_status=200 cs_username=* cs_username!="-"
     | stats dc(cs_username) as signed_in_as by c_ip | rename c_ip as src]
| fillnull value=0 signed_in_as
| eval verdict=case(isnotnull(approved),"approved scanner",
    signed_in_as>0,"scanned, then signed in",
    true(),"background scanning")
| eval first_scan=strftime(first_scan,"%d %b %H:%M")
| table src direction hosts ports scan_days first_scan signed_in_as verdict
```

**Expected:** Three scanners, three verdicts. 10.20.0.50 is internal, on the approved register, every Sunday morning. 198.51.100.77 is external, two isolated hours, ports 22 and 443 only, and never signs in: background. 203.0.113.47 is external, appears once (28 Sep 09:00), hits all six advisory ports and then signs in as one user: the actor.

_No results. That is the expected outcome._

### AA26 30 - Exposure - Exploit attempts by source (Exposure)

Who tried the advisory's exploits against us, and did anything answer?

```
`aa26_iis` (cs_User_Agent="*()*" OR cs_uri_stem IN ("/dana-na/*","/uploads/user","/FileUploader.ashx","/web-apps/apps/api/documents/*") OR cs_uri_query IN ("*memberAccess*","*ognl*","*startsWith*","*%3Cscript*","*%3Csvg*","*%3Cimg*","*onerror*","*onload*"))
| eval attempt=case(match(cs_User_Agent,"[(][)][+ ]?[{]"),"CVE-2014-6278 Bash",
    match(cs_uri_query,"(?i)memberAccess|ognl"),"CVE-2016-3081 Struts",
    match(cs_uri_stem,"(?i)^/dana-na/.*[.][.]/"),"CVE-2019-11510 Pulse Secure",
    cs_uri_stem=="/uploads/user" AND cs_method=="POST","CVE-2021-22205 GitLab",
    match(cs_uri_stem,"(?i)^/FileUploader[.]ashx|^/web-apps/apps/api/documents/"),"CVE-2021-3199 ONLYOFFICE",
    match(cs_uri_query,"(?i)[[]password[]].{0,4}startsWith"),"CVE-2023-22894 Strapi",
    match(cs_uri_query,"(?i)%3C(script|svg|img)|onerror%3D|onload%3D"),"XSS payload")
| where isnotnull(attempt)
| lookup aa26_approved_scanners src AS c_ip OUTPUT reason AS approved
| eval direction=if(cidrmatch("10.0.0.0/8",c_ip),"internal","external")
| stats count as requests dc(attempt) as techniques values(attempt) as attempts count(eval(sc_status<400)) as answered
    min(_time) as first values(approved) as approved values(direction) as direction by c_ip
| eval verdict=case(isnotnull(approved),"approved scanner", techniques>=3,"multi-exploit sweep: investigate", true(),"opportunistic probe")
| eval first=strftime(first,"%d %b %H:%M")
| rename c_ip as src
| sort - techniques
| table src direction techniques attempts requests answered first verdict
```

**Expected:** 203.0.113.47 tries six of the advisory's CVEs and three XSS payloads against WEB01 at 09:41, between the scan and the spray. The website answered two of the XSS requests with 200: check that /search.aspx and /contact.aspx encode their input. 198.51.100.77 tries one old Bash exploit twice: everyday internet noise. 10.20.0.50 is the approved scanner checking for the same CVEs on Sundays.

| src | techniques | attempts | requests | answered | verdict |
|---|---|---|---|---|---|
| 203.0.113.47 | 7 | CVE-2014-6278 Bash, CVE-2016-3081 Struts, CVE-2019-11510 Pulse Secure, CVE-2021-22205 GitLab, CVE-2021-3199 ONLYOFFICE, CVE-2023-22894 Strapi, XSS payload | 15 | 2 | multi-exploit sweep: investigate |
| 10.20.0.50 | 4 | CVE-2014-6278 Bash, CVE-2016-3081 Struts, CVE-2023-22894 Strapi, XSS payload | 12 | 3 | approved scanner |
| 198.51.100.77 | 1 | CVE-2014-6278 Bash | 2 | 0 | opportunistic probe |

### AA26 31 - Exposure - Advisory CVEs in our estate (Exposure)

The advisory's eight CVEs: present, internet-facing, scanned, attempted, visible?

```
| inputlookup aa26_advisory_cves.csv
| eval age=tonumber(strftime(now(),"%Y"))-year
| join type=left cve
    [| inputlookup aa26_lab_vulns.csv | rename host as asset]
| join type=left public_ip
    [| tstats count from datamodel=Network_Traffic
        where All_Traffic.dest_port IN (21,22,53,80,443,1080)
        by All_Traffic.src All_Traffic.dest
     | eventstats dc(All_Traffic.dest) as reach by All_Traffic.src
     | where reach>=25
     | lookup aa26_approved_scanners src AS All_Traffic.src OUTPUT reason
     | where isnull(reason)
     | stats values(All_Traffic.src) as scanned_by by All_Traffic.dest
     | rename All_Traffic.dest as public_ip]
| join type=left cve
    [search `aa26_iis` (cs_User_Agent="*()*" OR cs_uri_stem IN ("/dana-na/*","/uploads/user","/FileUploader.ashx","/web-apps/apps/api/documents/*") OR cs_uri_query IN ("*memberAccess*","*ognl*","*startsWith*","*%3Cscript*","*%3Csvg*","*%3Cimg*","*onerror*","*onload*"))
    | eval attempt=case(match(cs_User_Agent,"[(][)][+ ]?[{]"),"CVE-2014-6278 Bash",
        match(cs_uri_query,"(?i)memberAccess|ognl"),"CVE-2016-3081 Struts",
        match(cs_uri_stem,"(?i)^/dana-na/.*[.][.]/"),"CVE-2019-11510 Pulse Secure",
        cs_uri_stem=="/uploads/user" AND cs_method=="POST","CVE-2021-22205 GitLab",
        match(cs_uri_stem,"(?i)^/FileUploader[.]ashx|^/web-apps/apps/api/documents/"),"CVE-2021-3199 ONLYOFFICE",
        match(cs_uri_query,"(?i)[[]password[]].{0,4}startsWith"),"CVE-2023-22894 Strapi",
        match(cs_uri_query,"(?i)%3C(script|svg|img)|onerror%3D|onload%3D"),"XSS payload")
    | where isnotnull(attempt)
     | lookup aa26_approved_scanners src AS c_ip OUTPUT reason
     | where isnull(reason)
     | eval cve=mvindex(split(attempt," "),0)
     | stats values(c_ip) as attempted_by by cve]
| join type=left asset
    [| tstats count as events where index IN (exchange,web,o365,wineventlog,sysmon,firewall,dns) by host
     | eval asset=upper(host) | fields asset events]
| eval telemetry=case(isnull(asset),"-", events>0,"logs to Splunk", true(),"NO LOGS"),
    priority=case(isnull(asset),"Not found: confirm inventory",
        internet_facing=="yes" AND isnotnull(scanned_by),"1 Patch now",
        internet_facing=="yes","2 Patch this week",
        true(),"3 Patch this month")
| sort cve
| table cve year age product impact kev_added_with_advisory asset internet_facing scanned_by attempted_by telemetry priority
```

**Expected:** Five of the eight CVEs are on assets we own. VPN01 (Pulse Secure) and FTP01 (ProFTPD) are internet-facing and the actor scanned them: patch now. None of the five vulnerable assets sends logs, so an exploit against them would be invisible; the attempts we can see hit the web server. The FTP and DNS CVEs can never appear in a web log.

| cve | asset | attempted_by | telemetry | priority |
|---|---|---|---|---|
| CVE-2014-6278 | LEGACY01 | 198.51.100.77, 203.0.113.47 | NO LOGS | 3 Patch this month |
| CVE-2015-3306 | FTP01 |  | NO LOGS | 1 Patch now |
| CVE-2015-5477 | NS01 |  | NO LOGS | 2 Patch this week |
| CVE-2016-3081 |  | 203.0.113.47 | - | Not found: confirm inventory |
| CVE-2019-11510 | VPN01 | 203.0.113.47 | NO LOGS | 1 Patch now |
| CVE-2021-22205 | GIT01 | 203.0.113.47 | NO LOGS | 3 Patch this month |
| CVE-2021-3199 |  | 203.0.113.47 | - | Not found: confirm inventory |
| CVE-2023-22894 |  | 203.0.113.47 | - | Not found: confirm inventory |

## 4. Base detections monitoring for this adversary

The Integrity Tech Detections app (`integrity_tech_detections`) installs 18 Enterprise Security detections, enabled and scheduled. They find nothing in the lab data because it is historical; they watch for the same behaviour from now on. Each one writes risk to the user or system involved (an intermediate finding), and **Integrity Tech behaviour chain** raises a finding when one entity reaches risk 100 across three ATT&CK tactics. Change the `aa26_iis` and `aa26_o365` macros, and the `aa26_approved_scanners` lookup, to fit your environment.

`python3 labctl.py backtest` runs every detection over the scenario window without its actions and checks the row count below. Nothing is written to the risk index.

| detection | ATT&CK | risk to | runs | backtest rows |
|---|---|---|---|---|
| AA26-281A - Exchange password spray - Rule | T1110.003 | src +20 | */30 * * * * | 1 |
| AA26-281A - Spray source authenticated - Rule | T1078, T1110.003 | user +40, src +40 | */30 * * * * | 1 |
| AA26-281A - Scanning on advisory ports - Rule | T1595.002 | src +10 | 5 * * * * | 3 |
| AA26-281A - Web enumeration burst - Rule | T1595.003 | src +10 | */30 * * * * | 1 |
| AA26-281A - Exploit attempts for advisory CVEs - Rule | T1190, T1059.007 | src +20 | */30 * * * * | 1 |
| AA26-281A - SoftEther masquerading as Windows binary - Rule | T1036.005, T1133, T1572 | dest +60, owner +60 | 15 * * * * | 1 |
| AA26-281A - SoftEther dynamic DNS - Rule | T1572, T1568 | dest +20, owner +20 | 15 * * * * | 1 |
| AA26-281A - Autostart service outside system paths - Rule | T1543.003 | dest +30 | 20 * * * * | 2 |
| AA26-281A - EWS volume far above normal - Rule | T1114.002 | user +50 | 10 * * * * | 1 |
| AA26-281A - Unapproved app reading many mailboxes - Rule | T1114.002, T1550.001 | AppId +40 | 25 * * * * | 1 |
| AA26-281A - New app secret or consent - Rule | T1098.001 | user +30 | */30 * * * * | 1 |
| AA26-281A - DCSync by non-machine account - Rule | T1003.006 | user +80 | */30 * * * * | 0 |
| AA26-281A - Advisory decoy file names - Rule | T1036.008, T1074.001 | dest +30 | 20 * * * * | 3 |
| AA26-281A - FishHub-style script stager - Rule | T1566.001, T1059.005, T1105 | dest +40, user +40 | 15 * * * * | 2 |
| AA26-281A - Known-bad domain resolved - Rule | T1071.001, T1105 | src +30 | 15 * * * * | 1 |
| AA26-281A - Connection to known-bad IP - Rule | T1071.001, T1041 | src +30 | 15 * * * * | 1 |
| AA26-281A - Upload-heavy host - Rule | T1048, T1041 | src +20 | 5 * * * * | 6 |
| AA26-281A - Integrity Tech behaviour chain - Rule |  | raises a finding | 30 * * * * | 2 |

DCSync returns nothing in the lab because the replication audit SACL was never set: the gap is the finding.
