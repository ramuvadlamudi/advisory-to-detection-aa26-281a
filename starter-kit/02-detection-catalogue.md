# AA26-281A detection catalogue

17 behaviour detections and 1 correlation finding. Each behaviour detection writes risk (an intermediate finding) to the user or system involved; AA26-C01 raises the finding an analyst works. All were backtested on the synthetic lab: 16 fire on the attack, and AA26-D11 (DCSync) correctly returns nothing because the audit SACL is missing. That is a gap, not a pass.

| ID | Detection | ATT&CK | Severity | Risk | Owner | Review | Lab rows |
|---|---|---|---|---|---|---|---|
| AA26-D01 | Exchange password spray | T1110.003 | low | src (system) +20 | SOC Detection Engineering (Identity) | 2027-02-23 | 1 |
| AA26-D02 | Spray source authenticated | T1078, T1110.003 | high | user (user) +40, src (system) +40 | SOC Detection Engineering (Identity) | 2027-02-23 | 1 |
| AA26-D03 | Scanning on advisory ports | T1595.002 | low | src (system) +10 | SOC Detection Engineering (Network) | 2027-02-23 | 3 |
| AA26-D04 | Web enumeration burst | T1595.003 | low | src (system) +10 | SOC Detection Engineering (Network) | 2027-02-23 | 1 |
| AA26-D17 | Exploit attempts for advisory CVEs | T1190, T1059.007 | medium | src (system) +20 | SOC Detection Engineering (Network) | 2027-02-23 | 1 |
| AA26-D05 | SoftEther masquerading as Windows binary | T1036.005, T1133, T1572 | high | dest (system) +60, owner (user) +60 | SOC Detection Engineering (Endpoint) | 2027-02-23 | 1 |
| AA26-D06 | SoftEther dynamic DNS | T1572, T1568 | medium | dest (system) +20, owner (user) +20 | SOC Detection Engineering (Network) | 2027-02-23 | 1 |
| AA26-D07 | Autostart service outside system paths | T1543.003 | medium | dest (system) +30 | SOC Detection Engineering (Endpoint) | 2027-02-23 | 2 |
| AA26-D08 | EWS volume far above normal | T1114.002 | high | user (user) +50 | SOC Detection Engineering (Identity) | 2027-02-23 | 1 |
| AA26-D09 | Unapproved app reading many mailboxes | T1114.002, T1550.001 | high | AppId (other) +40 | SOC Detection Engineering (Cloud) | 2027-02-23 | 1 |
| AA26-D10 | New app secret or consent | T1098.001 | medium | user (user) +30 | SOC Detection Engineering (Cloud) | 2027-02-23 | 1 |
| AA26-D11 | DCSync by non-machine account | T1003.006 | critical | user (user) +80 | SOC Detection Engineering (Identity) | 2027-02-23 | 0 |
| AA26-D12 | Advisory decoy file names | T1036.008, T1074.001 | medium | dest (system) +30 | SOC Detection Engineering (Endpoint) | 2027-02-23 | 3 |
| AA26-D13 | FishHub-style script stager | T1566.001, T1059.005, T1105 | high | dest (system) +40, user (user) +40 | SOC Detection Engineering (Endpoint) | 2027-02-23 | 2 |
| AA26-D14 | Known-bad domain resolved | T1071.001, T1105 | medium | src (system) +30 | Cyber Threat Intelligence (indicator lifecycle) | 2027-01-06 | 1 |
| AA26-D15 | Connection to known-bad IP | T1071.001, T1041 | medium | src (system) +30 | Cyber Threat Intelligence (indicator lifecycle) | 2027-01-06 | 1 |
| AA26-D16 | Upload-heavy host | T1048, T1041 | low | src (system) +20 | SOC Detection Engineering (Network) | 2027-02-23 | 6 |
| AA26-C01 | Integrity Tech behaviour chain | TA0001-TA0011 (any three tactics) | high | raises a finding (severity high) | SOC Manager (finding queue) | 2027-02-23 | 2 |

## AA26-D01: Exchange password spray

**Behaviour.** EBurst-style password spraying across Exchange interfaces.

**Description.** One source fails against ten or more mailboxes, a few attempts each, across Exchange interfaces (EBurst-style spraying).

**ATT&CK.** T1110.003

**Data sources and fields.** Exchange IIS W3C logs: c_ip, cs_username, cs_uri_stem, sc_status (all ten Exchange virtual directories). CIM: Web (partial): IIS fields are used directly because CIM Web has no username field.

**Logic.**

```
`aa26_iis` cs_uri_stem IN ("/EWS/*","/owa/*","/ecp/*","/oab/*","/mapi/*","/rpc/*","/autodiscover/*","/powershell*","/Microsoft-Server-ActiveSync*","/api/*")
| eval interface=lower(mvindex(split(cs_uri_stem,"/"),1))
| bin _time span=30m
| stats count(eval(sc_status=401)) as failures dc(eval(if(sc_status=401,cs_username,null()))) as users dc(interface) as interfaces values(eval(if(sc_status=200,cs_username,null()))) as ok by _time c_ip
| where users>=10 AND failures/users<=3
| rename c_ip as src
```

**Schedule.** `*/30 * * * *` (every 30 minutes), searching -70m@m to -10m@m.

**Severity and risk.** low; src (system) +20.

**False-positive conditions.**

- Load balancers, reverse proxies or NAT egress presenting many users as one address
- Mobile gateways after a password-policy change

**Tuning.**

- Ingest the real client address (X-Forwarded-For) where a proxy fronts Exchange
- Allow-list known gateways in a lookup with an owner and review date; never by subnet wildcard

**Positive test.** Replay of the lab spray (64 mailboxes, 104 failures, 4 interfaces from 203.0.113.47) fires once.

**Negative test.** Monday-morning logon surge and the mobile gateway's routine failures stay silent.

**Owner.** SOC Detection Engineering (Identity). **Review by** 2027-02-23.

**When it fires.** Score only. Check the source's reputation; if it is internal, open a host investigation. Watch AA26-D02 for a success.

## AA26-D02: Spray source authenticated

**Behaviour.** A sprayed account then authenticates from the spraying source.

**Description.** An account that a spraying source failed against then succeeds from that same source in the same 30 minutes: the sprayed password worked.

**ATT&CK.** T1078, T1110.003

**Data sources and fields.** Exchange IIS W3C logs: c_ip, cs_username, sc_status. CIM: Web (partial).

**Logic.**

```
`aa26_iis` cs_uri_stem IN ("/EWS/*","/owa/*","/ecp/*","/oab/*","/mapi/*","/rpc/*","/autodiscover/*","/powershell*","/Microsoft-Server-ActiveSync*","/api/*")
| bin _time span=30m
| stats count(eval(sc_status=401)) as fails count(eval(sc_status=200)) as wins by _time c_ip cs_username
| eventstats sum(fails) as failures dc(eval(if(fails>0,cs_username,null()))) as users by _time c_ip
| where users>=10 AND failures/users<=3 AND fails>0 AND wins>0
| rename c_ip as src cs_username as user
```

**Schedule.** `*/30 * * * *` (every 30 minutes), searching -70m@m to -10m@m.

**Severity and risk.** high; user (user) +40, src (system) +40.

**False-positive conditions.**

- A user who mistyped once behind the same NAT as a spray (rare; check the user agent)

**Tuning.**

- Requires the account to be among the sprayed accounts and the success to come from the same source in the same 30 minutes

**Positive test.** j.citizen: failed once from 203.0.113.47 during the spray, then 200s from the same address: fires once.

**Negative test.** Users who succeed from the gateway during a spray without first failing from it stay silent.

**Owner.** SOC Detection Engineering (Identity). **Review by** 2027-02-23.

**When it fires.** Treat the account as compromised: reset the password, revoke sessions and tokens, confirm MFA on every Exchange protocol, and review mailbox activity since the success.

## AA26-D03: Scanning on advisory ports

**Behaviour.** Reconnaissance against the advisory's ports (21, 22, 53, 80, 443, 1080).

**Description.** One source touches 25 or more hosts in an hour on the ports AA26-281A lists (21, 22, 53, 80, 443, 1080). Approved scanners are excluded.

**ATT&CK.** T1595.002

**Data sources and fields.** Firewall or NetFlow: src, dest, dest_port. CIM: Network_Traffic.

**Logic.**

```
| tstats dc(All_Traffic.dest) as hosts dc(All_Traffic.dest_port) as ports from datamodel=Network_Traffic where All_Traffic.dest_port IN (21,22,53,80,443,1080) by All_Traffic.src _time span=1h
| rename All_Traffic.src as src
| where hosts>=25
| lookup aa26_approved_scanners src OUTPUT reason
| where isnull(reason)
```

**Schedule.** `5 * * * *` (hourly at :05), searching -2h@h to -1h@h.

**Severity and risk.** low; src (system) +10.

**False-positive conditions.**

- Approved vulnerability scanners and monitoring
- Internet background scanning

**Tuning.**

- aa26_approved_scanners lookup (scanner, owner, reason)
- Score external sources low; investigate internal sources

**Positive test.** 203.0.113.47 (41 hosts, 6 ports) fires; so does the internet background scanner, at low score.

**Negative test.** The internal vulnerability scanner 10.20.0.50 is excluded by the lookup.

**Owner.** SOC Detection Engineering (Network). **Review by** 2027-02-23.

**When it fires.** Score only. Internal source scanning: open a host investigation.

## AA26-D04: Web enumeration burst

**Behaviour.** dirsearch-style enumeration of .php and .asp pages.

**Description.** Two hundred or more distinct missing .php/.asp paths from one client in ten minutes (dirsearch-style enumeration).

**ATT&CK.** T1595.003

**Data sources and fields.** Web server or WAF logs: src, uri_path, status, http_user_agent. CIM: Web.

**Logic.**

```
| tstats dc(Web.uri_path) as paths from datamodel=Web where Web.status=404 (Web.uri_path="*.php" OR Web.uri_path="*.asp*") by Web.src Web.http_user_agent _time span=10m
| rename Web.src as src Web.http_user_agent as http_user_agent
| where paths>=200
```

**Schedule.** `*/30 * * * *` (every 30 minutes), searching -70m@m to -10m@m.

**Severity and risk.** low; src (system) +10.

**False-positive conditions.**

- Authorised web application scans and penetration tests

**Tuning.**

- Allow-list scheduled scanners by source and window
- Raise the path threshold for very large sites

**Positive test.** 203.0.113.47's 450 missing script paths in ten minutes fire once.

**Negative test.** Normal 404s from broken links stay silent.

**Owner.** SOC Detection Engineering (Network). **Review by** 2027-02-23.

**When it fires.** Score only. Correlate with exploitation attempts against the same server.

## AA26-D17: Exploit attempts for advisory CVEs

**Behaviour.** One source trying several of the advisory's exploited CVEs (2014-2023) and XSS payloads against web servers.

**Description.** One source tries three or more of AA26-281A's exploited CVEs or XSS payloads against a web server (MicroScan-style exploit sweep). Approved scanners are excluded; 'answered' counts responses below 400.

**ATT&CK.** T1190, T1059.007

**Data sources and fields.** Web server, reverse proxy or WAF logs: c_ip, cs_method, cs_uri_stem, cs_uri_query, cs_User_Agent, sc_status. CIM: Web (partial): the query string and user agent are used directly.

**Logic.**

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
| where isnull(approved)
| stats count as requests dc(attempt) as techniques values(attempt) as attempts count(eval(sc_status<400)) as answered min(_time) as first_seen values(host) as dest by c_ip
| where techniques>=3
| rename c_ip as src
```

**Schedule.** `*/30 * * * *` (every 30 minutes), searching -70m@m to -10m@m.

**Severity and risk.** medium; src (system) +20.

**False-positive conditions.**

- Authorised vulnerability scanners and penetration tests
- Security research crawlers

**Tuning.**

- aa26_approved_scanners lookup (scanner, owner, reason), never a user-agent allow-list
- Three or more distinct techniques from one source; a single probe is background noise
- FTP, DNS and VPN appliance exploits never reach a web log: cover them with inventory and appliance logs

**Positive test.** 203.0.113.47: 7 techniques (six advisory CVEs plus XSS), 15 requests, 2 answered: fires once.

**Negative test.** The approved scanner 10.20.0.50 (4 techniques) and a one-technique background probe stay silent.

**Owner.** SOC Detection Engineering (Network). **Review by** 2027-02-23.

**When it fires.** Score the source. Check which requests were answered (status below 400) and patch or fix those pages first; confirm the vulnerable products in the inventory (AA26 31).

## AA26-D05: SoftEther masquerading as Windows binary

**Behaviour.** SoftEther VPN renamed as a Windows process for persistence (the flagship walkthrough).

**Description.** conhost.exe or dllhost.exe running outside System32/SysWOW64, or any process whose original file name is a SoftEther VPN client or bridge, unless the host and path are in the approved remote-access register. Risk goes to the host and its assigned owner.

**ATT&CK.** T1036.005, T1133, T1572

**Data sources and fields.** Sysmon event 1 or EDR process telemetry: dest, process_name, process_path, original_file_name, parent_process_name. CIM: Endpoint.Processes (needs original_file_name).

**Logic.**

```
| tstats count min(_time) as first_seen values(Processes.parent_process_name) as parent_process_name from datamodel=Endpoint.Processes where (Processes.process_name IN ("conhost.exe","dllhost.exe") NOT Processes.process_path IN ("C:\\Windows\\System32\\*","C:\\Windows\\SysWOW64\\*")) OR Processes.original_file_name IN ("vpnclient*","vpnbridge*") by Processes.dest Processes.process_name Processes.original_file_name Processes.process_path
| rename Processes.* as *
| eval dest=upper(mvindex(split(dest,"."),0))
| lookup aa26_approved_remote_access dest process_path OUTPUT approved_by
| where isnull(approved_by)
| lookup aa26_lab_assets host AS dest OUTPUT owner
```

**Schedule.** `15 * * * *` (hourly at :15), searching -70m@m to -10m@m.

**Severity and risk.** high; dest (system) +60, owner (user) +60.

**False-positive conditions.**

- Approved SoftEther installs (IT remote access)
- Software that legitimately ships its own conhost-named helper

**Tuning.**

- aa26_approved_remote_access lookup: host plus exact path, with approver and review date
- Never allow-list by process name or by vendor alone

**Positive test.** WS-0417: conhost.exe in C:\ProgramData\USOShared with original file name vpnbridge.exe fires once.

**Negative test.** WS-0404's approved SoftEther VPN Client in Program Files and every real conhost.exe in System32 stay silent.

**Owner.** SOC Detection Engineering (Endpoint). **Review by** 2027-02-23.

**When it fires.** Corroborate with AA26-D06 and AA26-D07 on the same host, check the owner's recent authentication, then request approval to isolate the host. Block the SoftEther dynamic DNS name and hunt the same hash across the fleet.

## AA26-D06: SoftEther dynamic DNS

**Behaviour.** SoftEther reaching its server through dynamic DNS or VPN Azure.

**Description.** A host resolves SoftEther dynamic DNS or VPN Azure names, which SoftEther uses to reach its server through firewalls.

**ATT&CK.** T1572, T1568

**Data sources and fields.** DNS logs: src, query. CIM: Network_Resolution.

**Logic.**

```
| tstats count from datamodel=Network_Resolution where DNS.query IN ("*.softether.net","*.vpnazure.net") by DNS.src DNS.query
| rename DNS.src as src DNS.query as query
| lookup aa26_lab_assets ip AS src OUTPUT host AS dest owner
| eval dest=coalesce(dest,src)
```

**Schedule.** `15 * * * *` (hourly at :15), searching -70m@m to -10m@m.

**Severity and risk.** medium; dest (system) +20, owner (user) +20.

**False-positive conditions.**

- Approved SoftEther users who rely on its dynamic DNS

**Tuning.**

- Exclude hosts in the approved remote-access register

**Positive test.** WS-0417 resolving vpn583920174.softether.net (18 lookups) fires once.

**Negative test.** Hosts without SoftEther never resolve these names.

**Owner.** SOC Detection Engineering (Network). **Review by** 2027-02-23.

**When it fires.** Corroborate with AA26-D05 on the same host.

## AA26-D07: Autostart service outside system paths

**Behaviour.** New auto-start service whose binary sits outside System32 and Program Files.

**Description.** A new auto-start service whose binary is outside Windows\System32 and Program Files.

**ATT&CK.** T1543.003

**Data sources and fields.** Windows System log event 7045: Computer, ServiceName, ImagePath, StartType. CIM: Change (Endpoint.Services where mapped).

**Logic.**

```
`wineventlog_system` EventCode=7045 NOT ImagePath IN ("*\\Windows\\System32\\*","*\\Program Files*")
| stats count min(_time) as first_seen by Computer ServiceName ImagePath StartType
| eval dest=Computer
| eval dest=upper(mvindex(split(dest,"."),0))
```

**Schedule.** `20 * * * *` (hourly at :20), searching -70m@m to -10m@m.

**Severity and risk.** medium; dest (system) +30.

**False-positive conditions.**

- Vendor updaters installed in ProgramData (for example the lab's Lenovo service)

**Tuning.**

- Allow-list by host role, service name and exact path, with an owner

**Positive test.** 'Console Host Service' running C:\ProgramData\USOShared\conhost.exe on WS-0417 fires.

**Negative test.** The approved SoftEther client's service (Program Files) stays silent.

**Owner.** SOC Detection Engineering (Endpoint). **Review by** 2027-02-23.

**When it fires.** Check the binary's original file name and signer; corroborate with process and network evidence.

## AA26-D08: EWS volume far above normal

**Behaviour.** Scripted mailbox collection through Exchange Web Services (Curlc4.txt).

**Description.** A user's EWS calls in one hour are at least 500 and ten times their own 14-day hourly median, for users with at least 24 active hours of history (scripted mailbox collection).

**ATT&CK.** T1114.002

**Data sources and fields.** Exchange IIS W3C logs: cs_username, c_ip, cs_uri_stem, cs_User_Agent, sc_status. CIM: Web (partial).

**Logic.**

```
`aa26_iis` sc_status=200 cs_uri_stem="/EWS/Exchange.asmx"
| bin _time span=1h
| stats count as calls values(cs_User_Agent) as agents by _time cs_username c_ip
| eventstats median(calls) as typical count as active_hours by cs_username
| where active_hours>=24 AND calls>=500 AND calls>=10*typical
| eval hour=strftime(_time,"%Y-%m-%d %H:00")
| rename cs_username as user c_ip as src
```

**Schedule.** `10 * * * *` (hourly at :10), searching -14d@h to @h.

**Severity and risk.** high; user (user) +50.

**False-positive conditions.**

- Mailbox migrations, eDiscovery exports, backup service accounts

**Tuning.**

- Per-user baseline: ten times the user's own hourly median and at least 500 calls
- Skip users with fewer than 24 active hours, because a median of two or three hours is not a baseline
- Validate across the full retention, including low-volume users

**Positive test.** j.citizen: 2,400 EWS calls in one hour from 203.0.113.52 with no user agent (typical 3) fires once.

**Negative test.** svc-crm's steady 160 calls an hour stays silent.

**Owner.** SOC Detection Engineering (Identity). **Review by** 2027-02-23.

**When it fires.** Identify the client and source; if not a known integration, revoke the user's sessions and scope what was read.

## AA26-D09: Unapproved app reading many mailboxes

**Behaviour.** office-cli style collection through a Microsoft 365 app registration.

**Description.** An application not on the approved list reads five or more mailboxes (office-cli style collection through an app registration).

**ATT&CK.** T1114.002, T1550.001

**Data sources and fields.** Microsoft 365 unified audit log, MailItemsAccessed: AppId, MailboxOwnerUPN, ClientIPAddress. CIM: None (vendor fields).

**Logic.**

```
`aa26_o365` Operation=MailItemsAccessed
| stats dc(MailboxOwnerUPN) as mailboxes count values(ClientIPAddress) as src by AppId
| lookup approved_mail_apps AppId OUTPUT owner
| where mailboxes>=5 AND isnull(owner)
```

**Schedule.** `25 * * * *` (hourly at :25), searching -24h@h to @h.

**Severity and risk.** high; AppId (other) +40.

**False-positive conditions.**

- A new approved integration not yet in the register

**Tuning.**

- approved_mail_apps lookup with owner
- Requires MailItemsAccessed enabled and retained for every mailbox

**Positive test.** The rogue app owned by j.citizen reading 7 mailboxes fires once.

**Negative test.** The approved backup app reading every audited mailbox stays silent.

**Owner.** SOC Detection Engineering (Cloud). **Review by** 2027-02-23.

**When it fires.** Disable the app's credentials, review its consent and owner, and scope the mailboxes read.

## AA26-D10: New app secret or consent

**Behaviour.** Credentials added to an application, or consent granted.

**Description.** A credential is added to an application or service principal, or a user consents to an application.

**ATT&CK.** T1098.001

**Data sources and fields.** Microsoft 365 / Entra audit: UserId, Operation, ObjectId. CIM: Change.

**Logic.**

```
`aa26_o365` Operation IN ("Add service principal credentials*","*Certificates and secrets*","Consent to application*")
| stats count values(ObjectId) as app values(ClientIP) as src by UserId Operation
| rename UserId as user
```

**Schedule.** `*/30 * * * *` (every 30 minutes), searching -70m@m to -10m@m.

**Severity and risk.** medium; user (user) +30.

**False-positive conditions.**

- Routine secret rotation by the app owner

**Tuning.**

- Correlate with change records; alert on apps with mail permissions first

**Positive test.** j.citizen adding a secret to the rogue app the night before collection fires once.

**Negative test.** Scheduled rotation by the integration team, with a change record, is closed as expected.

**Owner.** SOC Detection Engineering (Cloud). **Review by** 2027-02-23.

**When it fires.** Confirm with the app owner; if unexpected, remove the credential and review the app's permissions.

## AA26-D11: DCSync by non-machine account

**Behaviour.** DCSync with DC.exe or secretsdump (directory replication by a non-DC account).

**Description.** Directory replication rights used by an account that is not a domain controller (needs 4662 auditing with the replication SACL).

**ATT&CK.** T1003.006

**Data sources and fields.** Security event 4662 on domain controllers: SubjectUserName, Properties, AccessMask. CIM: None (vendor fields).

**Prerequisite.** Needs two settings, not one: (1) Advanced Audit Policy, DS Access > Audit Directory Service Access (Success) on domain controllers; (2) a SACL on the domain root auditing Success for Everyone on the three control-access rights: Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes In Filtered Set. Without the SACL, 4662 is never written for replication.

**Logic.**

```
`wineventlog_security` EventCode=4662 AccessMask=0x100 Properties IN ("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*","*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*","*89e95b76-444d-4c62-991a-0facbeda640c*") NOT SubjectUserName="*$"
| stats count min(_time) as first_seen by SubjectUserName Computer
| rename SubjectUserName as user
```

**Schedule.** `*/30 * * * *` (every 30 minutes), searching -70m@m to -10m@m.

**Severity and risk.** critical; user (user) +80.

**False-positive conditions.**

- Microsoft Entra Connect (MSOL_ accounts)
- dcdiag and other replication tests

**Tuning.**

- Allow-list the Entra Connect account by name

**Positive test.** Cannot be tested in the lab: no 4662 events, because the SACL was never set. Record it as a gap.

**Negative test.** Domain controller computer accounts (ending in $) replicating normally stay silent.

**Owner.** SOC Detection Engineering (Identity). **Review by** 2027-02-23.

**When it fires.** Treat every domain credential as exposed: contain the account, reset krbtgt twice, and plan eviction.

## AA26-D12: Advisory decoy file names

**Behaviour.** Mail dumps and tools staged under the advisory's decoy names.

**Description.** Files named like AA26-281A's staging and tool files (001.gif, Css.js, M2k*.js, Include.png, All_scanner_v*.pl.gz, .sess.zip).

**ATT&CK.** T1036.008, T1074.001

**Data sources and fields.** Sysmon event 11 or EDR file telemetry: dest, file_path, file_name. CIM: Endpoint.Filesystem.

**Logic.**

```
| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("001.gif","Css.js","M2k*.js","Include.png","All_scanner_v*.pl.gz",".sess.zip") by Filesystem.dest Filesystem.file_path Filesystem.file_name
| rename Filesystem.* as *
| eval dest=upper(mvindex(split(dest,"."),0))
```

**Schedule.** `20 * * * *` (hourly at :20), searching -70m@m to -10m@m.

**Severity and risk.** medium; dest (system) +30.

**False-positive conditions.**

- Web deployments that legitimately ship Css.js or similar names

**Tuning.**

- Exclude by host role and path (for example the web root on WEB01)

**Positive test.** The staged files on WS-0417 fire.

**Negative test.** Ordinary image and script files with other names stay silent.

**Owner.** SOC Detection Engineering (Endpoint). **Review by** 2027-02-23.

**When it fires.** Check the file's size, type and creator; a large 'image' or 'script' is likely an archive.

## AA26-D13: FishHub-style script stager

**Behaviour.** FishHub phishing stager: a .vbe saved to %temp% and run by a script host.

**Description.** A script host or PowerShell handles a .vbe file in a temp folder, the pattern of the FishHub downloader in the 8 Oct 2026 seizure affidavit.

**ATT&CK.** T1566.001, T1059.005, T1105

**Data sources and fields.** Sysmon event 1 or EDR: dest, user, parent_process_name, process_name, process (command line). CIM: Endpoint.Processes.

**Logic.**

```
| tstats count min(_time) as first_seen values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe","powershell.exe") Processes.process="*temp*.vbe*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| rename Processes.* as *
| eval dest=upper(mvindex(split(dest,"."),0))
| eval user=mvindex(split(user,"\\"),-1)
```

**Schedule.** `15 * * * *` (hourly at :15), searching -70m@m to -10m@m.

**Severity and risk.** high; dest (system) +40, user (user) +40.

**False-positive conditions.**

- Rare: legacy logon scripts that use .vbe from temp folders

**Tuning.**

- Allow-list by exact script hash and parent, never by folder

**Positive test.** Outlook > PowerShell > .vbe in %temp% > wscript on WS-0458 fires (2 rows).

**Negative test.** PowerShell without a .vbe in temp stays silent.

**Owner.** SOC Detection Engineering (Endpoint). **Review by** 2027-02-23.

**When it fires.** Isolate the host with approval, block the stager domain, and check for collection and upload from the same host.

## AA26-D14: Known-bad domain resolved

**Behaviour.** Resolution of an advisory or seizure domain (indicator matching).

**Description.** A host resolves a domain from AA26-281A or the 8 Oct 2026 DOJ seizure (aa26_281a_domains lookup, wildcards allowed). Invalid and expired indicators are skipped; confidence and last-seen date go into the risk message.

**ATT&CK.** T1071.001, T1105

**Data sources and fields.** DNS logs: src, query. CIM: Network_Resolution.

**Logic.**

```
| tstats count from datamodel=Network_Resolution by DNS.src DNS.query
| rename DNS.src as src DNS.query as query
| lookup aa26_281a_domains domain AS query OUTPUT ioc_source confidence last_seen expires
| where isnotnull(ioc_source) AND confidence!="invalid" AND strptime(expires,"%Y-%m-%d")>now()
```

**Schedule.** `15 * * * *` (hourly at :15), searching -70m@m to -10m@m.

**Severity and risk.** medium; src (system) +30.

**False-positive conditions.**

- Security tools and sandboxes resolving indicators
- Sinkholed domains after seizure

**Tuning.**

- Every indicator carries source, confidence, last-seen and expiry columns
- Invalid and expired indicators are skipped; the nine tool file names typed as domains in the STIX are marked invalid

**Positive test.** WS-0458 resolving fym.linkedinns.net (DOJ seizure list, high confidence) fires once.

**Negative test.** The j.citizen intrusion's new infrastructure matches nothing: the behavioural detections caught it.

**Owner.** Cyber Threat Intelligence (indicator lifecycle). **Review by** 2027-01-06.

**When it fires.** Confidence sets the response: high, investigate now; low, retro-hunt and corroborate before acting.

## AA26-D15: Connection to known-bad IP

**Behaviour.** Traffic to an advisory or seizure IP address (indicator matching).

**Description.** Traffic to an IP address from AA26-281A or the 8 Oct 2026 DOJ seizure (aa26_281a_ips lookup). Invalid and expired indicators are skipped; confidence and last-seen date go into the risk message.

**ATT&CK.** T1071.001, T1041

**Data sources and fields.** Firewall or NetFlow: src, dest, bytes_out. CIM: Network_Traffic.

**Logic.**

```
| tstats count sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic by All_Traffic.src All_Traffic.dest
| rename All_Traffic.* as *
| lookup aa26_281a_ips ip AS dest OUTPUT ioc_source confidence last_seen expires
| where isnotnull(ioc_source) AND confidence!="invalid" AND strptime(expires,"%Y-%m-%d")>now()
| eval MB_out=round(bytes_out/1e6,1)
```

**Schedule.** `15 * * * *` (hourly at :15), searching -70m@m to -10m@m.

**Severity and risk.** medium; src (system) +30.

**False-positive conditions.**

- Shared hosting or cloud addresses that have been reassigned

**Tuning.**

- Same lifecycle columns as AA26-D14; 514 of 515 advisory IPs were last seen over 12 months before publication

**Positive test.** WS-0458 uploading 186 MB to 207.148.92.220 fires once (a low-confidence indicator that still matched).

**Negative test.** No other lab host touches the list.

**Owner.** Cyber Threat Intelligence (indicator lifecycle). **Review by** 2027-01-06.

**When it fires.** Corroborate with process and upload evidence on the host before containment.

## AA26-D16: Upload-heavy host

**Behaviour.** Bulk upload from a host that normally downloads.

**Description.** A host sends over 100 MB in an hour and at least five times what it receives.

**ATT&CK.** T1048, T1041

**Data sources and fields.** Firewall or NetFlow: src, bytes_in, bytes_out. CIM: Network_Traffic.

**Logic.**

```
| tstats sum(All_Traffic.bytes_out) as bytes_out sum(All_Traffic.bytes_in) as bytes_in from datamodel=Network_Traffic by All_Traffic.src _time span=1h
| rename All_Traffic.src as src
| where bytes_out > 5*bytes_in AND bytes_out > 100000000
| eval MB_out=round(bytes_out/1e6)
```

**Schedule.** `5 * * * *` (hourly at :05), searching -2h@h to -1h@h.

**Severity and risk.** low; src (system) +20.

**False-positive conditions.**

- Backups, cloud sync, video uploads

**Tuning.**

- Hourly window; over 100 MB and five times the bytes received
- Allow-list backup servers by host

**Positive test.** WS-0417 (5 hours through the tunnel) and WS-0458 (186 MB FishHub upload): 6 rows.

**Negative test.** Workstations' normal download-heavy traffic stays silent.

**Owner.** SOC Detection Engineering (Network). **Review by** 2027-02-23.

**When it fires.** Score only; corroborate with the destination and the process responsible.

## AA26-C01: Integrity Tech behaviour chain

**Behaviour.** Several AA26-281A behaviours on one identity or one host.

**Description.** Risk from the AA26-281A detections adds up to 100 or more across three or more ATT&CK tactics for one user or system.

**ATT&CK.** TA0001-TA0011 (any three tactics)

**Data sources and fields.** ES risk index (Risk data model): risk_object, risk_object_type, calculated_risk_score, ATT&CK tactic. CIM: Risk.

**Logic.**

```
| tstats sum(All_Risk.calculated_risk_score) as risk_score dc(All_Risk.annotations.mitre_attack.mitre_tactic_id) as tactics dc(source) as detections values(source) as sources from datamodel=Risk.All_Risk where source="AA26-281A - *" by All_Risk.risk_object All_Risk.risk_object_type
| rename All_Risk.* as *
| where risk_score>=100 AND tactics>=3
```

**Schedule.** `30 * * * *` (hourly at :30), searching -7d@h to now.

**Severity and risk.** high; raises a finding (severity high).

**False-positive conditions.**

- Shared or service identities that collect risk from many hosts

**Tuning.**

- Scores add up per entity (same risk_object and risk_object_type); there is no cross-entity sum
- Host signals reach a user only when the detection writes risk to the host's assigned owner

**Positive test.** j.citizen (identity) 200 across six tactics, and a.lim 100 across three: 2 findings.

**Negative test.** WS-0417 (host, 80) and 203.0.113.47 (90) stay below 100 on their own.

**Owner.** SOC Manager (finding queue). **Review by** 2027-02-23.

**When it fires.** Follow 07-analyst-investigation-playbook.md: open the finding, read the contributing events, validate the identity, inspect the host, explain, escalate.
