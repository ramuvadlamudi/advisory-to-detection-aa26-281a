#!/usr/bin/env python3
"""Build the AA26-281A detection engineering starter kit (the session's take-home artefact).

  python3 build_starter_kit.py

Writes ../starter-kit/ and ../AA26-281A Detection Engineering Starter Kit.zip. The detection logic is taken from
generate_lab_data.py, so the kit ships exactly the SPL that the lab backtests.
"""

import csv
import json
import re
import shutil
import zipfile
from pathlib import Path

import generate_lab_data as lab

HERE = Path(__file__).resolve().parent
KIT = HERE.parent / "starter-kit"
ZIP = HERE.parent / "AA26-281A Detection Engineering Starter Kit.zip"
EXP = json.loads((HERE / "output" / "expected.json").read_text())
BEHAVIOUR_REVIEW, IOC_REVIEW = "2027-02-23", "2027-01-06"

# Operational metadata for each lab detection, keyed by detection name. Logic, ATT&CK, schedule and risk come from the lab.
META = {
    "Exchange password spray": dict(
        id="AA26-D01", behaviour="EBurst-style password spraying across Exchange interfaces",
        data="Exchange IIS W3C logs: c_ip, cs_username, cs_uri_stem, sc_status (all ten Exchange virtual directories)",
        cim="Web (partial): IIS fields are used directly because CIM Web has no username field",
        severity="low", owner="SOC Detection Engineering (Identity)",
        fp=["Load balancers, reverse proxies or NAT egress presenting many users as one address",
            "Mobile gateways after a password-policy change"],
        tuning=["Ingest the real client address (X-Forwarded-For) where a proxy fronts Exchange",
                "Allow-list known gateways in a lookup with an owner and review date; never by subnet wildcard"],
        positive="Replay of the lab spray (64 mailboxes, 104 failures, 4 interfaces from 203.0.113.47) fires once",
        negative="Monday-morning logon surge and the mobile gateway's routine failures stay silent",
        response="Score only. Check the source's reputation; if it is internal, open a host investigation. Watch AA26-D02 for a success."),
    "Spray source authenticated": dict(
        id="AA26-D02", behaviour="A sprayed account then authenticates from the spraying source",
        data="Exchange IIS W3C logs: c_ip, cs_username, sc_status", cim="Web (partial)",
        severity="high", owner="SOC Detection Engineering (Identity)",
        fp=["A user who mistyped once behind the same NAT as a spray (rare; check the user agent)"],
        tuning=["Requires the account to be among the sprayed accounts and the success to come from the same source in the same 30 minutes"],
        positive="j.citizen: failed once from 203.0.113.47 during the spray, then 200s from the same address: fires once",
        negative="Users who succeed from the gateway during a spray without first failing from it stay silent",
        response="Treat the account as compromised: reset the password, revoke sessions and tokens, confirm MFA on every Exchange protocol, and review mailbox activity since the success."),
    "Scanning on advisory ports": dict(
        id="AA26-D03", behaviour="Reconnaissance against the advisory's ports (21, 22, 53, 80, 443, 1080)",
        data="Firewall or NetFlow: src, dest, dest_port", cim="Network_Traffic",
        severity="low", owner="SOC Detection Engineering (Network)",
        fp=["Approved vulnerability scanners and monitoring", "Internet background scanning"],
        tuning=["aa26_approved_scanners lookup (scanner, owner, reason)", "Score external sources low; investigate internal sources"],
        positive="203.0.113.47 (41 hosts, 6 ports) fires; so does the internet background scanner, at low score",
        negative="The internal vulnerability scanner 10.20.0.50 is excluded by the lookup",
        response="Score only. Internal source scanning: open a host investigation."),
    "Web enumeration burst": dict(
        id="AA26-D04", behaviour="dirsearch-style enumeration of .php and .asp pages",
        data="Web server or WAF logs: src, uri_path, status, http_user_agent", cim="Web",
        severity="low", owner="SOC Detection Engineering (Network)",
        fp=["Authorised web application scans and penetration tests"],
        tuning=["Allow-list scheduled scanners by source and window", "Raise the path threshold for very large sites"],
        positive="203.0.113.47's 450 missing script paths in ten minutes fire once",
        negative="Normal 404s from broken links stay silent",
        response="Score only. Correlate with exploitation attempts against the same server."),
    "Exploit attempts for advisory CVEs": dict(
        id="AA26-D17", behaviour="One source trying several of the advisory's exploited CVEs (2014-2023) and XSS payloads against web servers",
        data="Web server, reverse proxy or WAF logs: c_ip, cs_method, cs_uri_stem, cs_uri_query, cs_User_Agent, sc_status",
        cim="Web (partial): the query string and user agent are used directly", severity="medium",
        owner="SOC Detection Engineering (Network)",
        fp=["Authorised vulnerability scanners and penetration tests", "Security research crawlers"],
        tuning=["aa26_approved_scanners lookup (scanner, owner, reason), never a user-agent allow-list",
                "Three or more distinct techniques from one source; a single probe is background noise",
                "FTP, DNS and VPN appliance exploits never reach a web log: cover them with inventory and appliance logs"],
        positive="203.0.113.47: 7 techniques (six advisory CVEs plus XSS), 15 requests, 2 answered: fires once",
        negative="The approved scanner 10.20.0.50 (4 techniques) and a one-technique background probe stay silent",
        response="Score the source. Check which requests were answered (status below 400) and patch or fix those pages first; "
                 "confirm the vulnerable products in the inventory (AA26 31)."),
    "SoftEther masquerading as Windows binary": dict(
        id="AA26-D05", behaviour="SoftEther VPN renamed as a Windows process for persistence (the flagship walkthrough)",
        data="Sysmon event 1 or EDR process telemetry: dest, process_name, process_path, original_file_name, parent_process_name",
        cim="Endpoint.Processes (needs original_file_name)", severity="high", owner="SOC Detection Engineering (Endpoint)",
        fp=["Approved SoftEther installs (IT remote access)", "Software that legitimately ships its own conhost-named helper"],
        tuning=["aa26_approved_remote_access lookup: host plus exact path, with approver and review date",
                "Never allow-list by process name or by vendor alone"],
        positive="WS-0417: conhost.exe in C:\\ProgramData\\USOShared with original file name vpnbridge.exe fires once",
        negative="WS-0404's approved SoftEther VPN Client in Program Files and every real conhost.exe in System32 stay silent",
        response="Corroborate with AA26-D06 and AA26-D07 on the same host, check the owner's recent authentication, then request approval to isolate the host. Block the SoftEther dynamic DNS name and hunt the same hash across the fleet."),
    "SoftEther dynamic DNS": dict(
        id="AA26-D06", behaviour="SoftEther reaching its server through dynamic DNS or VPN Azure",
        data="DNS logs: src, query", cim="Network_Resolution", severity="medium", owner="SOC Detection Engineering (Network)",
        fp=["Approved SoftEther users who rely on its dynamic DNS"],
        tuning=["Exclude hosts in the approved remote-access register"],
        positive="WS-0417 resolving vpn583920174.softether.net (18 lookups) fires once",
        negative="Hosts without SoftEther never resolve these names",
        response="Corroborate with AA26-D05 on the same host."),
    "Autostart service outside system paths": dict(
        id="AA26-D07", behaviour="New auto-start service whose binary sits outside System32 and Program Files",
        data="Windows System log event 7045: Computer, ServiceName, ImagePath, StartType", cim="Change (Endpoint.Services where mapped)",
        severity="medium", owner="SOC Detection Engineering (Endpoint)",
        fp=["Vendor updaters installed in ProgramData (for example the lab's Lenovo service)"],
        tuning=["Allow-list by host role, service name and exact path, with an owner"],
        positive="'Console Host Service' running C:\\ProgramData\\USOShared\\conhost.exe on WS-0417 fires",
        negative="The approved SoftEther client's service (Program Files) stays silent",
        response="Check the binary's original file name and signer; corroborate with process and network evidence."),
    "EWS volume far above normal": dict(
        id="AA26-D08", behaviour="Scripted mailbox collection through Exchange Web Services (Curlc4.txt)",
        data="Exchange IIS W3C logs: cs_username, c_ip, cs_uri_stem, cs_User_Agent, sc_status", cim="Web (partial)",
        severity="high", owner="SOC Detection Engineering (Identity)",
        fp=["Mailbox migrations, eDiscovery exports, backup service accounts"],
        tuning=["Per-user baseline: ten times the user's own hourly median and at least 500 calls",
                "Skip users with fewer than 24 active hours, because a median of two or three hours is not a baseline",
                "Validate across the full retention, including low-volume users"],
        positive="j.citizen: 2,400 EWS calls in one hour from 203.0.113.52 with no user agent (typical 3) fires once",
        negative="svc-crm's steady 160 calls an hour stays silent",
        response="Identify the client and source; if not a known integration, revoke the user's sessions and scope what was read."),
    "Unapproved app reading many mailboxes": dict(
        id="AA26-D09", behaviour="office-cli style collection through a Microsoft 365 app registration",
        data="Microsoft 365 unified audit log, MailItemsAccessed: AppId, MailboxOwnerUPN, ClientIPAddress", cim="None (vendor fields)",
        severity="high", owner="SOC Detection Engineering (Cloud)",
        fp=["A new approved integration not yet in the register"],
        tuning=["approved_mail_apps lookup with owner", "Requires MailItemsAccessed enabled and retained for every mailbox"],
        positive="The rogue app owned by j.citizen reading 7 mailboxes fires once",
        negative="The approved backup app reading every audited mailbox stays silent",
        response="Disable the app's credentials, review its consent and owner, and scope the mailboxes read."),
    "New app secret or consent": dict(
        id="AA26-D10", behaviour="Credentials added to an application, or consent granted",
        data="Microsoft 365 / Entra audit: UserId, Operation, ObjectId", cim="Change",
        severity="medium", owner="SOC Detection Engineering (Cloud)",
        fp=["Routine secret rotation by the app owner"],
        tuning=["Correlate with change records; alert on apps with mail permissions first"],
        positive="j.citizen adding a secret to the rogue app the night before collection fires once",
        negative="Scheduled rotation by the integration team, with a change record, is closed as expected",
        response="Confirm with the app owner; if unexpected, remove the credential and review the app's permissions."),
    "DCSync by non-machine account": dict(
        id="AA26-D11", behaviour="DCSync with DC.exe or secretsdump (directory replication by a non-DC account)",
        data="Security event 4662 on domain controllers: SubjectUserName, Properties, AccessMask",
        cim="None (vendor fields)", severity="critical", owner="SOC Detection Engineering (Identity)",
        fp=["Microsoft Entra Connect (MSOL_ accounts)", "dcdiag and other replication tests"],
        tuning=["Allow-list the Entra Connect account by name"],
        prereq=("Needs two settings, not one: (1) Advanced Audit Policy, DS Access > Audit Directory Service Access (Success) on domain "
                "controllers; (2) a SACL on the domain root auditing Success for Everyone on the three control-access rights: "
                "Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes In Filtered Set. "
                "Without the SACL, 4662 is never written for replication."),
        positive="Cannot be tested in the lab: no 4662 events, because the SACL was never set. Record it as a gap",
        negative="Domain controller computer accounts (ending in $) replicating normally stay silent",
        response="Treat every domain credential as exposed: contain the account, reset krbtgt twice, and plan eviction."),
    "Advisory decoy file names": dict(
        id="AA26-D12", behaviour="Mail dumps and tools staged under the advisory's decoy names",
        data="Sysmon event 11 or EDR file telemetry: dest, file_path, file_name", cim="Endpoint.Filesystem",
        severity="medium", owner="SOC Detection Engineering (Endpoint)",
        fp=["Web deployments that legitimately ship Css.js or similar names"],
        tuning=["Exclude by host role and path (for example the web root on WEB01)"],
        positive="The staged files on WS-0417 fire", negative="Ordinary image and script files with other names stay silent",
        response="Check the file's size, type and creator; a large 'image' or 'script' is likely an archive."),
    "FishHub-style script stager": dict(
        id="AA26-D13", behaviour="FishHub phishing stager: a .vbe saved to %temp% and run by a script host",
        data="Sysmon event 1 or EDR: dest, user, parent_process_name, process_name, process (command line)", cim="Endpoint.Processes",
        severity="high", owner="SOC Detection Engineering (Endpoint)",
        fp=["Rare: legacy logon scripts that use .vbe from temp folders"],
        tuning=["Allow-list by exact script hash and parent, never by folder"],
        positive="Outlook > PowerShell > .vbe in %temp% > wscript on WS-0458 fires (2 rows)",
        negative="PowerShell without a .vbe in temp stays silent",
        response="Isolate the host with approval, block the stager domain, and check for collection and upload from the same host."),
    "Known-bad domain resolved": dict(
        id="AA26-D14", behaviour="Resolution of an advisory or seizure domain (indicator matching)",
        data="DNS logs: src, query", cim="Network_Resolution", severity="medium", owner="Cyber Threat Intelligence (indicator lifecycle)",
        fp=["Security tools and sandboxes resolving indicators", "Sinkholed domains after seizure"],
        tuning=["Every indicator carries source, confidence, last-seen and expiry columns",
                "Invalid and expired indicators are skipped; the nine tool file names typed as domains in the STIX are marked invalid"],
        positive="WS-0458 resolving fym.linkedinns.net (DOJ seizure list, high confidence) fires once",
        negative="The j.citizen intrusion's new infrastructure matches nothing: the behavioural detections caught it",
        response="Confidence sets the response: high, investigate now; low, retro-hunt and corroborate before acting."),
    "Connection to known-bad IP": dict(
        id="AA26-D15", behaviour="Traffic to an advisory or seizure IP address (indicator matching)",
        data="Firewall or NetFlow: src, dest, bytes_out", cim="Network_Traffic", severity="medium",
        owner="Cyber Threat Intelligence (indicator lifecycle)",
        fp=["Shared hosting or cloud addresses that have been reassigned"],
        tuning=["Same lifecycle columns as AA26-D14; 514 of 515 advisory IPs were last seen over 12 months before publication"],
        positive="WS-0458 uploading 186 MB to 207.148.92.220 fires once (a low-confidence indicator that still matched)",
        negative="No other lab host touches the list",
        response="Corroborate with process and upload evidence on the host before containment."),
    "Upload-heavy host": dict(
        id="AA26-D16", behaviour="Bulk upload from a host that normally downloads",
        data="Firewall or NetFlow: src, bytes_in, bytes_out", cim="Network_Traffic", severity="low",
        owner="SOC Detection Engineering (Network)",
        fp=["Backups, cloud sync, video uploads"],
        tuning=["Hourly window; over 100 MB and five times the bytes received", "Allow-list backup servers by host"],
        positive="WS-0417 (5 hours through the tunnel) and WS-0458 (186 MB FishHub upload): 6 rows",
        negative="Workstations' normal download-heavy traffic stays silent",
        response="Score only; corroborate with the destination and the process responsible."),
}
FINDING_META = dict(
    id="AA26-C01", behaviour="Several AA26-281A behaviours on one identity or one host",
    data="ES risk index (Risk data model): risk_object, risk_object_type, calculated_risk_score, ATT&CK tactic", cim="Risk",
    severity="high", owner="SOC Manager (finding queue)",
    fp=["Shared or service identities that collect risk from many hosts"],
    tuning=["Scores add up per entity (same risk_object and risk_object_type); there is no cross-entity sum",
            "Host signals reach a user only when the detection writes risk to the host's assigned owner"],
    positive="j.citizen (identity) 200 across six tactics, and a.lim 100 across three: 2 findings",
    negative="WS-0417 (host, 80) and 203.0.113.47 (90) stay below 100 on their own",
    response="Follow 07-analyst-investigation-playbook.md: open the finding, read the contributing events, validate the identity, inspect the host, explain, escalate.")

SCHEDULE_TEXT = {"*/30 * * * *": "every 30 minutes", "5 * * * *": "hourly at :05", "10 * * * *": "hourly at :10",
                 "15 * * * *": "hourly at :15", "20 * * * *": "hourly at :20", "25 * * * *": "hourly at :25", "30 * * * *": "hourly at :30"}


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def entries():
    out = []
    for d in lab.DETECTIONS:
        m = META[d["name"]]
        out.append(dict(m, name=d["name"], attack=d["mitre"], spl=d["search"], cron=d["cron"],
                        window=f"{d.get('earliest', '-70m@m')} to {d.get('latest', '-10m@m')}",
                        risk=", ".join(f"{f} ({t}) +{s}" for f, t, s in d["risk"]),
                        desc=d["desc"], backtest=EXP["backtest"][d["name"]],
                        review=IOC_REVIEW if m["id"] in ("AA26-D14", "AA26-D15") else BEHAVIOUR_REVIEW))
    t = lab.THRESHOLD
    out.append(dict(FINDING_META, name=t["name"], attack=["TA0001-TA0011 (any three tactics)"], spl=t["search"], cron="30 * * * *",
                    window="-7d@h to now", risk="raises a finding (severity high)", desc=t["desc"],
                    backtest=EXP["backtest"][t["name"]], review=BEHAVIOUR_REVIEW))
    return out


def yaml_value(v, indent=2):
    pad = " " * indent
    if isinstance(v, list):
        return "\n" + "\n".join(f"{pad}- {json.dumps(x, ensure_ascii=False)}" for x in v)
    if isinstance(v, str) and "\n" in v:
        return " |\n" + "\n".join(pad + line for line in v.split("\n"))
    return " " + json.dumps(v, ensure_ascii=False)


def write_detections(es):
    folder = KIT / "detections"
    folder.mkdir()
    for e in es:
        fields = [("id", e["id"]), ("name", f"AA26-281A - {e['name']} - Rule"), ("behaviour", e["behaviour"]),
                  ("description", e["desc"]), ("mitre_attack", e["attack"]), ("data_sources", e["data"]), ("cim", e["cim"]),
                  ("prerequisites", e.get("prereq", "None beyond the data sources")), ("search", e["spl"]),
                  ("schedule", e["cron"]), ("search_window", e["window"]), ("severity", e["severity"]), ("risk", e["risk"]),
                  ("false_positives", e["fp"]), ("tuning", e["tuning"]),
                  ("tests", None), ("owner", e["owner"]), ("review_date", e["review"]), ("response", e["response"]),
                  ("lab_backtest_rows", e["backtest"])]
        lines = [f"# {e['id']}: generated from the AA26-281A lab. Adapt names, indexes and thresholds to your environment."]
        for k, v in fields:
            if k == "tests":
                lines += ["tests:", f"  positive:{yaml_value(e['positive'], 4)}", f"  negative:{yaml_value(e['negative'], 4)}"]
            else:
                lines.append(f"{k}:{yaml_value(v)}")
        (folder / f"{e['id']}-{slug(e['name'])}.yml").write_text("\n".join(lines) + "\n")


def write_catalogue(es):
    with (KIT / "02-detection-catalogue.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "name", "behaviour", "mitre_attack", "data_sources", "severity", "risk", "schedule", "false_positives",
                    "positive_test", "negative_test", "owner", "review_date", "response", "lab_backtest_rows"])
        for e in es:
            w.writerow([e["id"], e["name"], e["behaviour"], " ".join(e["attack"]), e["data"], e["severity"], e["risk"], e["cron"],
                        "; ".join(e["fp"]), e["positive"], e["negative"], e["owner"], e["review"], e["response"], e["backtest"]])
    md = ["# AA26-281A detection catalogue", "",
          f"{len(es) - 1} behaviour detections and 1 correlation finding. Each behaviour detection writes risk (an intermediate finding) "
          "to the user or system involved; AA26-C01 raises the finding an analyst works. All were backtested on the synthetic lab: "
          "16 fire on the attack, and AA26-D11 (DCSync) correctly returns nothing because the audit SACL is missing. That is a gap, "
          "not a pass.", "",
          "| ID | Detection | ATT&CK | Severity | Risk | Owner | Review | Lab rows |", "|---|---|---|---|---|---|---|---|"]
    for e in es:
        md.append(f"| {e['id']} | {e['name']} | {', '.join(e['attack'])} | {e['severity']} | {e['risk']} | {e['owner']} | {e['review']} | {e['backtest']} |")
    for e in es:
        md += ["", f"## {e['id']}: {e['name']}", "", f"**Behaviour.** {e['behaviour']}.", "", f"**Description.** {e['desc']}", "",
               f"**ATT&CK.** {', '.join(e['attack'])}", "", f"**Data sources and fields.** {e['data']}. CIM: {e['cim']}.", ""]
        if e.get("prereq"):
            md += [f"**Prerequisite.** {e['prereq']}", ""]
        md += ["**Logic.**", "", "```", e["spl"], "```", "",
               f"**Schedule.** `{e['cron']}` ({SCHEDULE_TEXT.get(e['cron'], e['cron'])}), searching {e['window']}.", "",
               f"**Severity and risk.** {e['severity']}; {e['risk']}.", "",
               "**False-positive conditions.**", ""] + [f"- {x}" for x in e["fp"]] + ["", "**Tuning.**", ""] + \
              [f"- {x}" for x in e["tuning"]] + ["", f"**Positive test.** {e['positive']}.", "", f"**Negative test.** {e['negative']}.", "",
               f"**Owner.** {e['owner']}. **Review by** {e['review']}.", "", f"**When it fires.** {e['response']}"]
    (KIT / "02-detection-catalogue.md").write_text("\n".join(md) + "\n")


def write_spl():
    folder = KIT / "spl"
    folder.mkdir()
    for s in lab.SEARCHES:
        (folder / f"{slug(s['name'])}.spl").write_text(f"``` {s['name']}: {s['title']} ```\n{s['spl']}\n")


def write_readiness():
    rows = [("Scanning", 1, 1.0, "tested", "Firewall covers every internet-facing address"),
            ("Web enumeration", 1, 1.0, "tested", "IIS on both web servers"),
            ("Exchange spraying", 2, 1.0, "tested", "All ten Exchange interfaces in IIS"),
            ("SoftEther persistence", 3, 0.5, "tested", "Sysmon on Windows only; Linux installs invisible"),
            ("Mail collection", 3, 0.6, "tested", "EWS fully; MailItemsAccessed on 30 of 120 mailboxes"),
            ("Staging and exfiltration", 2, 0.5, "tested", "EDR files and firewall; no web proxy"),
            ("DCSync", 3, 0.0, "none", "Rule deployed but blind: no 4662 events (no SACL)")]
    with (KIT / "08-readiness-calculator.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["behaviour", "weight_1_to_3", "coverage_0_to_1", "maturity", "evidence"])
        w.writerows(rows)
    calc = '''#!/usr/bin/env python3
"""Detection readiness for one advisory: coverage (can we see it?) and confidence (would it work?).

  python3 readiness.py 08-readiness-calculator.csv
"""
import csv
import sys

STATES = ["none", "telemetry", "implemented", "tested", "effective"]
rows = list(csv.DictReader(open(sys.argv[1] if len(sys.argv) > 1 else "08-readiness-calculator.csv")))
w = [float(r["weight_1_to_3"]) for r in rows]
v = [float(r["coverage_0_to_1"]) for r in rows]
weighted = 100 * sum(a * b for a, b in zip(w, v)) / sum(w)
full = sum(1 for r in rows if float(r["coverage_0_to_1"]) == 1 and r["maturity"] in ("tested", "effective"))
print(f"Behaviours in scope (the denominator): {len(rows)}")
print(f"Detection readiness = validated / relevant = {full} of {len(rows)} = {100 * full / len(rows):.0f}%")
print(f"Weighted coverage = sum(w*v) / sum(w) = {sum(a * b for a, b in zip(w, v)):.1f} / {sum(w):.0f} = {weighted:.0f}%")
for s in STATES[1:]:
    n = sum(1 for r in rows if STATES.index(r["maturity"]) >= STATES.index(s))
    print(f"Confidence: {n} of {len(rows)} at '{s}' or better")
'''
    (KIT / "readiness.py").write_text(calc)
    w = sum(r[1] for r in rows)
    wv = sum(r[1] * r[2] for r in rows)
    return rows, w, wv


def write_docs(es, readiness):
    rows, w, wv = readiness
    d = {}
    d["README.md"] = f"""# AA26-281A detection engineering starter kit

Take-home material from "From Advisory to Detection: Hunting Integrity Tech (AA26-281A) in Splunk", ADF Cyber Skills
Challenge 2026. The method is vendor-independent; the SPL is Splunk, written against CIM data models where possible so the logic
ports to other SIEMs.

| File | Use it to |
|---|---|
| `00-threat-to-detection-playbook.md` | Follow the five steps from a new advisory to validated detections and action |
| `01-hypothesis-worksheet.md` | Turn one advisory behaviour into a testable detection (blank template plus the SoftEther example) |
| `02-detection-catalogue.md` / `.csv` | See all {len(es) - 1} behaviour detections and the correlation finding, with owner, tests and response |
| `detections/*.yml` | Manage each detection as code: ID, logic, risk, false positives, tests, owner, review date |
| `03-data-requirements.md` | Check the telemetry, fields and audit settings each behaviour needs |
| `04-validation-test-plan.md` | Prove each detection with a positive, a negative and a gap test |
| `05-tuning-guide.md` | Remove false positives without weakening the logic |
| `06-deployment-checklist.md` | Move a detection from search to production |
| `07-analyst-investigation-playbook.md` | Work a finding from open to escalation |
| `08-readiness-calculator.csv`, `readiness.py` | Report coverage and confidence for one advisory |
| `09-ai-prompts.md` | Use AI for the slow parts, and check its work |
| `10-exercise.md` | Take the 48-hour challenge on a new advisory |
| `11-demo-runbook.md` | Rerun the session walkthrough: what each screenshot shows, pre-flight checks and how to recapture |
| `app/integrity_tech_detections.tgz` | Install the Integrity Tech Detections app: 18 detections, lookups, catalogue, readiness and 10 dashboards (storyline, exposure and a Defender action centre) (lab first; tune the macros and lookups) |
| `spl/` | Every demo search from the session |

Lab only: the lab data is synthetic (fictional `lab.example`, documentation IP ranges). Never test against production, and never
exploit real systems.
"""
    d["01-hypothesis-worksheet.md"] = """# Hypothesis worksheet: the five-part detection template

Use one sheet per behaviour. If you cannot fill in part 3, you have found a gap: write it down, because that is a result.

| Part | Question | Your answer |
|---|---|---|
| 1. Adversary behaviour | What did the advisory say they did, in one sentence? | |
| 2. Observable evidence | If they did it here, what would be different from normal? | |
| 3. Required telemetry | Which log records it, with which fields? Do we have it, and for how long? | |
| 4. Detection logic | Which conditions, together, separate malicious from legitimate? | |
| 5. Validation | What proves it fires (positive), stays quiet (negative), and what can't we test (gap)? | |

Then write the hypothesis in one sentence: "A [entity] that [evidence], [in context], may indicate [behaviour]."

## Worked example: SoftEther renamed as a Windows process

**Intelligence.** AA26-281A: the actors install SoftEther VPN, rename it conhost.exe or dllhost.exe, and set it to reconnect at
startup. Endpoint tools are less likely to flag it, because SoftEther is legitimate software.

**The detection engineer's questions.**

| Question | Answer |
|---|---|
| What makes this suspicious? | A Windows process name on a binary that is really a VPN; a long-lived tunnel; persistence at boot |
| What does legitimate SoftEther use look like? | Installed in Program Files under its own names (vpnclient_x64.exe), approved by IT, on a few admin hosts |
| Which fields distinguish legitimate from malicious? | process_name vs original_file_name; process_path; parent process; service ImagePath; DNS queries |
| Which telemetry captures it? | Sysmon event 1 or EDR (original file name), Windows 7045 (service), DNS logs; Linux needs auditd or Sysmon for Linux |
| What other evidence raises confidence? | SoftEther dynamic DNS from the same host; unusual authentication by the host's owner; upload-heavy traffic |

**Hypothesis.** A process running under a legitimate Windows name, outside its expected path, with VPN-related binary metadata
and suspicious DNS activity, may indicate unauthorised VPN persistence.

**Logic.** Correlate four things on one host: process metadata (name vs original file name), execution path, service installation,
and DNS. Each search runs separately and writes its own signal; a host with two or more signals is a finding (lab search AA26 22).

**Validation.**

| Test | Lab data | Expected |
|---|---|---|
| Malicious simulation | conhost.exe in C:\\ProgramData\\USOShared, original file name vpnbridge.exe, 7045 service, softether.net DNS (WS-0417) | Fires, three signals |
| Legitimate SoftEther | vpnclient_x64.exe in Program Files, approved by change CHG-2291 (WS-0404) | One signal before tuning; silent after |
| Normal Windows activity | Thousands of real conhost.exe and dllhost.exe starts from System32 | Silent |
| Gap | SoftEther installed on Linux with curl or wget | Cannot test: no Linux process telemetry |
"""
    sources = [("Firewall or NetFlow", "src, dest, dest_port, bytes_in, bytes_out", "Network_Traffic", "Scanning, upload volume, known-bad IPs",
                "Log allowed and denied; include byte counts"),
               ("DNS resolver logs", "src, query", "Network_Resolution", "SoftEther dynamic DNS, known-bad domains",
                "Log at the resolver your clients use, not only at the edge"),
               ("Exchange IIS (W3C)", "c_ip, cs_username, cs_uri_stem, sc_status, cs_User_Agent", "Web (partial)",
                "Spraying, EWS collection", "Enable cs-username, c-ip and User-Agent; all ten virtual directories; real client IP behind proxies"),
               ("Windows Security", "4625, 4771 (failed logon); 4662 (directory access)", "Authentication; none for 4662",
                "Spraying (secondary), DCSync", "For 4662: Audit Directory Service Access (Success) on DCs, plus the replication-rights SACL on the domain root"),
               ("Windows System", "7045: ServiceName, ImagePath, StartType", "Change", "Persistence through services", "Collected by default; forward it"),
               ("Sysmon or EDR", "Process: process_name, process_path, original_file_name, parent; File: file_path, file_name",
                "Endpoint.Processes, Endpoint.Filesystem", "SoftEther masquerading, FishHub stager, decoy files",
                "Sysmon event 1 and 11 with OriginalFileName; deploy to servers and, for Linux, Sysmon for Linux or auditd"),
               ("Microsoft 365 unified audit", "MailItemsAccessed: AppId, MailboxOwnerUPN; app credential and consent operations",
                "None; Change for app changes", "App-based mail collection, new secrets", "Enable MailItemsAccessed for every mailbox and keep it at least 180 days")]
    md = ["# Data requirements", "", "Check each source with the discovery searches (spl/aa26-01, spl/aa26-02) before trusting any detection that uses it.", "",
          "| Source | Fields | CIM data model | Behaviours | Configuration that matters |", "|---|---|---|---|---|"]
    md += [f"| {a} | {b} | {c} | {e} | {f} |" for a, b, c, e, f in sources]
    md += ["", "## Directory replication auditing (DCSync)", "",
           "Event 4662 is written for replication only when both are in place:", "",
           "1. Advanced Audit Policy on domain controllers: DS Access > Audit Directory Service Access, Success.",
           "2. A SACL on the domain naming context root (for example DC=lab,DC=example) auditing Success for Everyone on the extended "
           "rights Replicating Directory Changes (1131f6aa-…), Replicating Directory Changes All (1131f6ad-…) and Replicating "
           "Directory Changes In Filtered Set (89e95b76-…).", "",
           "Test it safely: run a replication check from a domain controller and confirm a 4662 with those GUIDs arrives in the SIEM. "
           "Expect volume from DC computer accounts (ending in $); the detection excludes them.", ""]
    d["03-data-requirements.md"] = "\n".join(md)
    md = ["# Validation test plan", "",
          "Every detection gets three outcomes. Positive: it fires on controlled, harmless test activity. Negative: it stays quiet during "
          "normal work. Gap: it cannot be tested because telemetry is missing, and that is recorded, not hidden.", "",
          "Use replayed synthetic logs (this lab), Splunk Attack Range or Atomic Red Team in an isolated lab. Never exploit real systems.", "",
          "| ID | Positive test | Negative test | Lab result |", "|---|---|---|---|"]
    md += [f"| {e['id']} | {e['positive']} | {e['negative']} | {e['backtest']} rows |" for e in es]
    md += ["", "Re-run after every change to data sources, add-ons or thresholds, and at each review date. `labctl.py backtest` automates it for the lab."]
    d["04-validation-test-plan.md"] = "\n".join(md)
    d["05-tuning-guide.md"] = """# Tuning guide

Tune with registers, not by weakening the logic.

1. **Find the false positive's reason.** The SoftEther example: WS-0404 runs SoftEther legitimately, approved by IT.
2. **Record the exception as data.** A lookup row with the host, the exact path or identifier, who approved it, and a review date
   (`aa26_approved_remote_access.csv`, `aa26_approved_scanners.csv`, `approved_mail_apps.csv`).
3. **Exclude narrowly.** Host plus path, app ID, or source address. Never by process name, vendor, subnet wildcard or user group.
4. **Prefer baselines to fixed thresholds** where normal varies per entity: EWS calls against each user's own median, with a
   minimum history (24 active hours) so a new or quiet user doesn't produce a meaningless median.
5. **Score, don't page, the weak signals.** Scanning and upload volume add risk; the finding fires when signals add up on one entity.
6. **Re-run the backtest** after every tuning change: the positive test must still fire.
7. **Expire exceptions.** Review dates apply to allow-lists and indicators alike.

| Before tuning | After tuning |
|---|---|
| SoftEther process search: 2 hosts (WS-0417 malicious, WS-0404 approved) | 1 host (WS-0417); WS-0404 removed by the register |
| Spray success: any 200 from a spraying source | Only accounts that were sprayed and then succeeded from the same source |
| EWS volume: every user, including two-hour histories | Users with at least 24 active hours |
"""
    d["06-deployment-checklist.md"] = """# Deployment checklist

Before a detection is enabled in production:

- [ ] Unique ID and name (for example AA26-D05) and a one-line behaviour statement
- [ ] ATT&CK techniques and the advisory section it comes from
- [ ] Data sources confirmed present, with the fields populated (fieldsummary) and retention known
- [ ] Logic reviewed by a second engineer; uses CIM fields where possible
- [ ] Positive, negative and gap tests run and recorded
- [ ] False-positive conditions documented; exceptions held in a lookup with owner and review date
- [ ] Severity and risk score set; risk written to the right entity (user, system, or both)
- [ ] Schedule and search window set so consecutive runs neither overlap nor leave gaps; suppression where a baseline repeats
- [ ] Owner named (a team, not a person who might leave)
- [ ] Response instructions written: what the analyst checks first, and who approves containment
- [ ] Review date set (quarterly for behaviours; at expiry for indicators)
- [ ] Stored as code (YAML plus SPL) in version control; changes go through review
- [ ] Added to the readiness calculator; coverage and maturity updated
- [ ] After go-live: watch the first two weeks' volume, then record whether it found anything real ("operationally effective")
"""
    d["07-analyst-investigation-playbook.md"] = """# Analyst investigation playbook: a behaviour-chain finding

Lab example: finding "Integrity Tech behaviour chain on j.citizen", risk 200 across six ATT&CK tactics.

| Step | Do this | Lab search | What you should conclude |
|---|---|---|---|
| 1. Open the finding | Read the entity, its type, the score, the tactics and the contributing detections | AA26 14 | It is about one identity, j.citizen; the 200 is identity risk only |
| 2. Examine contributing events | List every risk event in time order, with its message and threat object | AA26 24 | Scan, spray, spray success, SoftEther, dynamic DNS, EWS collection over three days |
| 3. Validate the identity | Where has the account signed in from, and with which clients? Compare with known addresses | AA26 25 | Two addresses she has never used: 203.0.113.47 (spray source) and 203.0.113.52 (2,400 EWS calls, no user agent) |
| 4. Inspect the host | What is running on her workstation that shouldn't be? | AA26 22, AA26 19 | WS-0417 has three SoftEther signals; the pivot shows how it arrived |
| 5. Add context | Who is she, how critical is the host? | AA26 26 | Executive officer, high priority identity and host |
| 6. Explain | Write two sentences a commander can act on | | "A sprayed password gave an outside party access to j.citizen's mailbox; they installed a disguised VPN on her workstation and bulk-read her mail through EWS." |
| 7. Escalate | Request approval for containment; hand to incident response | | Disable the account, revoke sessions and app secrets, isolate WS-0417, block the SoftEther DNS name, report to ASD's ACSC |

What would change the conclusion: a known travel record for 203.0.113.47, an approved migration tool for the EWS volume, or an
IT change for the VPN. Check each before escalating; record that you did.
"""
    rws = "\n".join(f"| {b} | {wt} | {cv} | {m} | {ev} |" for b, wt, cv, m, ev in rows)
    d["08-readiness-method.md"] = f"""# Detection readiness: coverage and confidence

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
{rws}

Unweighted: 3 of 7 behaviours fully covered and tested = 43%. It treats scanning and DCSync as equally important and partial
coverage as zero.

Weighted coverage: {wv:.1f} / {w} = {100 * wv / w:.0f}%. Confidence: 6 of 7 tested in the lab; none yet operationally effective.

Fastest gains: the replication audit SACL (DCSync from 0 to 1, +20 points), MailItemsAccessed for every mailbox, Sysmon for Linux.
"""
    d["09-ai-prompts.md"] = """# AI prompts for the advisory-to-detection workflow

AI drafts; people validate. Label everything AI produced, and test it against real data before it becomes a detection.

## Stage 1: give AI the advisory

> From this advisory, list each adversary behaviour as one sentence. For each, give the ATT&CK technique, the telemetry and fields
> that would record it, and one testable hypothesis in the form "A [entity] that [evidence], [in context], may indicate [behaviour]."
> Quote the advisory text that supports each behaviour. Say "not stated" rather than guessing.

Check: every behaviour has a quote; no claims the advisory doesn't make (AA26-281A does not attribute AI use).

## Stage 2: connect it to the SIEM

> Using only searches you run, list the indexes, sourcetypes and retention available, and the populated fields in each source
> relevant to these hypotheses. Then write SPL for hypothesis N using only field names you have seen in the results.

Check: run the SPL yourself. Zero results can mean "no attack" or "wrong fields": test it on known-bad data first.

## Stage 3: challenge it

> Which of these behaviours can this environment not detect, and why? For each, name the missing telemetry or configuration,
> the fix, and how we would test the fix.

Check: compare each claim with a search result. In the lab, a typical first draft assumed `src_ip` and `action=failure`; the IIS
data has `c_ip`, and `action` is only `allowed` or `blocked`, so the draft returned nothing. `fieldsummary` and
`stats count by action` would have shown both in seconds.

## Five questions every AI finding must answer

1. What evidence supports it?
2. Which fields and behaviours contributed?
3. How confident is it, and why?
4. What evidence is missing?
5. What should the analyst do next?
"""
    d["10-exercise.md"] = """# Your first 48 hours: one advisory, one hypothesis, one gap

Within 48 hours of returning to your organisation, take one recent threat advisory and operationalise at least one detection
hypothesis using this method. Not every advisory can be operationalised in 48 hours: the goal is to start, and to make the gaps
visible.

1. **One advisory.** Name it and the behaviour you chose. Quote the sentence.
2. **One hypothesis.** Fill in the five-part worksheet (01-hypothesis-worksheet.md).
3. **Identify the telemetry.** Run the discovery searches. Does the data exist, with the fields populated, for long enough?
4. **Document one gap.** Something you could not see or test, why, the fix, and who owns it.

Bring it back to your team as one page. A documented gap is a successful outcome.

| Advisory | Behaviour | Hypothesis | Telemetry and fields | Present? | Gap, fix, owner |
|---|---|---|---|---|---|
| | | | | | |
"""
    d["00-threat-to-detection-playbook.md"] = PLAYBOOK
    d["11-demo-runbook.md"] = (HERE / "DEMO_RUNBOOK.md").read_text()
    for name, text in d.items():
        (KIT / name).write_text(text)


PLAYBOOK = """# The threat-to-detection playbook

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
"""


def main():
    if KIT.exists():
        shutil.rmtree(KIT)
    KIT.mkdir()
    es = entries()
    write_detections(es)
    write_catalogue(es)
    write_spl()
    readiness = write_readiness()
    write_docs(es, readiness)
    (KIT / "app").mkdir()
    shutil.copy2(HERE / "dist" / "integrity_tech_detections.tgz", KIT / "app")
    with zipfile.ZipFile(ZIP, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(KIT.rglob("*")):
            if p.is_file():
                z.write(p, Path("AA26-281A-starter-kit") / p.relative_to(KIT))
    print(f"{KIT}: {sum(1 for p in KIT.rglob('*') if p.is_file())} files; {ZIP.name}")
    _, w, wv = readiness
    print(f"Readiness: weighted coverage {wv:.1f}/{w} = {100 * wv / w:.0f}%")


if __name__ == "__main__":
    main()
