#!/usr/bin/env python3
"""Build the Integrity Tech Detections app: every AA26-281A detection, the hunts behind them, and dashboards.

  python3 build_detection_app.py          # writes integrity_tech_detections/ and dist/integrity_tech_detections.tgz

The app holds no data. It runs on any Splunk whose data is mapped to CIM; the risk panels and the behaviour-chain finding need
Enterprise Security 8. Point the `aa26_iis` and `aa26_o365` macros and the approved-list lookups at your own environment.
The dashboards open on the lab's scenario window, so they show the synthetic intrusion when TA-aa26-281a-lab is installed.
"""

import csv
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

from PIL import Image, ImageDraw

import generate_lab_data as lab

HERE = Path(__file__).resolve().parent
APP = HERE / "integrity_tech_detections"
TA_LOOKUPS = HERE / "TA-aa26-281a-lab" / "lookups"
ICON_SVG = HERE / "shield-lock.svg"
VERSION = "1.1.0"
WINDOW = json.loads((HERE / "output" / "manifest.json").read_text())["window"]
EXPECTED = json.loads((HERE / "output" / "expected.json").read_text())

ACCENT, ORANGE, RED, GREEN, GREY = "#02C8FF", "#FF9000", "#EB4651", "#45991F", "#6B6B6B"
PORTS = "(21,22,53,80,443,1080)"
SEARCH = {s["name"][:7]: s["spl"] for s in lab.SEARCHES}

# Detection -> (stage, data source). Stage order follows the advisory's chain.
STAGES = ["Reconnaissance", "Initial access", "Credential access", "Persistence", "Command and control", "Collection",
          "Exfiltration", "Correlation"]
CATALOG = {
    "Scanning on advisory ports": ("Reconnaissance", "Firewall (CIM Network_Traffic)"),
    "Web enumeration burst": ("Reconnaissance", "IIS web (CIM Web)"),
    "Exploit attempts for advisory CVEs": ("Initial access", "IIS web (exploit and XSS requests)"),
    "FishHub-style script stager": ("Initial access", "Sysmon (CIM Endpoint.Processes)"),
    "Exchange password spray": ("Credential access", "Exchange IIS"),
    "Spray source authenticated": ("Credential access", "Exchange IIS"),
    "DCSync by non-machine account": ("Credential access", "Windows Security 4662"),
    "SoftEther masquerading as Windows binary": ("Persistence", "Sysmon (CIM Endpoint.Processes)"),
    "Autostart service outside system paths": ("Persistence", "Windows System 7045"),
    "New app secret or consent": ("Persistence", "Microsoft 365 audit"),
    "SoftEther dynamic DNS": ("Command and control", "DNS (CIM Network_Resolution)"),
    "Known-bad domain resolved": ("Command and control", "DNS (CIM Network_Resolution)"),
    "Connection to known-bad IP": ("Command and control", "Firewall (CIM Network_Traffic)"),
    "EWS volume far above normal": ("Collection", "Exchange IIS"),
    "Unapproved app reading many mailboxes": ("Collection", "Microsoft 365 audit"),
    "Advisory decoy file names": ("Collection", "Sysmon (CIM Endpoint.Filesystem)"),
    "Upload-heavy host": ("Exfiltration", "Firewall (CIM Network_Traffic)"),
    "Integrity Tech behaviour chain": ("Correlation", "ES risk index"),
}
READINESS = [("Reconnaissance", "Available", "Firewall; positive and negative tests pass", "Scanning on advisory ports"),
             ("Web enumeration and exploitation", "Available", "IIS; tested. Edge appliances (VPN, FTP, DNS) send no logs", "Web enumeration burst; Exploit attempts for advisory CVEs"),
             ("Password spraying", "Available", "Exchange IIS and AD; tested", "Exchange password spray; Spray source authenticated"),
             ("VPN persistence", "Partial", "Windows only; no Linux endpoint telemetry", "SoftEther masquerading as Windows binary; SoftEther dynamic DNS"),
             ("Mailbox collection", "Partial", "IIS for everyone; M365 audit for 30 of 120 mailboxes", "EWS volume far above normal; Unapproved app reading many mailboxes"),
             ("Data exfiltration", "Partial", "Firewall bytes; no proxy logs", "Upload-heavy host; Connection to known-bad IP"),
             ("Credential theft (DCSync)", "Missing", "No replication SACL: nothing to search", "DCSync by non-machine account")]
LOOKUPS = {"approved_mail_apps": {}, "aa26_281a_domains": {"match_type": "WILDCARD(domain)", "case_sensitive_match": "false", "max_matches": "1"},
           "aa26_281a_ips": {}, "aa26_approved_scanners": {}, "aa26_approved_remote_access": {"case_sensitive_match": "false"},
           "aa26_lab_assets": {"case_sensitive_match": "false"}, "aa26_lab_identities": {"case_sensitive_match": "false"},
           "aa26_advisory_cves": {}, "aa26_lab_vulns": {},
           "itd_detection_catalog": {}, "itd_readiness": {}, "itd_response_actions": {}, "itd_controls": {}}

# The defender action centre: what each finding should turn into. Live risk is joined at search time.
ACTIONS = [
    (1, "Identity compromise", "j.citizen", "Spray success from 203.0.113.47; sign-ins from two never-seen addresses; 2,400 EWS calls in an hour",
     "High", "Confirm with the user and her manager; revoke sessions and tokens; reset the password; enforce phishing-resistant MFA on every Exchange protocol",
     "Identity team", "Yes: account action", "Open"),
    (2, "VPN persistence", "WS-0417", "conhost.exe is vpnbridge.exe; autostart service; SoftEther dynamic DNS; hourly tunnel to 203.0.113.88",
     "High", "Collect memory and disk first; isolate through the IR process; remove the service; then block the DDNS name and 203.0.113.88",
     "Endpoint and IR", "Yes: isolation", "Open"),
    (3, "Mailbox collection", "Project Mail Archiver", "Secret added by j.citizen from 203.0.113.52; the app read 7 mailboxes",
     "High", "Remove the secret and consent; disable the app; list the mailboxes and items read; brief the data owners",
     "Microsoft 365 admins", "Yes: notification", "Open"),
    (4, "Phishing victim", "a.lim", "FishHub stager from Outlook on WS-0458; seized domain fym.linkedinns.net; 186 MB to 207.148.92.220",
     "High", "Isolate WS-0458; identify the uploaded documents; reset credentials; search mail for the same lure",
     "IR and email security", "Yes: isolation", "Open"),
    (5, "Exposure: advisory CVEs", "VPN01, FTP01", "Actor scanned both; exploits for 6 advisory CVEs tried on WEB01; neither box sends logs",
     "High", "Patch or isolate VPN01 and FTP01 today and check them for compromise; patch NS01 this week; GIT01 and LEGACY01 this month",
     "Infrastructure", "Change approval", "Open"),
    (6, "Web input handling", "WEB01", "XSS payloads to /search.aspx and /contact.aspx answered with 200",
     "Unverified", "Test that both pages encode input; fix and retest; add a WAF rule meanwhile",
     "Web team", "No", "To verify"),
    (7, "Visibility gap: DCSync", "DC01, DC02", "Zero 4662 events: the replication audit SACL was never set",
     "Gap", "Enable Audit Directory Service Access and the replication SACL; prove it with a test replication from a non-DC",
     "AD team", "Change approval", "Open"),
    (8, "Visibility gap: edge, Linux, mail", "Appliances, Linux, 90 mailboxes", "Edge appliances send no logs; no Linux telemetry; MailItemsAccessed on 30 of 120 mailboxes",
     "Gap", "Forward VPN, FTP and DNS appliance logs; onboard Linux endpoint telemetry; enable mailbox auditing for everyone",
     "SOC engineering", "No", "Open"),
]
# Defence by stage: prevent, detect, and what this app watches.
CONTROLS = [
    (1, "Reconnaissance", "Mass scanning of FTP, SSH, DNS, HTTP(S) and SOCKS", "Attack surface management; close unused ports and services; minimal banners",
     "Scan patterns by source: direction, baseline, what happened next", "Scanning on advisory ports"),
    (2, "Exploitation", "Old CVEs (2014 to 2023) and XSS payloads", "Patch the advisory CVEs; replace end-of-life products; sanitise web input; WAF",
     "Exploit attempts in web logs; vulnerable versus targeted assets", "Exploit attempts for advisory CVEs; Web enumeration burst"),
    (3, "Phishing", "FishHub look-alike domains and script stagers", "Email security; domain protection; user reporting; block script hosts for users",
     "Office starting script hosts; seized domains; follow-on connections", "FishHub-style script stager; Known-bad domain resolved"),
    (4, "Password spraying", "EBurst across up to ten Exchange interfaces", "ICAM; phishing-resistant MFA on every protocol; disable legacy authentication",
     "Many accounts, few tries; success from the spraying source", "Exchange password spray; Spray source authenticated"),
    (5, "VPN persistence", "Renamed SoftEther, autostart service, dynamic DNS", "Application control; EDR; approved remote-access register",
     "Original file name; services outside system paths; dynamic DNS; hourly tunnels", "SoftEther masquerading as Windows binary; Autostart service outside system paths; SoftEther dynamic DNS"),
    (6, "Credential theft", "DCSync and Active Directory credential harvesting", "Restrict replication rights; tiered administration; privileged access management",
     "4662 with replication rights by a non-DC account", "DCSync by non-machine account"),
    (7, "Mailbox collection", "EWS scripts; an app granted Mail.Read", "Least privilege; app consent governance; audit every mailbox",
     "EWS volume against each user's own baseline; new secrets; unapproved apps reading mail", "EWS volume far above normal; New app secret or consent; Unapproved app reading many mailboxes"),
    (8, "Exfiltration", "Uploads through the tunnel; FishHub collection server", "Egress filtering; data protection; proxy",
     "Upload-heavy hosts; known-bad destinations", "Upload-heavy host; Connection to known-bad IP"),
]


def rule(name):
    return f"AA26-281A - {name} - Rule"


def write(rel, text):
    path = APP / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def write_csv(rel, cols, rows):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(cols)
    w.writerows(rows)
    write(rel, buf.getvalue())


# ---------------------------------------------------------------------
# Dashboard Studio
# ---------------------------------------------------------------------

class Dash:
    def __init__(self, view, title, desc, inputs=None):
        self.view, self.title, self.desc = view, title, desc
        self.viz, self.ds, self.items, self.n = {}, {}, [], 0
        self.inputs = {"input_time": {"type": "input.timerange", "title": "Time",
                                      "options": {"token": "global_time", "defaultValue": f"{WINDOW['earliest']},{WINDOW['latest']}"}}}
        self.inputs.update(inputs or {})

    def link(self, dashboard, tokens=None):
        """Clicking the last visualisation opens another dashboard in this app, passing row values as tokens."""
        opts = {"app": APP.name, "dashboard": dashboard, "newTab": False}
        if tokens:
            opts["tokens"] = [{"token": t, "value": v} for t, v in tokens.items()]
        self.viz[f"viz_{self.n}"]["eventHandlers"] = [{"type": "drilldown.linkToDashboard", "options": opts}]

    def add(self, kind, title, spl, x, y, w, h, options=None, context=None, desc=None):
        self.n += 1
        v, d = f"viz_{self.n}", f"ds_{self.n}"
        viz = {"type": kind, "options": options or {}}
        if title:
            viz["title"] = title
        if desc:
            viz["description"] = desc
        if context:
            viz["context"] = context
        if spl is not None:
            self.ds[d] = {"type": "ds.search", "name": title or d, "options": {"query": spl.strip()}}
            viz["dataSources"] = {"primary": d}
        self.viz[v] = viz
        self.items.append({"item": v, "type": "block", "position": {"x": x, "y": y, "w": w, "h": h}})

    def single(self, title, spl, x, y, w=360, h=150, color=ACCENT, under=None):
        opts = {"majorColor": color, "sparklineDisplay": "off", "trendDisplay": "off"}
        if under:
            opts["underLabel"] = under
        self.add("splunk.singlevalue", title, spl, x, y, w, h, opts)

    def table(self, title, spl, x, y, w, h, colors=None, count=10, desc=None, widths=None):
        opts, ctx = {"count": count}, {}
        for field, mapping in (colors or {}).items():
            key = f"{field.replace(' ', '_')}Colors"
            ctx[key] = [{"match": m, "value": c} for m, c in mapping.items()]
            ctx[f"{key}Text"] = [{"match": m, "value": "#FFFFFF"} for m in mapping]
            opts.setdefault("columnFormat", {})[field] = {
                "data": f'> table | seriesByName("{field}") | formatByType({field.replace(" ", "_")}Format)',
                "rowBackgroundColors": f'> table | seriesByName("{field}") | matchValue({key})',
                "rowColors": f'> table | seriesByName("{field}") | matchValue({key}Text)'}
            ctx[f"{field.replace(' ', '_')}Format"] = {"string": {"unitPosition": "after"}}
        for field, width in (widths or {}).items():
            opts.setdefault("columnFormat", {}).setdefault(field, {})["width"] = width
        self.add("splunk.table", title, spl, x, y, w, h, opts, ctx or None, desc)

    def chart(self, kind, title, spl, x, y, w, h, colors=None, stack=False, y_title=None, legend="bottom"):
        opts = {"legendDisplay": legend, "xAxisTitleVisibility": "hide"}
        if colors:
            opts["seriesColors"] = colors
        if stack:
            opts["stackMode"] = "stacked"
        if y_title:
            opts["yAxisTitleText"] = y_title
        self.add(kind, title, spl, x, y, w, h, opts)

    def md(self, text, x, y, w, h):
        self.add("splunk.markdown", None, None, x, y, w, h, {"markdown": text, "fontColor": "#B4B9C0"})

    def xml(self):
        height = max(i["position"]["y"] + i["position"]["h"] for i in self.items) + 20
        definition = {
            "title": self.title, "description": self.desc, "inputs": self.inputs,
            "defaults": {"dataSources": {"ds.search": {"options": {"queryParameters": {
                "earliest": "$global_time.earliest$", "latest": "$global_time.latest$"}}}}},
            "visualizations": self.viz, "dataSources": self.ds,
            "layout": {"type": "grid", "options": {"width": 1440, "height": height}, "structure": self.items,
                       "globalInputs": list(self.inputs)}}
        body = json.dumps(definition, indent=2)
        assert "]]>" not in body
        return (f'<dashboard version="2" theme="dark">\n  <label>{self.title}</label>\n  <description>{self.desc}</description>\n'
                f"  <definition><![CDATA[\n{body}\n  ]]></definition>\n"
                '  <meta type="hiddenElements"><![CDATA[{"hideEdit": false, "hideOpenInSearch": false, "hideExport": false}]]></meta>\n'
                "</dashboard>\n")


RISK_AGG = "| tstats sum(All_Risk.calculated_risk_score) as risk dc(All_Risk.annotations.mitre_attack.mitre_tactic_id) as tactics dc(source) as detections"
RISK_FROM = ' from datamodel=Risk.All_Risk where source="AA26-281A - *"'
RISK = RISK_AGG + RISK_FROM
SHORT_DET = '| eval detection=replace(source,"^AA26-281A - (.*) - Rule$","\\1")'
VERDICT = {"scanned, then signed in": RED, "background scanning": GREY, "approved scanner": GREEN}
STATUS = {"Available": GREEN, "Partial": ORANGE, "Missing": RED}


def dashboards():
    out = []
    lab_idx = "index IN (exchange, web, o365, wineventlog, sysmon, firewall, dns)"
    behaviours = len(lab.DETECTIONS)

    d = Dash("itd_overview", "Integrity Tech: threat overview",
             "The advisory has landed. What does our environment already know about this adversary? Click a number to dig in.")
    d.single("Detections in this app", '| rest splunk_server=local /servicesNS/-/integrity_tech_detections/saved/searches '
             '| search eai:acl.app=integrity_tech_detections title="AA26-281A - *" | stats count', 0, 0,
             under=f"{behaviours} behaviour detections plus one finding")
    d.link("itd_detections")
    d.single("Fired on the simulated intrusion", '| inputlookup itd_detection_catalog.csv | where type="Detection" '
             '| stats count(eval(lab_rows>0)) as fired count as total | eval value=fired." of ".total | fields value', 360, 0,
             under="the one that didn't is a telemetry gap")
    d.link("itd_detections")
    d.single("Entities over the risk threshold", RISK + ' by All_Risk.risk_object | where risk>=100 AND tactics>=3 | stats count',
             720, 0, color=RED, under="risk 100+ across 3+ tactics: open the storyline")
    d.link("itd_storyline")
    d.single("Detection readiness", '| inputlookup itd_readiness.csv | stats count(eval(status="Available")) as ok count as total '
             '| eval value=round(100*ok/total)."%" | fields value', 1080, 0, color=ORANGE, under="validated ÷ relevant behaviours: see the gaps")
    d.link("itd_readiness")
    d.chart("splunk.bar", "Risk by entity", RISK + ' by All_Risk.risk_object | rename All_Risk.risk_object as entity '
            '| sort - risk | head 8 | table entity risk', 0, 160, 560, 380, [ACCENT], legend="off")
    d.chart("splunk.column", "Risk added per day, by detection", 'index=risk source="AA26-281A - *" ' + SHORT_DET +
            ' | timechart span=1d sum(risk_score) by detection', 560, 160, 880, 380, stack=True)
    d.table("Entities ranked by risk (click a row to investigate)", RISK_AGG + RISK_FROM + ' by All_Risk.risk_object All_Risk.risk_object_type '
            '| rename All_Risk.risk_object as entity All_Risk.risk_object_type as type '
            '| eval finding=if(risk>=100 AND tactics>=3,"FINDING","below threshold") '
            '| sort - risk | table entity type risk tactics detections finding', 0, 550, 1440, 330,
            {"finding": {"FINDING": RED, "below threshold": GREY}})
    d.link("itd_investigate", {"entity": "$row.entity.value$"})
    out.append(d)

    related = ('(['
               '| inputlookup aa26_lab_identities.csv | search identity="$entity$" | eval risk_object=mvappend(identity, workstation) '
               '| mvexpand risk_object | fields risk_object] OR [search index=risk source="AA26-281A - *" risk_object="$entity$" '
               'threat_object_type=ip_address | stats count by threat_object | rename threat_object as risk_object | fields risk_object] '
               'OR risk_object="$entity$")')
    chain = 'index=risk source="AA26-281A - *" ' + related
    apps_of = ('[search `aa26_o365` Operation="Add service principal credentials*" UserId="$entity$@*" | stats count by ObjectId '
               '| rename ObjectId as AppId | fields AppId]')
    d = Dash("itd_storyline", "Incident storyline",
             "Six quiet detections, or one intrusion? Everything linked to one identity, its workstation and the addresses that used it, in order.",
             {"input_entity": {"type": "input.text", "title": "Identity", "options": {"token": "entity", "defaultValue": "j.citizen"}}})
    d.single("First signal", chain + ' | stats min(_time) as t | eval t=strftime(t,"%d %b %H:%M") | fields t', 0, 0, color="#FFFFFF",
             under="the first detection that touched this chain")
    d.single("Inside before the advisory", chain + ' | stats min(_time) as first | addinfo | eval d=info_max_time-first '
             '| eval value=floor(d/86400)." days ".floor((d%86400)/3600)." h" | fields value', 360, 0, color=RED,
             under="from first signal to the end of the time range")
    d.single("Detections in the chain", chain + ' | stats dc(source)', 720, 0, under="each quiet on its own")
    d.single("Behaviours we cannot see", '| inputlookup itd_readiness.csv | where status="Missing" | stats count', 1080, 0, color=RED,
             under="DCSync: no 4662 telemetry")
    d.table("What happened, in order", chain + SHORT_DET + '''
| stats min(_time) as _time values(risk_object) as entities earliest(risk_message) as what by detection
| lookup itd_detection_catalog detection OUTPUT stage
| eval evidence="risk event", status="detected"
| append [search index=sysmon EventCode=11 TargetFilename="*live700*"
    [| inputlookup aa26_lab_identities.csv | search identity="$entity$" | eval Computer=workstation."*" | fields Computer]
    | stats min(_time) as _time by Computer
    | eval Computer=upper(mvindex(split(Computer,"."),0)),
        stage="Execution", what="The advisory's fake-login payload live700_v1.exe is saved on ".Computer.", then drops DiagTrack.exe",
        entities=Computer, evidence="Sysmon file create", status="evidence only", detection="none (hunt: AA26 19)"]
| append [search `aa26_o365` Operation="Add service principal credentials*" UserId="$entity$@*"
    | stats min(_time) as _time values(ObjectId) as app values(ClientIP) as ip by UserId
    | eval stage="Persistence", what="A secret is added to an app this identity owns, from ".ip, entities=UserId,
        evidence="Microsoft 365 audit", status="detected", detection="New app secret or consent"]
| append [search `aa26_o365` Operation=MailItemsAccessed ''' + apps_of + '''
    | stats min(_time) as _time dc(MailboxOwnerUPN) as n by AppId
    | eval stage="Collection", what="That app reads ".n." mailboxes", entities=AppId, evidence="Microsoft 365 audit",
        status="detected", detection="Unapproved app reading many mailboxes"]
| append [| makeresults | eval _time=null(), stage="Credential access", entities="DC01, DC02", evidence="none",
    what="DCSync cannot be seen: no 4662 events, because the replication audit SACL was never set", status="GAP", detection="DCSync by non-machine account"]
| eval time=if(isnull(_time),"unknown",strftime(_time,"%d %b %H:%M")), entity=mvjoin(entities,", "), k=if(isnull(_time),1,0)
| sort k _time
| table time stage what entity evidence detection status''', 0, 140, 1440, 640,
            {"status": {"detected": GREEN, "evidence only": ORANGE, "GAP": RED}}, count=15,
            widths={"time": 110, "stage": 140, "what": 560, "entity": 200, "evidence": 150, "detection": 170, "status": 110})
    d.md("### Six separate alerts, or one intrusion?\n"
         "- **What we know (in this lab):** one external source scanned us, tried old exploits, sprayed 64 mailboxes and got into "
         "j.citizen's. Her workstation then ran a disguised VPN, and her mailbox was read in bulk from a second address.\n"
         "- **What we don't know yet:** how the payload reached WS-0417, whether domain credentials were taken (DCSync is invisible "
         "here), and what the seven mailboxes held.\n"
         "- **What needs approval:** disabling the account, isolating WS-0417, removing the app. "
         "Next: the [Defender action centre](/app/integrity_tech_detections/itd_response).", 0, 790, 1440, 150)
    out.append(d)

    d = Dash("itd_detections", "Detection library",
             "Every Integrity Tech detection in this app: what it looks for, the data it needs, and how it did in the lab.")
    d.single("Detections", '| inputlookup itd_detection_catalog.csv | stats count', 0, 0, under=f"{behaviours} behaviour detections and 1 finding")
    d.single("ATT&CK techniques", '| inputlookup itd_detection_catalog.csv | makemv delim=" " mitre | mvexpand mitre | stats dc(mitre)',
             360, 0)
    d.single("Data sources", '| inputlookup itd_detection_catalog.csv | where type="Detection" | stats dc(data_source)', 720, 0)
    d.single("Fire on the simulated intrusion", '| inputlookup itd_detection_catalog.csv | where type="Detection" '
             '| stats count(eval(lab_rows>0)) as fired count as total | eval value=fired." of ".total | fields value', 1080, 0, color=GREEN)
    d.table("Detections, in attack-chain order", '| inputlookup itd_detection_catalog.csv '
            '| join type=left rule [| rest splunk_server=local /servicesNS/-/integrity_tech_detections/saved/searches '
            '| search eai:acl.app=integrity_tech_detections | rename title as rule '
            '| eval state=if(disabled=1,"disabled","scheduled") | table rule state cron_schedule] '
            '| eval schedule=case(type="Finding","hourly, 7-day window", match(cron_schedule,"^\\*/30"),"every 30 min", true(),"hourly") '
            '| eval lab_result=case(type="Finding","raises the finding", lab_rows>0,"fires (".lab_rows." rows)", true(),"silent: telemetry gap") '
            '| table order stage detection mitre data_source risk schedule state lab_result | sort order | fields - order',
            0, 160, 1440, 800, {"lab_result": {"silent: telemetry gap": RED}}, count=20)
    out.append(d)

    exploit = lab.EXPLOIT_BASE
    d = Dash("itd_exposure", "Exposure: old CVEs, still exploited",
             "The advisory's eight exploited CVEs date from 2014 to 2023. Which do we run, which face the internet, who tried them, and would we see it?")
    d.single("Advisory CVEs", '| inputlookup aa26_advisory_cves.csv | stats count', 0, 0, 288, under="successfully exploited, 2014 to 2023")
    d.single("Oldest", '| inputlookup aa26_advisory_cves.csv | stats min(year) as y '
             '| eval value=(tonumber(strftime(now(),"%Y"))-y)." years" | fields value', 288, 0, 288, color=ORANGE, under="CVE-2014-6278, GNU Bash")
    d.single("Newly added to CISA KEV", '| inputlookup aa26_advisory_cves.csv | where kev_added_with_advisory="yes" | stats count',
             576, 0, 288, color=ORANGE, under="exploited recently, not a decade ago")
    d.single("On our assets", '| inputlookup aa26_lab_vulns.csv | stats dc(cve) as n '
             '| appendcols [| inputlookup aa26_advisory_cves.csv | stats count as t] | eval value=n." of ".t | fields value',
             864, 0, 288, under="from the vulnerability inventory")
    d.single("Patch now", SEARCH["AA26 31"] + '\n| where priority="1 Patch now" | stats count', 1152, 0, 288, color=RED,
             under="internet-facing and scanned by the actor")
    d.table("The advisory's CVEs in our estate: present, exposed, scanned, attempted, visible?",
            SEARCH["AA26 31"] + '\n| rename kev_added_with_advisory as new_in_KEV | fields - year impact', 0, 160, 1440, 470,
            {"priority": {"1 Patch now": RED, "2 Patch this week": ORANGE, "3 Patch this month": GREY},
             "telemetry": {"NO LOGS": RED}},
            widths={"cve": 150, "age": 60, "product": 230, "new_in_KEV": 100, "asset": 100, "internet_facing": 120,
                    "scanned_by": 190, "attempted_by": 190, "telemetry": 120, "priority": 180})
    d.table("Who tried the advisory's exploits against us, and did anything answer?",
            SEARCH["AA26 30"] + '\n| eval attempts=mvjoin(attempts,", ")', 0, 640, 1440, 240,
            {"verdict": {"multi-exploit sweep: investigate": RED, "opportunistic probe": GREY, "approved scanner": GREEN}},
            widths={"src": 130, "direction": 90, "techniques": 90, "attempts": 640, "requests": 80, "answered": 80, "first": 110, "verdict": 220})
    d.md("### Why 2014 CVEs still work in 2026\n"
         "- **Automation makes old cheap.** MicroScan carries 1,300+ scripts; trying every exploit on every host costs the actor nothing.\n"
         "- **Old systems outlive their patches.** Edge appliances and legacy servers drift out of patch cycles, and often send no logs.\n"
         "- **Five of the eight were only added to CISA KEV with this advisory:** recent exploitation, not history.\n"
         "- **Defend with inventory:** what you run, what faces the internet, and whether it logs to your SIEM.", 900, 890, 540, 330)
    d.table("What the sweep looked like (the actor's requests, as logged)", exploit + '''
| lookup aa26_approved_scanners src AS c_ip OUTPUT reason
| where isnull(reason)
| eventstats dc(attempt) as techniques by c_ip
| where techniques>=3
| eval time=strftime(_time,"%d %b %H:%M:%S"), request=cs_method." ".cs_uri_stem.if(cs_uri_query="-","","?".substr(cs_uri_query,1,60))
| sort _time
| table time c_ip attempt request sc_status''', 0, 890, 900, 560, count=15,
            widths={"time": 130, "c_ip": 110, "attempt": 200, "request": 390, "sc_status": 70})
    out.append(d)

    d = Dash("itd_recon", "Hunt: reconnaissance, exploitation and initial access",
             "Who scanned us on the advisory's ports, what they tried, the spray that followed, and the sign-in that worked.")
    d.table("Who is scanning: direction, baseline and what they did next (click a source to investigate)", SEARCH["AA26 29"], 0, 0, 1440, 200,
            {"verdict": VERDICT})
    d.link("itd_investigate", {"entity": "$row.src.value$"})
    d.chart("splunk.column", "Hosts touched per hour on ports 21, 22, 53, 80, 443 and 1080 (sources touching 25+)",
            f'| tstats dc(All_Traffic.dest) as hosts from datamodel=Network_Traffic where All_Traffic.dest_port IN {PORTS} '
            'by All_Traffic.src _time span=1h | rename All_Traffic.src as src | where hosts>=25 | timechart span=1h max(hosts) by src',
            0, 210, 1440, 240, [GREEN, GREY, RED])
    d.table("Exploit attempts for the advisory's CVEs", SEARCH["AA26 30"] + '\n| eval attempts=mvjoin(attempts,", ") | fields - direction first',
            0, 460, 1440, 240, {"verdict": {"multi-exploit sweep: investigate": RED, "opportunistic probe": GREY, "approved scanner": GREEN}},
            widths={"src": 120, "techniques": 100, "attempts": 760, "requests": 90, "answered": 90, "verdict": 230})
    d.table("Password spray across Exchange interfaces", SEARCH["AA26 03"] + '\n| eval time=strftime(_time,"%d %b %H:%M") | table time c_ip failures users interfaces ok verdict',
            0, 710, 640, 190, {"verdict": {"SPRAY + SUCCESS": RED, "SPRAY": ORANGE}})
    spray_hits = SEARCH["AA26 03"] + '\n| where verdict="SPRAY + SUCCESS" | mvexpand ok'
    d.table("The sign-in that worked: the evidence behind the detection", f'''`aa26_iis` sc_status=200
    [search {spray_hits} | rename ok as cs_username | fields c_ip cs_username]
| stats min(_time) as t count as requests values(cs_uri_stem) as interface by cs_username c_ip
| eval evidence="IIS log, MAIL01", detail=requests." requests in the session"
| append [search `wineventlog_security` EventCode=4624
    [search {spray_hits} | rename ok as TargetUserName c_ip as IpAddress | fields TargetUserName IpAddress]
    | stats min(_time) as t values(LogonType) as lt by TargetUserName IpAddress
    | rename TargetUserName as cs_username IpAddress as c_ip
    | eval evidence="Windows 4624, MAIL01", interface="logon type ".lt, detail="by w3wp.exe (IIS)"]
| eval time=strftime(t,"%d %b %H:%M:%S") | sort t
| table time evidence cs_username c_ip interface detail''', 640, 710, 800, 190,
            widths={"time": 140, "evidence": 170, "cs_username": 100, "c_ip": 110, "interface": 150, "detail": 130})
    d.table("Web enumeration (dirsearch-style)", SEARCH["AA26 05"] + '\n| rename Web.src as src | eval time=strftime(_time,"%d %b %H:%M") | table time src paths',
            0, 910, 1440, 140)
    out.append(d)

    d = Dash("itd_persistence", "Hunt: SoftEther VPN persistence",
             "A legitimate VPN bridge renamed conhost.exe: the process, the service, the DNS and the tunnel it keeps open.")
    d.table("Masquerading binary, after tuning (approved installs removed)", SEARCH["AA26 23"] + "\n| fields - approved_by", 0, 0, 880, 230)
    d.table("Evidence correlated by host: one signal is a question, three is a finding", SEARCH["AA26 22"], 880, 0, 560, 230)
    d.chart("splunk.column", "Sessions to 203.0.113.88:443 per day: one an hour, every hour, from 29 Sep",
            '| tstats count from datamodel=Network_Traffic where All_Traffic.dest="203.0.113.88" by _time span=1d '
            '| timechart span=1d sum(count) as sessions', 0, 240, 1440, 280, [RED], legend="off")
    d.table("New autostart services outside system paths", SEARCH["AA26 16"] + '\n| eval time=strftime(_time,"%d %b %H:%M") | table time Computer ServiceName ImagePath', 0, 530, 880, 160,
            {"ServiceName": {"Console Host Service": RED}})
    d.table("SoftEther dynamic DNS lookups", SEARCH["AA26 07"] + "\n| rename DNS.src as src DNS.query as query", 880, 530, 560, 160)
    out.append(d)

    d = Dash("itd_collection", "Hunt: mailbox collection",
             "Email is the objective. Volume against each user's own normal, and an app reading mailboxes it shouldn't, event by event.")
    d.chart("splunk.line", "EWS calls per hour: j.citizen against a busy service account",
            '`aa26_iis` sc_status=200 cs_uri_stem="/EWS/Exchange.asmx" cs_username IN ("j.citizen","svc-crm") '
            '| timechart span=1h count by cs_username', 0, 0, 1440, 300, [RED, GREY])
    d.table("EWS volume far above the user's own normal", SEARCH["AA26 09"] + '\n| eval hour=strftime(_time,"%d %b %H:00"), agents=coalesce(agents,"(none)") '
            '| table hour cs_username c_ip calls typical active_hours agents', 0, 310, 1440, 130)
    d.table("Unapproved app reading many mailboxes (Microsoft 365)", SEARCH["AA26 10"], 0, 450, 560, 140)
    d.table("New app secrets and consents", SEARCH["AA26 11"] + '\n| eval time=strftime(_time,"%d %b %H:%M") | table time UserId Operation ObjectId',
            0, 600, 560, 170)
    d.table("The app's audit trail: a secret is added, then seven mailboxes are read", '''`aa26_o365` Operation IN ("Add service principal credentials*","MailItemsAccessed")
| eval app=coalesce(AppId,ObjectId)
| search [search `aa26_o365` Operation=MailItemsAccessed | stats dc(MailboxOwnerUPN) as m by AppId
    | lookup approved_mail_apps AppId OUTPUT owner | where m>=5 AND isnull(owner) | rename AppId as app | fields app]
| eval time=strftime(_time,"%d %b %H:%M:%S"), actor=if(match(UserId,"^ServicePrincipal_"),"the app itself",UserId),
    ip=coalesce(ClientIP,ClientIPAddress), mailbox=coalesce(MailboxOwnerUPN,"-")
| sort _time
| table time Operation actor ip mailbox''', 560, 450, 880, 320, {"Operation": {"Add service principal credentials.": RED}})
    out.append(d)

    d = Dash("itd_investigate", "Investigate an entity",
             "Everything the detections know about one user or host, in order, with the context to decide fast.",
             {"input_entity": {"type": "input.text", "title": "User or host", "options": {"token": "entity", "defaultValue": "j.citizen"}}})
    d.single("Total risk", 'index=risk source="AA26-281A - *" risk_object="$entity$" | stats sum(risk_score)', 0, 0, color=RED)
    d.single("ATT&CK tactics", RISK + ' AND All_Risk.risk_object="$entity$" | fields tactics', 360, 0)
    d.single("Detections", RISK + ' AND All_Risk.risk_object="$entity$" | fields detections', 720, 0)
    d.single("First signal", 'index=risk source="AA26-281A - *" risk_object="$entity$" | stats min(_time) as t '
             '| eval t=strftime(t,"%d %b %H:%M") | fields t', 1080, 0, color="#FFFFFF")
    d.table("Risk events, in order", 'index=risk source="AA26-281A - *" risk_object="$entity$" ' + SHORT_DET +
            ' | eval time=strftime(_time,"%d %b %H:%M") | sort _time | table time detection risk_score risk_message', 0, 160, 1440, 300)
    d.table("Where this account signs in from", SEARCH["AA26 25"].replace('"j.citizen"', '"$entity$"'), 0, 470, 880, 220,
            {"seen_before": {"NEVER": RED}})
    d.table("Who and what is at risk", '| inputlookup aa26_lab_identities.csv | search identity="$entity$" '
            '| lookup aa26_lab_assets host AS workstation OUTPUT ip priority AS host_priority '
            '| table identity display title department workstation priority host_priority', 880, 470, 560, 220)
    out.append(d)

    d = Dash("itd_response", "Defender action centre",
             "What the investigation turns into: prioritised actions with evidence, owner and approval, and the controls that stop each stage.")
    d.single("Actions open", '| inputlookup itd_response_actions.csv | where status!="Done" | stats count', 0, 0, color=ORANGE)
    d.single("Need human approval", '| inputlookup itd_response_actions.csv | where approval!="No" | stats count', 360, 0, color=RED,
             under="detection proposes; people decide")
    d.single("Highest live risk", RISK + ' by All_Risk.risk_object | sort - risk | head 1 '
             '| eval value=\'All_Risk.risk_object\'." (".risk.")" | fields value', 720, 0, color=RED, under="from the risk index, now")
    d.single("Visibility gaps to close", '| inputlookup itd_response_actions.csv | where like(finding,"Visibility gap%") | stats count',
             1080, 0, color=RED, under="telemetry we need before we can detect")
    d.table("Prioritised actions (live risk joined from Enterprise Security)", '''| inputlookup itd_response_actions.csv
| join type=left entity [''' + RISK + ''' by All_Risk.risk_object | rename All_Risk.risk_object as entity | fields entity risk]
| fillnull value="-" risk
| sort priority
| table priority finding entity risk evidence confidence action owner approval status''', 0, 160, 1440, 720,
            {"confidence": {"High": RED, "Gap": RED, "Unverified": GREY}, "status": {"Open": ORANGE, "To verify": GREY}}, count=10,
            widths={"priority": 70, "finding": 160, "entity": 140, "risk": 60, "evidence": 270, "confidence": 100, "action": 330,
                    "owner": 110, "approval": 120, "status": 80})
    d.table("Defence by stage: prevent it, detect it, and what this app watches", '''| inputlookup itd_controls.csv
| eval d=split(detections,"; ")
| mvexpand d
| lookup itd_detection_catalog detection AS d OUTPUT lab_rows
| stats values(activity) as activity values(prevent) as prevent values(detect) as detect values(detections) as detections min(lab_rows) as worst by order stage
| eval in_this_lab=if(worst>0,"detected","GAP: no telemetry")
| sort order
| table stage activity prevent detect detections in_this_lab''', 0, 890, 1440, 620,
            {"in_this_lab": {"detected": GREEN, "GAP: no telemetry": RED}}, count=10,
            widths={"stage": 140, "activity": 230, "prevent": 320, "detect": 320, "detections": 290, "in_this_lab": 140})
    out.append(d)

    d = Dash("itd_readiness", "Telemetry and detection readiness",
             "What we can prove we would see. Readiness = validated behaviours ÷ relevant behaviours (a proposed metric).")
    d.single("Detection readiness", '| inputlookup itd_readiness.csv | stats count(eval(status="Available")) as ok count as total '
             '| eval value=ok." of ".total." = ".round(100*ok/total)."%" | fields value', 0, 0, color=ORANGE)
    d.single("Available", '| inputlookup itd_readiness.csv | where status="Available" | stats count', 360, 0, color=GREEN,
             under="telemetry and a tested detection")
    d.single("Partial", '| inputlookup itd_readiness.csv | where status="Partial" | stats count', 720, 0, color=ORANGE,
             under="some evidence, incomplete coverage")
    d.single("Directory replication events (4662)", '`wineventlog_security` EventCode=4662 | stats count', 1080, 0, color=RED,
             under="zero is not safe: the audit SACL was never set")
    d.table("Readiness by behaviour", '| inputlookup itd_readiness.csv | table behaviour status evidence detections', 0, 160, 860, 470,
            {"status": STATUS})
    d.table("What data do we have, and how far back?", '| tstats count min(_time) as first max(_time) as last '
            f'where {lab_idx} by index sourcetype '
            '| eval days=round((last-first)/86400) | sort - count | table index sourcetype count days', 860, 160, 580, 470)
    out.append(d)
    return out


# ---------------------------------------------------------------------
# App files
# ---------------------------------------------------------------------

def app_icons():
    svg = ICON_SVG.read_text().replace('stroke="currentColor"', f'stroke="{ACCENT}"').replace('stroke-width="2"', 'stroke-width="1.8"')
    for name, size, bg in [("appIcon", 36, "#07182D"), ("appIcon_2x", 72, "#07182D"), ("appIconAlt", 36, "#07182D"), ("appIconAlt_2x", 72, "#07182D")]:
        glyph = subprocess.run(["rsvg-convert", "-w", str(int(size * 0.7)), "-h", str(int(size * 0.7))], input=svg.encode(),
                               capture_output=True, check=True).stdout
        im = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        ImageDraw.Draw(im).rounded_rectangle([0, 0, size - 1, size - 1], radius=size // 6, fill=bg)
        g = Image.open(io.BytesIO(glyph)).convert("RGBA")
        im.alpha_composite(g, ((size - g.width) // 2, (size - g.height) // 2))
        (APP / "static").mkdir(parents=True, exist_ok=True)
        im.save(APP / "static" / f"{name}.png")


def build():
    if APP.exists():
        shutil.rmtree(APP)
    write("default/app.conf", f"""[install]
is_configured = true

[package]
id = integrity_tech_detections
check_for_updates = false

[launcher]
author = Rama Vadlamudi
description = Detections, hunts and dashboards for Integrity Tech (AA26-281A, Flax Typhoon). Runs on CIM-mapped data; risk and findings need Enterprise Security 8.
version = {VERSION}

[ui]
is_visible = true
label = Integrity Tech Detections
""")
    write("metadata/default.meta", "[]\naccess = read : [ * ], write : [ admin ]\nexport = system\n")
    write("default/macros.conf", """# Where the detections look. Point these at your own indexes.
[aa26_iis]
definition = (index=exchange OR index=web) sourcetype=ms:iis:auto
iseval = 0

[aa26_o365]
definition = index=o365 sourcetype=o365:management:activity
iseval = 0
""")
    write("default/savedsearches.conf", "# Generated by build_detection_app.py from generate_lab_data.DETECTIONS.\n\n"
          + "\n".join(lab.detection_stanzas()))
    transforms = []
    for name, opts in LOOKUPS.items():
        transforms += [f"[{name}]", f"filename = {name}.csv"] + [f"{k} = {v}" for k, v in opts.items()] + [""]
    write("default/transforms.conf", "\n".join(transforms))
    (APP / "lookups").mkdir(parents=True, exist_ok=True)
    for name in LOOKUPS:
        if (TA_LOOKUPS / f"{name}.csv").exists():
            shutil.copy(TA_LOOKUPS / f"{name}.csv", APP / "lookups" / f"{name}.csv")

    rows = []
    alld = lab.DETECTIONS + [dict(lab.THRESHOLD, mitre=[], risk=[], cron="30 * * * *")]
    order = sorted(alld, key=lambda d: (STAGES.index(CATALOG[d["name"]][0]), d["name"]))
    for i, d in enumerate(order, 1):
        stage, source = CATALOG[d["name"]]
        finding = d["name"] == lab.THRESHOLD["name"]
        rows.append([i, STAGES.index(stage) + 1, stage, d["name"], rule(d["name"]), "Finding" if finding else "Detection",
                     " ".join(d["mitre"]), source, ", ".join(f"{f} +{s}" for f, _, s in d["risk"]) or "raises a finding",
                     EXPECTED["backtest"][d["name"]], d["desc"]])
    write_csv("lookups/itd_detection_catalog.csv", ["order", "order_stage", "stage", "detection", "rule", "type", "mitre",
                                                    "data_source", "risk", "lab_rows", "description"], rows)
    write_csv("lookups/itd_readiness.csv", ["behaviour", "status", "evidence", "detections"], READINESS)
    write_csv("lookups/itd_response_actions.csv", ["priority", "finding", "entity", "evidence", "confidence", "action", "owner",
                                                   "approval", "status"], ACTIONS)
    write_csv("lookups/itd_controls.csv", ["order", "stage", "activity", "prevent", "detect", "detections"], CONTROLS)
    known = {d["name"] for d in lab.DETECTIONS}
    assert all(n in known for c in CONTROLS for n in c[5].split("; ")), "controls reference an unknown detection"

    views = dashboards()
    for d in views:
        write(f"default/data/ui/views/{d.view}.xml", d.xml())
    write("default/data/ui/nav/default.xml", """<nav search_view="search" color="#07182D">
  <view name="itd_overview" default="true" />
  <view name="itd_storyline" />
  <collection label="Hunts">
    <view name="itd_exposure" />
    <view name="itd_recon" />
    <view name="itd_persistence" />
    <view name="itd_collection" />
  </collection>
  <view name="itd_investigate" />
  <view name="itd_response" />
  <view name="itd_readiness" />
  <view name="itd_detections" />
  <view name="search" />
</nav>
""")
    app_icons()
    write("README.md", f"""# Integrity Tech Detections {VERSION}

Detections, hunts and dashboards for Integrity Technology Group activity described in joint advisory AA26-281A (8 Oct 2026),
tracked by industry as Flax Typhoon. Built for "From Advisory to Detection" (ADF Cyber Skills Challenge 2026).

## What's inside

- {len(lab.DETECTIONS)} behaviour detections and 1 finding (`AA26-281A - * - Rule`), as Enterprise Security 8 event-based detections.
  Each writes risk to the user or system involved; "Integrity Tech behaviour chain" raises a finding at risk 100 across 3 ATT&CK tactics.
- Dashboards, in the order an analyst uses them:
  - **Threat overview**: what the detections found, who is over the risk threshold, and readiness. Click any number to dig in.
  - **Incident storyline**: every signal linked to one identity, its workstation and the addresses that used it, in order,
    including evidence no detection covered and the behaviours you cannot see.
  - **Hunts**: exposure (the advisory's CVEs in your estate and who tried them), reconnaissance and initial access (with the
    sign-in that worked), SoftEther persistence, and mailbox collection (with the app's audit trail).
  - **Investigate**: one user or host, risk in order, sign-in sources and context.
  - **Defender action centre**: prioritised actions with evidence, owner, approval and status, plus defence by stage.
  - **Readiness**: telemetry you have, behaviours you can prove you would see, and the gaps.
  - **Detection library**: every detection, its data, schedule and lab result.
- Lookups: the advisory's and the DOJ seizure's indicators (with confidence and expiry), the advisory's eight exploited CVEs,
  approved scanners, approved remote access, approved mail apps, a detection catalogue, the readiness register, response actions
  and defence-by-stage controls.

## Make it yours

1. Point the `aa26_iis` and `aa26_o365` macros at your indexes. The other detections read CIM data models.
2. Replace the sample approved lists (`aa26_approved_scanners`, `aa26_approved_remote_access`, `approved_mail_apps`) and the
   asset and identity lookups with your own registers.
3. Enable 4662 auditing with the replication SACL on domain controllers, or the DCSync detection has nothing to read.
4. Update `itd_readiness.csv` with your own statuses: it drives the readiness dashboard.
5. Replace `aa26_lab_vulns.csv` with your vulnerability inventory, and `itd_response_actions.csv` with your owners and
   approval rules.

The dashboards open on the lab's scenario window ({WINDOW['earliest_local'][:10]} to {WINDOW['latest_local'][:10]}). Change the
time picker for your own data. Lab and synthetic data only: test in a non-production instance first.

Icons: Tabler Icons (MIT).
""")
    dist = HERE / "dist" / f"{APP.name}.tgz"
    dist.parent.mkdir(exist_ok=True)
    with tarfile.open(dist, "w:gz") as tar:
        tar.add(APP, arcname=APP.name, filter=lambda ti: None if "__pycache__" in ti.name or ti.name.endswith(".DS_Store") else ti)
    print(f"{APP.name}: {len(lab.DETECTIONS) + 1} detections, {len(views)} dashboards, {len(LOOKUPS)} lookups -> {dist} "
          f"({dist.stat().st_size / 1e3:,.0f} KB)")


if __name__ == "__main__":
    build()
