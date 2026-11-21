#!/usr/bin/env python3
"""Install, load, seed, validate and backtest the AA26-281A demo lab on a lab Splunk instance.

  python3 labctl.py all        # install app + restart, load data, seed risk, validate
  python3 labctl.py install    # copy TA-aa26-281a-lab (with its bundled data) into $SPLUNK_HOME/etc/apps and restart
  python3 labctl.py load       # wait until the app's monitored files are fully indexed
  python3 labctl.py seed       # run output/seed_risk.spl (writes the lab's intermediate findings to index=risk)
  python3 labctl.py validate   # run every "AA26 ..." saved search and compare with output/expected.json
  python3 labctl.py backtest   # run every "AA26-281A - ... - Rule" detection over the scenario window, actions off
  python3 labctl.py reset      # stop Splunk, empty the lab indexes, start Splunk (risk events are left in place)

Credentials come from SPLUNK_USERNAME / SPLUNK_PASSWORD, or you are prompted.
Lab only: never point this at a production Splunk.
"""

import argparse
import base64
import getpass
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP_NAME = "TA-aa26-281a-lab"
DETECTION_APP = "integrity_tech_detections"
OUT = HERE / "output"
LAB_INDEXES = ["exchange", "web", "o365", "wineventlog", "sysmon", "firewall", "dns"]
SPLUNK_HOME = Path(os.environ.get("SPLUNK_HOME", "/Applications/Splunk"))
MGMT = os.environ.get("SPLUNK_MGMT", "https://localhost:8089")


class Splunk:
    def __init__(self):
        user = os.environ.get("SPLUNK_USERNAME") or input("Splunk username [admin]: ").strip() or "admin"
        pw = os.environ.get("SPLUNK_PASSWORD") or getpass.getpass(f"Password for {user}: ")
        self.auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def call(self, path, data=None, method=None):
        body = urllib.parse.urlencode({"output_mode": "json", **(data or {})}, doseq=True).encode()
        url = f"{MGMT}{path}"
        if method == "GET":
            url, body = f"{url}?{body.decode()}", None
        req = urllib.request.Request(url, data=body, headers={"Authorization": self.auth}, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=600) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise SystemExit(f"Splunk REST {e.code} on {path}: {e.read().decode()[:400]}")

    def search(self, spl, earliest=None, latest=None):
        args = {"search": spl if spl.lstrip().startswith("|") else f"search {spl}", "exec_mode": "blocking"}
        if earliest is not None:
            args.update(earliest_time=earliest, latest_time=latest)
        sid = self.call("/services/search/jobs", args)["sid"]
        return self.results(sid)

    def dispatch(self, name, app=APP_NAME, **args):
        path = f"/servicesNS/nobody/{app}/saved/searches/{urllib.parse.quote(name, safe='')}/dispatch"
        sid = self.call(path, args)["sid"]
        while True:
            job = self.call(f"/services/search/jobs/{sid}", method="GET")["entry"][0]["content"]
            if job["isDone"]:
                break
            time.sleep(1)
        return self.results(sid)

    def results(self, sid):
        return self.call(f"/services/search/jobs/{sid}/results", {"count": 0}, method="GET").get("results", [])


def splunk_cli(*args):
    return subprocess.run([str(SPLUNK_HOME / "bin" / "splunk"), *args], check=False)


def install(_):
    for name in (APP_NAME, DETECTION_APP):
        dest = SPLUNK_HOME / "etc" / "apps" / name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(HERE / name, dest)
        print(f"Installed {name} to {dest}")
    running = subprocess.run([str(SPLUNK_HOME / "bin" / "splunk"), "status"], capture_output=True, text=True).stdout
    splunk_cli("restart" if "splunkd is running" in running else "start", "--accept-license", "--answer-yes", "--no-prompt")


def manifest():
    return json.loads((OUT / "manifest.json").read_text())


def add_lab_indexes(sp):
    role = sp.call("/services/authorization/roles/admin", method="GET")["entry"][0]["content"]
    have = role["srchIndexesDefault"]
    missing = [i for i in LAB_INDEXES if i not in have]
    if missing:
        sp.call("/services/authorization/roles/admin", {"srchIndexesDefault": have + missing,
                                                         "srchIndexesAllowed": role["srchIndexesAllowed"]})
        print("Added to the admin role's default search indexes:", ", ".join(missing))


def load(sp):
    add_lab_indexes(sp)
    m = manifest()
    want = {}
    for f in m["files"]:
        want[f["index"]] = want.get(f["index"], 0) + f["events"]
    print("Waiting for indexing", end="", flush=True)
    for _ in range(180):
        rows = sp.search(f"| tstats count where index IN ({','.join(want)}) by index", 0, "now")
        have = {r["index"]: int(r["count"]) for r in rows}
        if all(have.get(i, 0) >= n for i, n in want.items()):
            print(" done")
            for i, n in want.items():
                print(f"  {i:<12} {have[i]:>8,} events" + ("  <- MORE THAN EXPECTED: indexed twice?" if have[i] > n else ""))
            if any(have[i] > n for i, n in want.items()):
                print("Some files were indexed twice (this can happen when the app is re-uploaded). Run 'labctl.py reset' on the "
                      "Splunk host, or delete the newer copy by _indextime as a user with can_delete.")
            return
        print(".", end="", flush=True)
        time.sleep(5)
    print("\nTimed out waiting; indexed so far:", have)


def seed(sp, force=False):
    """Seed each detection's risk events once. Sources already in index=risk are skipped unless --force."""
    have = {r["source"] for r in sp.search('search index=risk aa26_lab=1 | stats count by source', 0, "now")}
    for line in (OUT / "seed_risk.spl").read_text().splitlines():
        if not line.strip():
            continue
        source = line.split('source="')[1].split('"')[0]
        if source in have and not force:
            print("  already seeded", source)
            continue
        sp.search(line)
        print("  seeded", source)


def validate(sp):
    exp = json.loads((OUT / "expected.json").read_text())
    m = manifest()

    def find(rows, **kv):
        return [r for r in rows if all(str(r.get(k)) == str(v) for k, v in kv.items())]

    def mv(r, k):
        v = r.get(k)
        return v if isinstance(v, list) else [v]

    per_index = {}
    for f in m["files"]:
        per_index[f["index"]] = per_index.get(f["index"], 0) + f["events"]
    sp_row = exp["spray"][0]
    checks = [
        ("AA26 01 - Telemetry discovery", lambda r: all(sum(int(x["count"]) for x in find(r, index=i)) == n for i, n in per_index.items()),
         ", ".join(f"{i} {n:,}" for i, n in per_index.items())),
        ("AA26 02 - Are the fields we need populated", lambda r: len(r) == 5, "5 fields populated"),
        ("AA26 03 - Detection 1 - Exchange password spray",
         lambda r: any(x["c_ip"] == sp_row["c_ip"] and int(x["users"]) == sp_row["users"] and int(x["interfaces"]) == sp_row["interfaces"]
                       and mv(x, "ok") == sp_row["ok"] for x in r) and len(r) == len(exp["spray"]),
         f"{sp_row['c_ip']} users {sp_row['users']} interfaces {sp_row['interfaces']} ok {sp_row['ok'][0]}"),
        ("AA26 04 - Detection 2 - Network scanning",
         lambda r: len(r) == len(exp["recon_network"]) and any(x["All_Traffic.src"] == "203.0.113.47" and int(x["hosts"]) == 41 for x in r),
         f"{len(exp['recon_network'])} rows incl. 203.0.113.47 with 41 hosts"),
        ("AA26 05 - Detection 2 - Web enumeration",
         lambda r: len(r) == 1 and int(r[0]["paths"]) == exp["recon_web"][0]["paths"], f"1 row, {exp['recon_web'][0]['paths']} paths"),
        ("AA26 06 - Detection 3 - SoftEther process",
         lambda r: len(r) == len(exp["softether_process"]) and any(
             x["Processes.original_file_name"] == "vpnbridge.exe" and int(x["count"]) == 2 for x in r),
         "WS-0417 conhost.exe vpnbridge.exe x2, plus the approved SoftEther client"),
        ("AA26 07 - Detection 3 - SoftEther DNS",
         lambda r: len(r) == 1 and int(r[0]["count"]) == exp["softether_dns"][0]["count"], f"{exp['softether_dns'][0]['count']} lookups"),
        ("AA26 08 - Shipped ES detection - SoftEther masquerading",
         lambda r: len(r) == 1 and int(r[0]["count"]) == 2, "WS-0417, 2 starts"),
        ("AA26 09 - Detection 4 - EWS volume",
         lambda r: len(r) == 1 and r[0]["cs_username"] == "j.citizen" and int(r[0]["calls"]) == 2400, "j.citizen 2,400 calls"),
        ("AA26 10 - Detection 4 - Unapproved app reading mailboxes",
         lambda r: len(r) == 1 and int(r[0]["mailboxes"]) == 7, "1 app, 7 mailboxes"),
        ("AA26 11 - Detection 4 - New app secrets and consents", lambda r: len(r) == 1, "1 new secret"),
        ("AA26 12 - Detection 5 - DCSync", lambda r: len(r) == 0, "no results (the gap)"),
        ("AA26 13 - Detection 5 - Staging file names", lambda r: len(r) == len(exp["staging"]), f"{len(exp['staging'])} files"),
        ("AA26 14 - Step 4 - Risk",
         lambda r: len(r) == len(exp["risk"]) and all(
             any(x["All_Risk.risk_object"] == e["risk_object"] and float(x["risk"]) == e["risk"] and int(x["tactics"]) == e["tactics"]
                 for x in r) for e in exp["risk"]),
         "; ".join(f"{e['risk_object']} risk {e['risk']}, {e['tactics']} tactics" for e in exp["risk"])),
        ("AA26 15 - A1 - CIM Authentication spray",
         lambda r: any(x["Authentication.src"] == exp["auth_spray"][0]["src"] and int(x["users"]) == exp["auth_spray"][0]["users"] for x in r),
         f"{exp['auth_spray'][0]['src']}, {exp['auth_spray'][0]['users']} users"),
        ("AA26 16 - A2 - New services outside system paths", lambda r: len(r) == len(exp["new_services"]), f"{len(exp['new_services'])} services"),
        ("AA26 17 - A3 - Upload-heavy hosts",
         lambda r: sorted((x["All_Traffic.src"], int(x["MB_out"])) for x in r) == sorted((e["src"], e["MB_out"]) for e in exp["upload_hours"]),
         f"{len(exp['upload_hours'])} hours from " + ", ".join(sorted({e['src'] for e in exp['upload_hours']}))),
        ("AA26 18 - A4 - Indicator sweep",
         lambda r: sorted((x["DNS.src"], x["DNS.query"]) for x in r) == sorted((e["src"], e["query"]) for e in exp["ioc_sweep"]),
         ", ".join(f"{e['src']} {e['query']}" for e in exp["ioc_sweep"])),
        ("AA26 19 - Pivot - What happened on WS-0417", lambda r: len(r) == len(exp["pivot"]), f"{len(exp['pivot'])} events"),
        ("AA26 20 - Detection 5 - FishHub-style stager",
         lambda r: sorted(x["Processes.process_name"] for x in r) == sorted(e["process_name"] for e in exp["fishhub"]),
         " + ".join(f"{e['parent_process_name']} > {e['process_name']}" for e in exp["fishhub"])),
        ("AA26 21 - A4 - Known-bad IP sweep",
         lambda r: sorted((x["All_Traffic.src"], x["All_Traffic.dest"]) for x in r) == sorted(map(tuple, exp["ioc_ip"])),
         ", ".join(f"{s} > {d}" for s, d in exp["ioc_ip"])),
        ("AA26 22 - SoftEther - Evidence correlated by host",
         lambda r: sorted((x["host"], int(x["signals"])) for x in r) == sorted((e["host"], e["signals"]) for e in exp["softether_corr"]),
         ", ".join(f"{e['host']} {e['signals']}" for e in exp["softether_corr"])),
        ("AA26 23 - SoftEther - Tuned detection",
         lambda r: sorted((x["dest"], x["process_path"]) for x in r) == sorted((e[0], e[3]) for e in exp["softether_tuned"]),
         ", ".join(e[0] for e in exp["softether_tuned"])),
        ("AA26 24 - Investigate - Risk events for j.citizen", lambda r: len(r) == 6 and sum(float(x["risk_score"]) for x in r) == 200,
         "6 events totalling 200"),
        ("AA26 25 - Investigate - Where j.citizen signs in from",
         lambda r: sorted((x["c_ip"], x["seen_before"], int(x["count"])) for x in r)
         == sorted((e["c_ip"], e["seen_before"], e["count"]) for e in exp["signin"]),
         ", ".join(f"{e['c_ip']} {e['seen_before']}" for e in exp["signin"])),
        ("AA26 26 - Investigate - Identity and asset context", lambda r: len(r) == 2 and all(x["priority"] == "high" for x in r),
         "j.citizen and a.lim, both high priority"),
        ("AA26 27 - Exposure - Vulnerable vs targeted",
         lambda r: sorted((x["host"], x["state"]) for x in r) == sorted((e["host"], e["state"]) for e in exp["vuln_state"]),
         ", ".join(f"{e['host']} {e['state'].split(':')[0]}" for e in exp["vuln_state"])),
        ("AA26 28 - AI - First draft with assumed fields", lambda r: len(r) == 0, "no results (wrong field names)"),
        ("AA26 29 - Recon - Scanner profile",
         lambda r: len(r) == 3 and {x["src"]: x["verdict"] for x in r} == {"10.20.0.50": "approved scanner", "198.51.100.77": "background scanning", "203.0.113.47": "scanned, then signed in"},
         "10.20.0.50 approved, 198.51.100.77 background, 203.0.113.47 scanned then signed in"),
        ("AA26 30 - Exposure - Exploit attempts by source",
         lambda r: sorted((x["src"], int(x["techniques"]), int(x["requests"]), int(x["answered"]), x["verdict"]) for x in r)
         == sorted((e["src"], e["techniques"], e["requests"], e["answered"], e["verdict"]) for e in exp["exploit_sources"]),
         ", ".join(f"{e['src']} {e['techniques']} techniques ({e['verdict']})" for e in exp["exploit_sources"])),
        ("AA26 31 - Exposure - Advisory CVEs in our estate",
         lambda r: sorted((x["cve"], x["priority"], x.get("telemetry")) for x in r)
         == sorted((e["cve"], e["priority"], e["telemetry"]) for e in exp["advisory_cves"])
         and all(sorted(" ".join(mv(x, "attempted_by")).split()) == e["attempted_by"] for x in r for e in exp["advisory_cves"] if e["cve"] == x["cve"] and e["attempted_by"]),
         "8 CVEs; patch now: " + ", ".join(e["asset"] for e in exp["advisory_cves"] if e["priority"].startswith("1"))),
    ]
    failed = 0
    for name, ok, want in checks:
        rows = sp.dispatch(name)
        good = False
        try:
            good = ok(rows)
        except (KeyError, ValueError, TypeError, IndexError):
            pass
        failed += not good
        print(f"  {'PASS' if good else 'FAIL'}  {name}  (expected: {want}; got {len(rows)} rows)")
        if not good:
            for r in rows[:5]:
                print("        ", {k: v for k, v in r.items() if not k.startswith("_") or k == "_time"})
    print(f"\n{len(checks) - failed}/{len(checks)} checks passed")
    return failed


def backtest(sp):
    exp = json.loads((OUT / "expected.json").read_text())
    w = manifest()["window"]
    failed = 0
    for short, want in exp["backtest"].items():
        name = f"AA26-281A - {short} - Rule"
        rows = sp.dispatch(name, DETECTION_APP, **{"dispatch.earliest_time": w["earliest"], "dispatch.latest_time": w["latest"], "trigger_actions": 0})
        good = len(rows) == want
        failed += not good
        print(f"  {'PASS' if good else 'FAIL'}  {name}  (expected {want} rows; got {len(rows)})")
        if not good:
            for r in rows[:5]:
                print("        ", {k: v for k, v in r.items() if not k.startswith("_") or k == "_time"})
    print(f"\n{len(exp['backtest']) - failed}/{len(exp['backtest'])} detections behaved as expected")
    return failed


def findings(sp):
    """Run the behaviour-chain finding once over the scenario window, with its actions on, so ES shows the two findings."""
    name = "AA26-281A - Integrity Tech behaviour chain - Rule"
    have = sp.search(f'search index=notable search_name="{name}" | stats count', 0, "now")
    if have and int(have[0]["count"]):
        print(f"{have[0]['count']} findings from '{name}' already in ES; skipping")
        return
    w = manifest()["window"]
    rows = sp.dispatch(name, DETECTION_APP, **{"dispatch.earliest_time": w["earliest"], "dispatch.latest_time": w["latest"], "trigger_actions": 1})
    print(f"Raised {len(rows)} findings: " + ", ".join(f"{r['risk_object']} (risk {r['risk_score']}, {r['tactics']} tactics)" for r in rows))


def reset(_):
    splunk_cli("stop")
    for i in LAB_INDEXES:
        splunk_cli("clean", "eventdata", "-index", i, "-f")
    splunk_cli("start")
    print("Lab indexes emptied. Seeded findings in index=risk remain; remove them with "
          "'index=risk aa26_lab=1 | delete' as a user with the can_delete role.")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["all", "install", "load", "seed", "findings", "validate", "backtest", "reset"])
    ap.add_argument("--force", action="store_true", help="seed even if lab findings already exist")
    args = ap.parse_args()
    if not (OUT / "manifest.json").exists() and args.command not in ("install", "reset"):
        raise SystemExit("Run generate_lab_data.py first.")
    if args.command in ("install", "reset"):
        return (install if args.command == "install" else reset)(None)
    if args.command == "all":
        install(None)
    sp = Splunk()
    if args.command in ("all", "load"):
        load(sp)
    if args.command in ("all", "seed"):
        seed(sp, args.force)
    if args.command in ("all", "findings"):
        findings(sp)
    failed = 0
    if args.command in ("all", "validate"):
        failed += validate(sp)
    if args.command in ("all", "backtest"):
        failed += backtest(sp)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
