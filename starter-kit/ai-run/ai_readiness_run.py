"""Recorded AI run: "which AA26-281A behaviours can't we detect?", answered by a locally hosted model from real lab search results.

The model never sees the readiness register or the answer. It gets the advisory's seven behaviours and the raw output of
read-only telemetry searches, then must give a verdict, quote its evidence and propose a search to prove each gap.
Its proposed searches are run back against the lab (read-only commands only) so the analyst can check them.

Lab use only. Connection details come from the environment, never from this file:
    SPLUNK_URL=https://<lab-host>:8089 SPLUNK_USER=... SPLUNK_PASSWORD=... python3 ai_readiness_run.py
Optional: OLLAMA_URL (default http://localhost:11434), MODEL (default gemma3:12b).
Re-run only the proving searches of a saved run: python3 ai_readiness_run.py ai-run/<timestamp>
"""

import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()

SPLUNK = os.environ.get("SPLUNK_URL")
AUTH = (os.environ.get("SPLUNK_USER", ""), os.environ.get("SPLUNK_PASSWORD", ""))
OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("MODEL", "gemma3:12b")
OUT = Path(__file__).parent / "ai-run"
SCOPE = "index IN (dns, exchange, firewall, o365, sysmon, web, wineventlog)"
FORBIDDEN = re.compile(r"\|\s*(delete|outputlookup|outputcsv|collect|sendemail|script|run|map|rest|tscollect|sendalert)\b", re.I)

EVIDENCE = [
    ("Data inventory (the SOC's scenario indexes)",
     f"| tstats count min(_time) as first max(_time) as last where {SCOPE} by index sourcetype"
     " | eval first=strftime(first,\"%F\"), last=strftime(last,\"%F\")"),
    ("Windows Security and System event codes collected",
     "search index=wineventlog | stats count by EventCode"),
    ("Sysmon endpoint telemetry: event codes and host count",
     "search index=sysmon | stats count dc(host) as hosts by EventCode"),
    ("Asset inventory by category, and how many of those hosts send any log",
     f"| inputlookup aa26_lab_assets | join type=left host [| tstats count as events where {SCOPE} by host]"
     " | eval sends_logs=if(events>0,\"yes\",\"no\") | stats count by category internet_facing sends_logs"),
    ("Vulnerable appliances from the vulnerability inventory, and whether they send logs",
     f"| inputlookup aa26_lab_vulns | join type=left host [| tstats count as events where {SCOPE} by host]"
     " | fillnull value=0 events | table host product cve internet_facing events"),
    ("Microsoft 365 mailbox audit coverage",
     "search index=o365 Operation=MailItemsAccessed | stats dc(MailboxOwnerUPN) as audited_mailboxes"
     " | appendcols [| inputlookup aa26_lab_identities | stats count as total_identities]"),
    ("Microsoft 365 audit operations present",
     "search index=o365 | stats count by Operation"),
    ("Firewall fields populated",
     "search index=firewall | fieldsummary | search field IN (src, dest, dest_port, bytes_in, bytes_out, action, app)"
     " | table field count distinct_count"),
    ("Exchange and web server (IIS) fields populated",
     "search index=exchange OR index=web | fieldsummary"
     " | search field IN (c_ip, cs_username, cs_uri_stem, sc_status, cs_User_Agent) | table field count distinct_count"),
    ("DNS fields populated",
     "search index=dns | fieldsummary | search field IN (src, query, answer) | table field count distinct_count"),
]

BEHAVIOURS = """1. Reconnaissance: scanning of internet-facing services on ports 21, 22, 53, 80, 443 and 1080.
2. Exploitation of public-facing applications: eight CVEs including ProFTPD, ISC BIND, Pulse Connect Secure, GitLab and Bash, plus XSS against web pages.
3. Password spraying against Exchange (EBurst) across several Exchange interfaces.
4. Persistence with a renamed SoftEther VPN client on Windows and Linux hosts, using SoftEther dynamic DNS.
5. Credential theft by DCSync (Active Directory replication requested by a non-domain-controller account).
6. Mailbox collection through Exchange Web Services and an application granted mail access.
7. Exfiltration of collected data to actor-controlled servers."""

PROMPT = """You are helping a SOC analyst. Use ONLY the telemetry evidence below; it is the output of searches run in this Splunk environment. Do not assume data that is not shown.

Question: Based on the telemetry in this Splunk environment, which AA26-281A behaviours can we detect, which can't we, and why?

The seven behaviours, from the advisory:
{behaviours}

Telemetry evidence:
{evidence}

Answer in this exact format:
1. A markdown table with columns: Behaviour | Verdict (Detectable, Partial or Not detectable) | Evidence (quote the evidence that supports the verdict) | Missing telemetry.
2. Then, for every behaviour that is Partial or Not detectable, one Splunk SPL search that would prove the gap in this environment, in a ```spl code block, preceded by the behaviour number.
Be concise. If the evidence does not show something, say it is not shown."""


def search(spl):
    r = requests.post(f"{SPLUNK}/services/search/jobs/export", auth=AUTH, verify=False, timeout=180,
                      data={"search": spl, "output_mode": "json", "earliest_time": "0", "latest_time": "now"})
    r.raise_for_status()
    rows, errors = [], []
    for line in r.text.splitlines():
        if not line.strip():
            continue
        msg = json.loads(line)
        if "result" in msg:
            rows.append(msg["result"])
        errors += [m["text"] for m in msg.get("messages", []) if m.get("type") in ("ERROR", "FATAL")]
    return rows, errors


def as_text(rows):
    if not rows:
        return "(no results)"
    cols = list(dict.fromkeys(k for r in rows for k in r if not k.startswith("_")))
    lines = [" | ".join(cols)]
    for r in rows:
        lines.append(" | ".join(", ".join(v) if isinstance(v := r.get(c, ""), list) else str(v) for c in cols))
    return "\n".join(lines)


def check(answer):
    """Run each SPL block the model proposed, read-only and capped at 500 rows, so the analyst can see what it returns."""
    checks = []
    for n, m in enumerate(re.finditer(r"```(?:spl|splunk)?[ \t]*\n(.*?)```", answer, re.S), 1):
        spl = " ".join(m.group(1).split())
        entry = {"proposed": n, "spl": spl}
        if FORBIDDEN.search(spl):
            checks.append(entry | {"status": "not run: non-read-only command"})
            continue
        run = spl if spl.startswith("|") or spl.lower().startswith("search ") else "search " + spl
        try:
            rows, errors = search(run + " | head 500")
            entry |= {"row_count": len(rows), "rows": rows[:5], "errors": errors}
        except requests.HTTPError as e:
            entry |= {"status": f"search failed: HTTP {e.response.status_code}", "detail": e.response.text[:400]}
        checks.append(entry)
    return checks


def recheck(run_dir):
    """Re-run the proving searches of a saved run without asking the model again."""
    path = Path(run_dir) / "run.json"
    record = json.loads(path.read_text())
    record["proving_searches"] = check(record["answer"])
    path.write_text(json.dumps(record, indent=2))
    for c in record["proving_searches"]:
        print(f"  {c['proposed']}: {c.get('status') or str(c['row_count']) + ' rows'} {c.get('errors') or ''}  {c['spl']}")


def main():
    if not SPLUNK or not AUTH[0]:
        sys.exit("Set SPLUNK_URL, SPLUNK_USER and SPLUNK_PASSWORD for the lab instance.")
    if len(sys.argv) > 1:
        return recheck(sys.argv[1])
    stamp = dt.datetime.now().strftime("%Y-%m-%d_%H%M")
    run_dir = OUT / stamp
    run_dir.mkdir(parents=True, exist_ok=True)

    blocks, evidence_log = [], []
    for title, spl in EVIDENCE:
        rows, errors = search(spl)
        text = as_text(rows)
        blocks.append(f"## {title}\nSearch: {spl}\n{text}")
        evidence_log.append({"title": title, "spl": spl, "rows": rows, "errors": errors})
    prompt = PROMPT.format(behaviours=BEHAVIOURS, evidence="\n\n".join(blocks))

    t0 = time.time()
    r = requests.post(f"{OLLAMA}/api/generate", timeout=900, json={
        "model": MODEL, "prompt": prompt, "stream": False, "options": {"temperature": 0, "seed": 7, "num_ctx": 16384}})
    r.raise_for_status()
    gen = r.json()
    answer = gen["response"].strip()
    elapsed = time.time() - t0

    checks = check(answer)
    record = {"model": MODEL, "runtime": "Ollama, local", "ollama_version": requests.get(f"{OLLAMA}/api/version").json().get("version"),
              "options": {"temperature": 0, "seed": 7}, "started": stamp, "generation_seconds": round(elapsed, 1),
              "eval_tokens": gen.get("eval_count"), "evidence": evidence_log, "prompt": prompt, "answer": answer,
              "proving_searches": checks}
    (run_dir / "run.json").write_text(json.dumps(record, indent=2))
    (run_dir / "prompt.txt").write_text(prompt)
    (run_dir / "answer.md").write_text(answer + "\n")
    print(answer)
    print(f"\n--- {MODEL} via Ollama, {elapsed:.0f}s; {len(checks)} proving searches run; saved to {run_dir}")
    for c in checks:
        print(f"  {c['proposed']}: {c.get('status') or str(c['row_count']) + ' rows'} {c.get('errors') or ''}  {c['spl']}")


if __name__ == "__main__":
    main()
