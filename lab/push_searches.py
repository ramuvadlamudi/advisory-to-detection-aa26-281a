#!/usr/bin/env python3
"""Push the AA26 saved reports from the app's savedsearches.conf to a running lab instance over REST.

Use this when the app is already installed and only saved searches changed (new reports, new descriptions), so nothing is
re-uploaded or re-indexed. Creates missing reports and updates existing ones in the app's namespace.

  SPLUNK_MGMT=https://<lab-splunk>:8089 SPLUNK_USERNAME=<user> python3 push_searches.py
  python3 labctl.py validate
"""
import re
import urllib.parse
from pathlib import Path

from labctl import APP_NAME, Splunk

CONF = Path(__file__).resolve().parent / "TA-aa26-281a-lab" / "default" / "savedsearches.conf"
KEYS = ("description", "search", "dispatch.earliest_time", "dispatch.latest_time")


def stanzas(text):
    out, name, buf = {}, None, []
    for line in text.splitlines():
        m = re.match(r"^\[(.+)\]$", line)
        if m:
            name = m.group(1)
            out[name] = {}
            continue
        if name is None:
            continue
        if buf:
            buf.append(line)
        elif " = " in line:
            k, v = line.split(" = ", 1)
            buf = [f"{k} = {v}"]
        if buf and not buf[-1].endswith("\\"):
            k, v = "\n".join(b[:-1] if b.endswith("\\") else b for b in buf).split(" = ", 1)
            out[name][k] = v
            buf = []
    return out


def main():
    sp = Splunk()
    base = f"/servicesNS/nobody/{APP_NAME}/saved/searches"
    have = {e["name"] for e in sp.call(base, {"count": 0, "search": "AA26"}, method="GET")["entry"]}
    for name, conf in stanzas(CONF.read_text()).items():
        if not name.startswith("AA26 "):
            continue
        body = {k: conf[k] for k in KEYS if k in conf}
        if name in have:
            sp.call(f"{base}/{urllib.parse.quote(name, safe='')}", body)
            print(f"updated  {name}")
        else:
            sp.call(base, {"name": name, **body})
            print(f"created  {name}")


if __name__ == "__main__":
    main()
