#!/usr/bin/env python3
"""Upload an app (the lab app by default) to a remote lab Splunk through Splunk Web, then restart Splunk.

  python3 upload_app.py https://splunk-lab:8000 [--app integrity_tech_detections] [--skip-data FILE ...] [--no-restart]

--skip-data leaves named data files out of the uploaded package. Use it for files the instance has already indexed:
Splunk can re-read a monitored file when an app upload replaces it, which would index it twice.
Credentials come from SPLUNK_USERNAME / SPLUNK_PASSWORD. Lab only: never point this at a production Splunk.
"""

import argparse
import http.cookiejar
import io
import os
import re
import ssl
import tarfile
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP = HERE / "TA-aa26-281a-lab"


def package(app, skip):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def keep(ti):
            if "__pycache__" in ti.name or ti.name.endswith(".DS_Store"):
                return None
            if "/data/" in ti.name and ti.name.rsplit("/", 1)[-1] in skip:
                return None
            return ti
        tar.add(app, arcname=app.name, filter=keep)
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("web", help="Splunk Web base URL, e.g. https://10.0.0.5:8000")
    ap.add_argument("--mgmt", help="management URL (default: same host, port 8089)")
    ap.add_argument("--skip-data", nargs="*", default=[], help="data file names to leave out")
    ap.add_argument("--locale", default="en-GB")
    ap.add_argument("--app", default=APP.name, help="app directory next to this script (default: the lab app)")
    ap.add_argument("--no-restart", action="store_true", help="skip the restart, e.g. before uploading a second app")
    a = ap.parse_args()
    user, pw = os.environ.get("SPLUNK_USERNAME", "admin"), os.environ["SPLUNK_PASSWORD"]
    web = a.web.rstrip("/")
    mgmt = a.mgmt or re.sub(r":\d+$", ":8089", web)
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(jar))
    op.open(f"{web}/{a.locale}/account/login").read()
    cval = next(c.value for c in jar if c.name == "cval")
    op.open(f"{web}/{a.locale}/account/login",
            urllib.parse.urlencode({"username": user, "password": pw, "cval": cval}).encode()).read()
    csrf = next(c.value for c in jar if c.name.startswith("splunkweb_csrf_token"))
    page = op.open(f"{web}/{a.locale}/manager/appinstall/_upload").read().decode()
    state = re.search(r'name="state" value="([^"]+)"', page).group(1)
    app = HERE / a.app
    blob = package(app, set(a.skip_data))
    b = uuid.uuid4().hex
    parts = []
    for k, v in (("splunk_form_key", csrf), ("state", state), ("force", "1")):
        parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{b}\r\nContent-Disposition: form-data; name="appfile"; filename="{app.name}.tgz"\r\n'
                 'Content-Type: application/x-gzip\r\n\r\n'.encode() + blob + b"\r\n")
    parts.append(f"--{b}--\r\n".encode())
    req = urllib.request.Request(f"{web}/{a.locale}/manager/appinstall/_upload", b"".join(parts),
                                 {"Content-Type": f"multipart/form-data; boundary={b}", "X-Splunk-Form-Key": csrf})
    resp = op.open(req).read().decode(errors="replace")
    print(f"Uploaded {len(blob) / 1e3:,.0f} KB; skipped {len(a.skip_data)} data files. Confirm with: | rest /services/apps/local/{app.name}")
    if a.no_restart:
        return
    import base64
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    r = urllib.request.Request(f"{mgmt}/services/server/control/restart", b"", {"Authorization": auth})
    urllib.request.urlopen(r, context=ctx).read()
    print("Restart requested; waiting for splunkd", end="", flush=True)
    time.sleep(20)
    for _ in range(60):
        try:
            urllib.request.urlopen(urllib.request.Request(f"{mgmt}/services/server/info", headers={"Authorization": auth}),
                                   context=ctx, timeout=5).read()
            print(" up")
            return
        except Exception:
            print(".", end="", flush=True)
            time.sleep(5)
    print(" still down; check the server")


if __name__ == "__main__":
    main()
