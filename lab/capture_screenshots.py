#!/usr/bin/env python3
"""Capture stage screenshots from the lab Splunk: the Integrity Tech Detections dashboards and key searches.

  SPLUNK_WEB=https://<lab-splunk>:8000 SPLUNK_USERNAME=<user> SPLUNK_PASSWORD=... python3 capture_screenshots.py [name ...]

Needs Playwright (pip3 install playwright) and Google Chrome. Writes PNGs to screenshots/. Lab only.
"""

import os
import re
import sys
import json
import urllib.parse
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
OUT = HERE / "screenshots"
WEB = os.environ.get("SPLUNK_WEB", "https://localhost:8000").rstrip("/") + "/en-GB"
APP = "integrity_tech_detections"

VIEWS = HERE / APP / "default" / "data" / "ui" / "views"


def view_height(view):
    """Viewport tall enough for the whole dashboard: the grid scales with the page width, plus Splunk's header."""
    grid = json.loads(re.search(r"<!\[CDATA\[(.*?)\]\]></definition>", (VIEWS / f"{view}.xml").read_text(), re.S).group(1))
    return int(grid["layout"]["options"]["height"] * 1.07 + 160)


# name -> (url path, viewport height, seconds to let panels finish)
WAIT = {"itd_exposure": 70, "itd_storyline": 60, "itd_recon": 55, "itd_response": 45}
SHOTS = {v.stem: (f"app/{APP}/{v.stem}", view_height(v.stem), WAIT.get(v.stem, 40)) for v in sorted(VIEWS.glob("itd_*.xml"))}
SHOTS["es_findings"] = ("app/SplunkEnterpriseSecuritySuite/incident_review", 900, 50)
REPORTS = {
    "search_spray": "AA26 03 - Detection 1 - Exchange password spray",
    "search_recon": "AA26 29 - Recon - Scanner profile",
    "search_softether": "AA26 23 - SoftEther - Tuned detection",
    "search_ews": "AA26 09 - Detection 4 - EWS volume",
    "search_dcsync": "AA26 12 - Detection 5 - DCSync",
    "search_discovery": "AA26 01 - Telemetry discovery",
    "search_ai_draft": "AA26 28 - AI - First draft with assumed fields",
}
import generate_lab_data as lab

SPL = {s["name"]: s["spl"] for s in lab.SEARCHES}
WINDOW = json.loads((HERE / "output" / "manifest.json").read_text())["window"]
for name, title in REPORTS.items():
    q = urllib.parse.urlencode({"q": SPL[title], "earliest": WINDOW["earliest"], "latest": WINDOW["latest"]})
    SHOTS[name] = (f"app/search/search?{q}", 900, 35)


# Search pages: drop the one-off "AI Assistant is now available" toast and take focus out of the search bar.
TIDY = """() => {
  const hits = [...document.querySelectorAll('div')].filter(e => e.innerText && e.innerText.includes('is now available')
      && e.getBoundingClientRect().width < 500);
  hits.sort((a, b) => b.getBoundingClientRect().height * b.getBoundingClientRect().width
                    - a.getBoundingClientRect().height * a.getBoundingClientRect().width);
  if (hits.length) hits[0].remove();
  if (document.activeElement) document.activeElement.blur();
}"""


def main():
    # search_discovery lists every index on a shared server, not just the lab's; capture it only on request.
    want = sys.argv[1:] or [n for n in SHOTS if n != "search_discovery"]
    OUT.mkdir(exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1600, "height": 900}, device_scale_factor=2,
                                  timezone_id="Australia/Sydney", locale="en-AU")
        page = ctx.new_page()
        page.goto(f"{WEB}/account/login")
        page.fill("#username", os.environ.get("SPLUNK_USERNAME", "admin"))
        page.fill("#password", os.environ["SPLUNK_PASSWORD"])
        page.keyboard.press("Enter")
        page.wait_for_url(re.compile(r"^(?!.*account/login)"), timeout=60000)
        for name in want:
            path, height, wait = SHOTS[name]
            page.set_viewport_size({"width": 1600, "height": height})
            page.goto(f"{WEB}/{path}")
            page.wait_for_timeout(wait * 1000)
            if name.startswith("search_"):
                try:
                    page.click(".ace_content", timeout=3000)
                    page.keyboard.press("Meta+ArrowUp")
                    page.keyboard.press("Control+Home")
                except Exception:
                    pass
                page.evaluate(TIDY)
                page.mouse.click(800, height - 40)
                page.wait_for_timeout(500)
            if name.startswith("es_"):
                try:
                    page.get_by_text("Remind me later").click(timeout=5000)
                    page.wait_for_timeout(2000)
                except Exception:
                    pass
            page.screenshot(path=str(OUT / f"{name}.png"))
            print("captured", name)
        browser.close()


if __name__ == "__main__":
    main()
