# From Advisory to Detection: Hunting Integrity Tech (AA26-281A) in Splunk

A method, a Splunk app and synthetic data for turning a threat advisory into validated detections. The worked example is AA26-281A (Integrity Tech, also tracked as Flax Typhoon), from the ADF Cyber Skills Challenge session on 23 November 2026.

**Page:** https://ramuvadlamudi.github.io/advisory-to-detection-aa26-281a/

> **Lab and synthetic data only.** The data add-on creates indexes and the detection app installs 18 scheduled detections. Never install either on production. Nothing here exploits a system or sends traffic to the real indicators it contains.

## Download

From the [latest release](https://github.com/ramuvadlamudi/advisory-to-detection-aa26-281a/releases/latest):

| File | What it is |
|---|---|
| `integrity_tech_detections.tgz` | The Integrity Tech Detections app: 18 Enterprise Security detections (17 behaviours and one correlation finding), 10 dashboards, 13 lookups |
| `TA-aa26-281a-lab.tgz` | Synthetic lab data: 388,653 events from 14 Sep to 8 Oct 2026 (Sydney time), 31 saved reports with expected results |
| `aa26-281a-starter-kit.zip` | The vendor-independent starter kit: playbook, hypothesis worksheet, catalogue, test plan, tuning guide, readiness calculator, AI prompts, the recorded local-model run, an exercise, YAML for each detection and the SPL |
| `SHA256SUMS.txt` | Checksums for the three files |

## What's in this repository

| Path | Contents |
|---|---|
| `docs/` | The GitHub Pages site: context, the investigation, how to use the app |
| `lab/` | The generator for the synthetic data and saved reports (`generate_lab_data.py`), the app source and builder (`build_detection_app.py`), the starter-kit builder, and helper scripts for a lab instance (`labctl.py`, `upload_app.py`, `push_searches.py`, `capture_screenshots.py`). `ai_readiness_run.py` asks a locally hosted model (Ollama) which behaviours the lab can't detect, from read-only search results, and `ai-run/` holds the recorded run. `lab/README.md` explains the scenario; `lab/DEMO_SEARCHES.md` lists every search with its expected result. |
| `starter-kit/` | The starter kit, readable on GitHub |

The `dist/` packages referred to in `lab/README.md` are the release files above. To rebuild them, run `python3 generate_lab_data.py` and `python3 build_detection_app.py` in `lab/`. The generator needs only Python 3.9+; the app builder also needs Pillow and `rsvg-convert` (librsvg) for the app icon, which comes from [Tabler Icons](https://tabler.io/icons) (MIT).

## Quick start

1. Use a lab Splunk Enterprise instance with Enterprise Security 8.x, Splunk_SA_CIM, the Splunk Add-on for Microsoft Windows, the Splunk Add-on for Microsoft Office 365 and ES Content Update.
2. Install `TA-aa26-281a-lab.tgz`, restart, then install `integrity_tech_detections.tgz` (**Apps > Manage Apps > Install app from file**).
3. Set your time zone to Australia/Sydney.
4. Seed the risk events and raise the findings, either by following `lab/DEMO_SEARCHES.md` or with the helper:

   ```sh
   cd lab
   export SPLUNK_MGMT=https://<your-lab-host>:8089 SPLUNK_USERNAME=<user>   # password is prompted
   python3 labctl.py load && python3 labctl.py seed && python3 labctl.py validate && python3 labctl.py backtest && python3 labctl.py findings
   ```

5. Open **Integrity Tech Detections > Overview** and follow the eight-step investigation on the page.

Scripts read the Splunk address and credentials from environment variables or a prompt; nothing is stored.

## Use it on your next advisory

1. Take one advisory that names technology you run.
2. Extract one behaviour, and quote the sentence.
3. Identify the telemetry, and prove it exists with a search.
4. Build and test one detection: it fires on a safe simulation and stays quiet on the legitimate look-alike.
5. Record the gap, the owner and the plan. If you can't build it, the gap is the deliverable.

## Disclaimer

Community content, provided as is for training and lab use. Not an official or supported Splunk or Cisco product. Hosts, users and internal addresses are fictional; external actors use documentation IP ranges, except the FishHub scenario, which deliberately uses two real indicators (`fym.linkedinns.net` and 207.148.92.220, a low-confidence STIX address last seen July 2024) so the sweeps have something to find; no traffic is ever sent to them. The indicator lookups contain the real AA26-281A domains and IPs from CISA's STIX file and the DOJ seizure announcement.
