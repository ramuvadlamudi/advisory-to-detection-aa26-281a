# AA26-281A detection engineering starter kit

Take-home material from "From Advisory to Detection: Hunting Integrity Tech (AA26-281A) in Splunk", ADF Cyber Skills
Challenge 2026. The method is vendor-independent; the SPL is Splunk, written against CIM data models where possible so the logic
ports to other SIEMs.

| File | Use it to |
|---|---|
| `00-threat-to-detection-playbook.md` | Follow the five steps from a new advisory to validated detections and action |
| `01-hypothesis-worksheet.md` | Turn one advisory behaviour into a testable detection (blank template plus the SoftEther example) |
| `02-detection-catalogue.md` / `.csv` | See all 17 behaviour detections and the correlation finding, with owner, tests and response |
| `detections/*.yml` | Manage each detection as code: ID, logic, risk, false positives, tests, owner, review date |
| `03-data-requirements.md` | Check the telemetry, fields and audit settings each behaviour needs |
| `04-validation-test-plan.md` | Prove each detection with a positive, a negative and a gap test |
| `05-tuning-guide.md` | Remove false positives without weakening the logic |
| `06-deployment-checklist.md` | Move a detection from search to production |
| `07-analyst-investigation-playbook.md` | Work a finding from open to escalation |
| `08-readiness-calculator.csv`, `readiness.py` | Report coverage and confidence for one advisory |
| `09-ai-prompts.md` | Use AI for the slow parts, and check its work |
| `ai-run/` | The recorded run from the session: a local model asked which behaviours the lab can't detect, its verbatim answer, and the script to repeat it |
| `10-exercise.md` | Take the 48-hour challenge on a new advisory |
| `11-demo-runbook.md` | Rerun the session walkthrough: what each screenshot shows, pre-flight checks and how to recapture |
| `app/integrity_tech_detections.tgz` | Install the Integrity Tech Detections app: 18 detections, lookups, catalogue, readiness and 10 dashboards (storyline, exposure and a Defender action centre) (lab first; tune the macros and lookups) |
| `spl/` | Every demo search from the session |

Lab only: the lab data is synthetic (fictional `lab.example`, documentation IP ranges, plus two real AA26-281A indicators in the FishHub thread: `fym.linkedinns.net` and 207.148.92.220). Never test against production, and never
exploit real systems.
