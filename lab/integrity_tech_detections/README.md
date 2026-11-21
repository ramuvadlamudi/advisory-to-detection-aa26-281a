# Integrity Tech Detections 1.1.0

Detections, hunts and dashboards for Integrity Technology Group activity described in joint advisory AA26-281A (8 Oct 2026),
tracked by industry as Flax Typhoon. Built for "From Advisory to Detection" (ADF Cyber Skills Challenge 2026).

## What's inside

- 17 behaviour detections and 1 finding (`AA26-281A - * - Rule`), as Enterprise Security 8 event-based detections.
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

The dashboards open on the lab's scenario window (2026-09-14 to 2026-10-08). Change the
time picker for your own data. Lab and synthetic data only: test in a non-production instance first.

Icons: Tabler Icons (MIT).
