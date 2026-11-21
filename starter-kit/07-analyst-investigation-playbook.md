# Analyst investigation playbook: a behaviour-chain finding

Lab example: finding "Integrity Tech behaviour chain on j.citizen", risk 200 across six ATT&CK tactics.

| Step | Do this | Lab search | What you should conclude |
|---|---|---|---|
| 1. Open the finding | Read the entity, its type, the score, the tactics and the contributing detections | AA26 14 | It is about one identity, j.citizen; the 200 is identity risk only |
| 2. Examine contributing events | List every risk event in time order, with its message and threat object | AA26 24 | Scan, spray, spray success, SoftEther, dynamic DNS, EWS collection over three days |
| 3. Validate the identity | Where has the account signed in from, and with which clients? Compare with known addresses | AA26 25 | Two addresses she has never used: 203.0.113.47 (spray source) and 203.0.113.52 (2,400 EWS calls, no user agent) |
| 4. Inspect the host | What is running on her workstation that shouldn't be? | AA26 22, AA26 19 | WS-0417 has three SoftEther signals; the pivot shows how it arrived |
| 5. Add context | Who is she, how critical is the host? | AA26 26 | Executive officer, high priority identity and host |
| 6. Explain | Write two sentences a commander can act on | | "A sprayed password gave an outside party access to j.citizen's mailbox; they installed a disguised VPN on her workstation and bulk-read her mail through EWS." |
| 7. Escalate | Request approval for containment; hand to incident response | | Disable the account, revoke sessions and app secrets, isolate WS-0417, block the SoftEther DNS name, report to ASD's ACSC |

What would change the conclusion: a known travel record for 203.0.113.47, an approved migration tool for the EWS volume, or an
IT change for the VPN. Check each before escalating; record that you did.
