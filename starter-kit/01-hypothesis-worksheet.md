# Hypothesis worksheet: the five-part detection template

Use one sheet per behaviour. If you cannot fill in part 3, you have found a gap: write it down, because that is a result.

| Part | Question | Your answer |
|---|---|---|
| 1. Adversary behaviour | What did the advisory say they did, in one sentence? | |
| 2. Observable evidence | If they did it here, what would be different from normal? | |
| 3. Required telemetry | Which log records it, with which fields? Do we have it, and for how long? | |
| 4. Detection logic | Which conditions, together, separate malicious from legitimate? | |
| 5. Validation | What proves it fires (positive), stays quiet (negative), and what can't we test (gap)? | |

Then write the hypothesis in one sentence: "A [entity] that [evidence], [in context], may indicate [behaviour]."

## Worked example: SoftEther renamed as a Windows process

**Intelligence.** AA26-281A: the actors install SoftEther VPN, rename it conhost.exe or dllhost.exe, and set it to reconnect at
startup. Endpoint tools are less likely to flag it, because SoftEther is legitimate software.

**The detection engineer's questions.**

| Question | Answer |
|---|---|
| What makes this suspicious? | A Windows process name on a binary that is really a VPN; a long-lived tunnel; persistence at boot |
| What does legitimate SoftEther use look like? | Installed in Program Files under its own names (vpnclient_x64.exe), approved by IT, on a few admin hosts |
| Which fields distinguish legitimate from malicious? | process_name vs original_file_name; process_path; parent process; service ImagePath; DNS queries |
| Which telemetry captures it? | Sysmon event 1 or EDR (original file name), Windows 7045 (service), DNS logs; Linux needs auditd or Sysmon for Linux |
| What other evidence raises confidence? | SoftEther dynamic DNS from the same host; unusual authentication by the host's owner; upload-heavy traffic |

**Hypothesis.** A process running under a legitimate Windows name, outside its expected path, with VPN-related binary metadata
and suspicious DNS activity, may indicate unauthorised VPN persistence.

**Logic.** Correlate four things on one host: process metadata (name vs original file name), execution path, service installation,
and DNS. Each search runs separately and writes its own signal; a host with two or more signals is a finding (lab search AA26 22).

**Validation.**

| Test | Lab data | Expected |
|---|---|---|
| Malicious simulation | conhost.exe in C:\ProgramData\USOShared, original file name vpnbridge.exe, 7045 service, softether.net DNS (WS-0417) | Fires, three signals |
| Legitimate SoftEther | vpnclient_x64.exe in Program Files, approved by change CHG-2291 (WS-0404) | One signal before tuning; silent after |
| Normal Windows activity | Thousands of real conhost.exe and dllhost.exe starts from System32 | Silent |
| Gap | SoftEther installed on Linux with curl or wget | Cannot test: no Linux process telemetry |
