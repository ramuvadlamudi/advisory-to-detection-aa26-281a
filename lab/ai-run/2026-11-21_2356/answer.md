Here's an analysis of the AA26-281A behaviors based on the provided telemetry, formatted as requested.

| Behaviour | Verdict | Evidence | Missing telemetry |
|---|---|---|---|
| 1. Reconnaissance: scanning of internet-facing services on ports 21, 22, 53, 80, 443 and 1080 | Not detectable | Firewall data shows `dest_port` with a distinct count of 8.  This suggests some port scanning activity, but doesn't specify the ports being scanned.  DNS data shows queries, but doesn't indicate scanning. | Specific port scanning events (e.g., multiple connections to different ports from the same source within a short timeframe) are not explicitly logged and correlated. |
| 2. Exploitation of public-facing applications: eight CVEs including ProFTPD, ISC BIND, Pulse Connect Secure, GitLab and Bash, plus XSS against web pages | Partial | Vulnerability inventory shows Pulse Connect Secure, ProFTPD, ISC BIND, GitLab and Bash are present.  Web data shows `cs_uri_stem` and `sc_status` fields populated, indicating web requests.  No evidence of exploitation attempts is shown. | Evidence of exploitation attempts (e.g., specific exploit signatures, unusual HTTP request patterns, successful authentication attempts using known vulnerabilities) is missing. |
| 3. Password spraying against Exchange (EBurst) across several Exchange interfaces | Not detectable | Exchange data shows `cs_username` field populated, but no specific indicators of password spraying (multiple failed login attempts against different accounts). |  Telemetry to identify repeated failed login attempts against different user accounts within a short timeframe is not present. |
| 4. Persistence with a renamed SoftEther VPN client on Windows and Linux hosts, using SoftEther dynamic DNS | Not detectable | No telemetry related to SoftEther VPN client installation, renaming, or dynamic DNS usage is present. |  Sysmon event codes related to process creation and modification, specifically targeting SoftEther VPN, are not shown. |
| 5. Credential theft by DCSync (Active Directory replication requested by a non-domain-controller account) | Not detectable | Windows event code 4624 (Authentication Success) is present, but no specific DCSync events are logged.  Domain controllers are identified, but no unusual replication requests are evident. |  Specific DCSync event logging (e.g., event IDs related to AD replication requests from non-domain controllers) is not present. |
| 6. Mailbox collection through Exchange Web Services and an application granted mail access | Partial | O365 audit logs show `MailItemsAccessed` operations.  The number of audited mailboxes (30) is significantly lower than the total number of identities (120), suggesting incomplete coverage. |  Detailed logs of which mailboxes are being accessed, by whom, and for what purpose are limited. |
| 7. Exfiltration of collected data to actor-controlled servers | Not detectable | Firewall data shows `dest` and `src` fields populated, indicating network traffic, but no specific indicators of data exfiltration (e.g., large data transfers to unusual destinations, unusual protocols). |  Network traffic analysis focused on identifying unusual outbound connections and data transfer patterns is not present. |

---

**Additional SPL Searches to Prove Gaps:**

```spl
index=firewall src=* dest=* dest_port IN (21,22,53,80,443,1080)
```

```spl
index=exchange status=401 cs_username=*  | stats count by cs_username
```

```spl
index=sysmon EventCode=4688  | search Image="softether.exe"
```

```spl
index=wineventlog EventCode=4768 | stats count by TargetUserName
```

```spl
index=firewall dest=* NOT (dest IN (internal_ip_ranges)) | stats sum(bytes_out) by dest
```
