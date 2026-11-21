# Data requirements

Check each source with the discovery searches (spl/aa26-01, spl/aa26-02) before trusting any detection that uses it.

| Source | Fields | CIM data model | Behaviours | Configuration that matters |
|---|---|---|---|---|
| Firewall or NetFlow | src, dest, dest_port, bytes_in, bytes_out | Network_Traffic | Scanning, upload volume, known-bad IPs | Log allowed and denied; include byte counts |
| DNS resolver logs | src, query | Network_Resolution | SoftEther dynamic DNS, known-bad domains | Log at the resolver your clients use, not only at the edge |
| Exchange IIS (W3C) | c_ip, cs_username, cs_uri_stem, sc_status, cs_User_Agent | Web (partial) | Spraying, EWS collection | Enable cs-username, c-ip and User-Agent; all ten virtual directories; real client IP behind proxies |
| Windows Security | 4625, 4771 (failed logon); 4662 (directory access) | Authentication; none for 4662 | Spraying (secondary), DCSync | For 4662: Audit Directory Service Access (Success) on DCs, plus the replication-rights SACL on the domain root |
| Windows System | 7045: ServiceName, ImagePath, StartType | Change | Persistence through services | Collected by default; forward it |
| Sysmon or EDR | Process: process_name, process_path, original_file_name, parent; File: file_path, file_name | Endpoint.Processes, Endpoint.Filesystem | SoftEther masquerading, FishHub stager, decoy files | Sysmon event 1 and 11 with OriginalFileName; deploy to servers and, for Linux, Sysmon for Linux or auditd |
| Microsoft 365 unified audit | MailItemsAccessed: AppId, MailboxOwnerUPN; app credential and consent operations | None; Change for app changes | App-based mail collection, new secrets | Enable MailItemsAccessed for every mailbox and keep it at least 180 days |

## Directory replication auditing (DCSync)

Event 4662 is written for replication only when both are in place:

1. Advanced Audit Policy on domain controllers: DS Access > Audit Directory Service Access, Success.
2. A SACL on the domain naming context root (for example DC=lab,DC=example) auditing Success for Everyone on the extended rights Replicating Directory Changes (1131f6aa-…), Replicating Directory Changes All (1131f6ad-…) and Replicating Directory Changes In Filtered Set (89e95b76-…).

Test it safely: run a replication check from a domain controller and confirm a 4662 with those GUIDs arrives in the SIEM. Expect volume from DC computer accounts (ending in $); the detection excludes them.
