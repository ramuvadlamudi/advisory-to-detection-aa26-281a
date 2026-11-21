# Tuning guide

Tune with registers, not by weakening the logic.

1. **Find the false positive's reason.** The SoftEther example: WS-0404 runs SoftEther legitimately, approved by IT.
2. **Record the exception as data.** A lookup row with the host, the exact path or identifier, who approved it, and a review date
   (`aa26_approved_remote_access.csv`, `aa26_approved_scanners.csv`, `approved_mail_apps.csv`).
3. **Exclude narrowly.** Host plus path, app ID, or source address. Never by process name, vendor, subnet wildcard or user group.
4. **Prefer baselines to fixed thresholds** where normal varies per entity: EWS calls against each user's own median, with a
   minimum history (24 active hours) so a new or quiet user doesn't produce a meaningless median.
5. **Score, don't page, the weak signals.** Scanning and upload volume add risk; the finding fires when signals add up on one entity.
6. **Re-run the backtest** after every tuning change: the positive test must still fire.
7. **Expire exceptions.** Review dates apply to allow-lists and indicators alike.

| Before tuning | After tuning |
|---|---|
| SoftEther process search: 2 hosts (WS-0417 malicious, WS-0404 approved) | 1 host (WS-0417); WS-0404 removed by the register |
| Spray success: any 200 from a spraying source | Only accounts that were sprayed and then succeeded from the same source |
| EWS volume: every user, including two-hour histories | Users with at least 24 active hours |
