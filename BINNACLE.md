# The Binnacle List

Updated 2026-11-26. What came through sick call, and what it means for the plan of the day.

sick-call triages; it isn't incident response. Credible signs of compromise in your own environment go to your IR plan, not this list.

## Confined to quarters (1): needs action

Being exploited, or working exploit code is public. Act inside the window.

| What | Rung | Window | Due | Exploited |
| --- | --- | --- | --- | --- |
| N-able (MailAssure): 1 CVE | 4 Exploited | 24 hours | 2026-11-23 (overdue) | CVE-2026-134624 |

## Light duty (8): patch by the due date (or your SLA, if sooner)

Nothing public yet, but internet-facing edge or remote-access gear gets a short window anyway. Due dates here are sick-call's defaults. If your contract SLA is shorter, it wins.

- Citrix NetScaler (ADC, Console, Gateway): 2 CVEs. 7 days, due 2026-11-19 (overdue)
- Citrix (NetScaler ADC, NetScaler Gateway): 27 CVEs. 7 days, due 2026-11-20 (overdue)
- N-able (N-central, N-central Patch Management Component): 17 CVEs. 72 hours, due 2026-11-20 (overdue)
- ConnectWise (Automate): 1 CVE. 72 hours, due 2026-11-22 (overdue)
- [Zyxel (DX3300-T0 firmware, DX3301-T0 firmware, EX3301-T0 firmware): 2 CVEs](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-out-of-bounds-write-and-post-authentication-command-injection-vulnerabilities-in-certain-dsl-ethernet-cpe-fiber-onts-and-wireless-extenders-11-17-2026). 7 days, due 2026-11-24 (overdue)
- [Zyxel (EE5301-00 customized firmware): 1 CVE](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-incorrect-authorization-vulnerability-in-the-snmp-parameter-of-customized-firmware-for-the-ee5301-00-ethernet-cpe-11-17-2026). 7 days, due 2026-11-24 (overdue)
- WatchGuard (Dimension): 15 CVEs. 7 days, due 2026-11-26
- Ubiquiti Inc (UniFi Access Application): 7 CVEs. 7 days, due 2026-11-26

## Escalated (0): in the last 7 days

None.

## On the list (67): watching

Deferred to the normal patch cycle and re-scored every day. Any one of them moves up the day a public PoC, working exploit code, or a KEV listing appears.

Rechecks due in the next 7 days: 15.

## Sick call commandos (5): the last 90 days

The vendors that keep turning up at sick call. Ranked by short-window bulletins (confined to quarters or light duty), then CVEs on CISA KEV, then total CVEs. SMB-relevant advisories only, counted by disclosure date. A bulletin that names several vendors counts once for each of them. Same rule for every vendor.

| Vendor | Bulletins | CVEs | Short-window | CVEs on KEV | Median days to KEV |
| --- | --- | --- | --- | --- | --- |
| WatchGuard | 11 | 61 | 11 | 0 | - |
| MikroTik | 8 | 15 | 8 | 3 | 5 |
| SonicWall | 6 | 20 | 6 | 3 | 1 |
| N-able | 7 | 30 | 6 | 2 | 1.5 |
| Fortinet | 9 | 123 | 6 | 1 | 0 |


## Cleared (194): this week

Deferral held: 117. Window passed: 77. Marked done: 0.

The full record, with every item's history, is in [watchlist.json](watchlist.json).
