# The Binnacle List

Updated 2026-11-22. What came through sick call, and what it means for the plan of the day.

sick-call triages; it isn't incident response. Credible signs of compromise in your own environment go to your IR plan, not this list.

## Confined to quarters (2): needs action

Being exploited, or working exploit code is public. Act inside the window.

| What | Rung | Window | Due | Exploited |
| --- | --- | --- | --- | --- |
| Microsoft release, 2026-11-10: 1094 CVEs | 4 Exploited | 24 hours | 2026-11-11 (overdue) | CVE-2026-124194 |
| Google release, 2026-11-10: 8 CVEs | 4 Exploited | 24 hours | 2026-11-11 (overdue) | CVE-2026-125350 |

## Light duty (12): patch by the due date (or your SLA, if sooner)

Nothing public yet, but internet-facing edge or remote-access gear gets a short window anyway. Due dates here are sick-call's defaults. If your contract SLA is shorter, it wins.

- Fortinet (FortiAnalyzer, FortiClientMac, FortiClientWindows and 7 more): 5 CVEs. 7 days, due 2026-11-17 (overdue)
- WatchGuard (Endpoint Security): 1 CVE. 7 days, due 2026-11-17 (overdue)
- Fortinet (FortiAnalyzer, FortiAnalyzer Cloud, FortiAnalyzer-BigData and 8 more): 93 CVEs. 7 days, due 2026-11-18 (overdue)
- Palo Alto Networks (Checkov by Prisma Cloud, Cloud NGFW, PAN-OS and 1 more): 8 CVEs. 7 days, due 2026-11-18 (overdue)
- Citrix NetScaler (ADC, Console, Gateway): 2 CVEs. 7 days, due 2026-11-19 (overdue)
- Citrix (NetScaler ADC, NetScaler Gateway): 27 CVEs. 7 days, due 2026-11-20 (overdue)
- N-able (N-central, N-central Patch Management Component): 17 CVEs. 72 hours, due 2026-11-20 (overdue)
- ConnectWise (Automate): 1 CVE. 72 hours, due 2026-11-22
- [Zyxel (DX3300-T0 firmware, DX3301-T0 firmware, EX3301-T0 firmware): 2 CVEs](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-out-of-bounds-write-and-post-authentication-command-injection-vulnerabilities-in-certain-dsl-ethernet-cpe-fiber-onts-and-wireless-extenders-11-17-2026). 7 days, due 2026-11-24
- [Zyxel (EE5301-00 customized firmware): 1 CVE](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-incorrect-authorization-vulnerability-in-the-snmp-parameter-of-customized-firmware-for-the-ee5301-00-ethernet-cpe-11-17-2026). 7 days, due 2026-11-24
- WatchGuard (Dimension): 15 CVEs. 7 days, due 2026-11-26
- Ubiquiti Inc (UniFi Access Application): 7 CVEs. 7 days, due 2026-11-26

## Escalated (0): in the last 7 days

None.

## On the list (64): watching

Deferred to the normal patch cycle and re-scored every day. Any one of them moves up the day a public PoC, working exploit code, or a KEV listing appears.

Rechecks due in the next 7 days: 17.

## Sick call commandos (5): the last 90 days

The vendors that keep turning up at sick call. Ranked by short-window bulletins (confined to quarters or light duty), then CVEs on CISA KEV, then total CVEs. SMB-relevant advisories only, counted by disclosure date. A bulletin that names several vendors counts once for each of them. Same rule for every vendor.

| Vendor | Bulletins | CVEs | Short-window | CVEs on KEV | Median days to KEV |
| --- | --- | --- | --- | --- | --- |
| WatchGuard | 13 | 91 | 13 | 0 | - |
| MikroTik | 8 | 15 | 8 | 3 | 5 |
| SonicWall | 7 | 22 | 7 | 3 | 1 |
| Fortinet | 9 | 123 | 6 | 1 | 0 |
| N-able | 6 | 29 | 5 | 1 | 2 |


## Cleared (184): this week

Deferral held: 113. Window passed: 71. Marked done: 0.

The full record, with every item's history, is in [watchlist.json](watchlist.json).
