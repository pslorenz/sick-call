# sick-call v0.1 backtest results

**Window:** disclosures from 2026-08-23 to 2026-11-21 (90 days)
**Data:** cvelistV5, CISA KEV, nuclei-templates, and FIRST EPSS, all pulled 2026-11-21

## The short version

Of 1,434 SMB-relevant advisories disclosed in 90 days, 28 were exploited before their window closed. The ladder called 23 of those urgent on the day they dropped. The other 5 were all internet-facing systems the business runs itself, and all 5 hit CISA KEV within 3 to 10 days of disclosure. None escalated after its window closed.

Meanwhile, 112 SMB-relevant bugs scored CVSS 9.0 or higher were deferred, stayed quiet for at least 30 days, and were never exploited. That's 112 times the group chat would have caught fire for nothing.

## SMB scorecard

| Outcome | SMB advisories | What it means |
| --- | --- | --- |
| Urgent on day 0 | 23 | Rung 3 or higher at disclosure. Acting immediately was right. |
| Escalated inside window | 5 | Exploited before the window closed. The watch list had to catch these. |
| Escalated after window | 0 | Exploited only after the window closed. |
| Deferral held | 734 | Deferred, then quiet for 30+ days and past its window. |
| Too new to judge | 672 | Quiet so far, but disclosed too recently to count. |
| **Total** | **1,434** | |

Across all 35,684 advisories (SMB or not): 87 urgent on day 0, 21 escalated inside the window, 1 escalated after it, and 2,574 CVSS 9.0+ advisories deferred and never exploited.

## What it asks of an MSP

The windows the ladder assigned to the 1,434 SMB-relevant advisories, assuming they're internet-facing:

| Window | SMB advisories | Mostly driven by |
| --- | --- | --- |
| 24 hours | 22 | Exploited on release day |
| 72 hours | 36 | The remote-access floor |
| 7 days | 287 | The edge-device floor |
| 30 days or normal cycle | 1,089 | Everything else |

That works out to about four advisories a day that need action inside a week, and nearly all of them are firewalls, VPNs, and remote-access tools. The other 76% go into the normal patch cycle, with the watch list keeping an eye on them.

## The five misses

| Advisory | Days to KEV | Window given | Day-0 EPSS percentile |
| --- | --- | --- | --- |
| ConnectWise ScreenConnect (CVE-2026-84869) | 3 | 72 hours | 0.32 |
| WordPress core (CVE-2026-119977) | 3 | Normal cycle | 0.49 |
| MikroTik RouterOS, September 2026 advisory | 5 | 7 days | 0.38 |
| AhsayCBS (CVE-2026-105133) | 10 | Normal cycle | 0.30 |
| AhsayCBS (CVE-2026-105134) | 10 | Normal cycle | 0.78 |

What each one says:

- **ScreenConnect** landed on KEV on the last day of its 72-hour window. Remote access is how attackers get into every client an MSP manages, which is why it now has its own floor.
- **WordPress core** went from disclosure to KEV in 3 days on the normal cycle. That's the clearest miss in the set, and a candidate rule for the next period (internet-facing web platforms).
- **MikroTik** is now covered by the edge floor, and still landed on KEV inside its 7-day window. The watch list catches it either way.
- **AhsayCBS** is backup software MSPs run with a web portal, which makes it an internet-facing target. Ten days to KEV.

## Findings

1. **The value is in what you don't drop everything for.** Of 1,434 SMB-relevant advisories, 734 were deferred and stayed quiet (672 more are too recent to judge), against 28 that needed fast action.
2. **"Urgent on day 0" is reading, not prediction.** Most of the 23 were already being exploited when they were disclosed: zero-days on CISA KEV, or released with the vendor saying they were exploited. The ladder read that correctly. It didn't foresee anything.
3. **The watch list is mandatory.** Every escalation hit KEV within 3 to 10 days. Deferring without a daily watch list would have left all five exposed.
4. **EPSS gave no early warning.** On day 0, the five misses scored between the 30th and 49th percentile, with one at the 78th. EPSS stays a tiebreaker in the ladder, not a trigger.
5. **Internet-facing, self-hosted systems are where the risk is.** All five misses were systems the business exposes to the internet and runs itself: remote access, a router, a CMS, a backup portal.
6. **Group scheduled releases by date.** An early version grouped Patch Tuesday-style releases by calendar month, which hid four Microsoft and Adobe releases that were exploited on release day. Grouping by release date fixed it.

## Changes made during the backtest

The ladder was adjusted while this window was being studied, so these results aren't independent of those adjustments:

- Product matching is anchored to vendor, so "Acme Agent for Windows" no longer counts as Windows.
- Scheduled vendors (Microsoft, Adobe, Oracle, Chrome, Mozilla) are grouped into one advisory per release date.
- MikroTik and Ahsay were added to the SMB baseline.
- New remote-access floor: at least 72 hours for internet-facing remote access and RMM tools.
- The edge floor no longer requires the vendor to have recent KEV entries.

**The ladder is now frozen for v0.1.** Any further rule change will be scored on the next 90 days of disclosures, not this one. If a change can't hold up on data it wasn't tuned on, it doesn't stay.

## Limits

- **Feed evidence only.** Signals were rebuilt as of each disclosure date from KEV, CISA SSVC, Nuclei template history, and EPSS. Analyst evidence (researcher write-ups, scanning reports, vendor "exploited" statements outside KEV) can't be reliably rebuilt after the fact, so these rungs are the automated floor. A person reviewing the brief can raise a rung, never lower one.
- **KEV lags real exploitation.** "Days to KEV" is when exploitation was confirmed, not when it started.
- **Windows assume internet-facing exposure,** the worst case. Internal systems get longer windows.
- **672 SMB advisories are too new to judge.** They'll be scored in the next run.
- **One 90-day window.** Five misses is a small sample. Read the findings as directional.
- **The SMB baseline is a judgment call.** It's in `tools/fud_meter.py`, and any MSP can change its own copy with `sick-call.local.json`.

## Reproduce it

```
python3 backtest/backtest.py --cvelist cvelistV5 --kev kev.json --nuclei nuclei-templates --epss --days 90 --end 2026-11-21
```

Results will differ slightly with a newer KEV feed, which is the point: rerun it later and see whether the calls held.
