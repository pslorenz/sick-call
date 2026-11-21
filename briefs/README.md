# Briefs

One folder per advisory: `briefs/YYYY/<advisory-id>/`. A brand with no vendor advisory uses its name (`briefs/2026/php2shell/`).

| File | What it holds |
| --- | --- |
| `brief.md` | The one-screen quick brief. Front matter carries the machine-readable state (below). |
| `writeup.md` | The full writeup, for readers who want the detail. |
| `runbook.md` | Mitigation runbook: gates, checks, patch, workarounds, priority tiers, detection. |
| `factcheck.md` | Claim ledger, "Sources disagree" rows, "Not verified" list, dated signals. |
| `signals.json` | Meter input. |
| `meter-YYYY-MM-DD.json` | Meter output, one snapshot per run. The history is the track record. |
| `applicability.json` | Inventory-match rule. `status: draft` until a person signs off. |
| `sources.json` | Every URL used, with fetch time and a content hash. No copies of other people's pages. |

## brief.md front matter

```yaml
advisory: SNWLID-2026-0014
cves: [CVE-2026-19868, CVE-2026-107154, CVE-2026-107155, CVE-2026-82308]
rung: 4
label: Exploited
driven_by: CVE-2026-19868
publish: action brief        # action brief | calm-down brief | validation brief | log
review: held                 # reviewed | unreviewed | held
reviewer:                    # set on merge
reviewed_on:
window_internet: 24 hours
tripwire:                    # for deferrals: what moves it up, e.g. "lands on KEV"
smb_relevance: yes
```

Merging the pull request is the review. `held` briefs can't merge until every "Sources disagree" row is settled.
