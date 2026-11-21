# Changelog

sick-call uses semantic versioning. Everything before 1.0 is alpha: the ladder, windows, and file formats can change between minor versions, and the changelog will say when they do.

## [0.2.0] - unreleased

The daily pipeline. The ladder is unchanged from 0.1.0.

### Added
- `tools/daily.py`: daily intake, watch list, escalations, follow-through, and the Binnacle List (`BINNACLE.md`).
- `.github/workflows/daily.yml`: runs it every morning, commits the record, and opens issues for new action items, escalations, and lapsed risk acceptances. Manual runs for a single CVE via workflow dispatch.
- `recheck_by`, `owner`, and `expires` on every watch-list item. Statuses: needs action, light duty (short floor window), watching (normal cycle), accepted, done, held, window passed.
- Binnacle List lines lead with product and CVE count; the tripwire is stated once per section, not on every line; owners aren't shown (assignment lives in tickets).
- Due dates count from disclosure, not intake.
- Age-off is configurable (`age_off`): the public list drops needs action 14 days and light duty 7 days past due; a private working copy can set `null` to keep items until closed. The daily workflow uses `sick-call.worklist.json` when a private copy commits one.
- Daily intake log in `log/`, with vendor, disclosure date, and window for every advisory scored.
- Sick call commandos: the five vendors that turned up most over 90 days, at the end of the Binnacle List, by a fixed published rule. `tools/commandos.py` produces the same table for any period (the annual hall of fame).

### Changed
- Advisory grouping: CVEs with no shared advisory URL (none, or only per-CVE pages like psirt.watchguard.com/CVE-… or …/cve2026125878-…) are grouped by vendor and publish day, one bulletin per vendor per day (13 WatchGuard Dimension CVEs on one day are one advisory, not 13). Applies to the backtest too, so 0.1.0's published counts were made with the earlier grouping.

## [0.1.0] - unreleased

First public alpha.

### Added
- The six-rung ladder, action windows, headline-noise readout, edge-device floor, and SMB filter (`tools/fud_meter.py`).
- Advisory expansion: sibling CVEs that share a vendor advisory are scored together.
- 90-day backtest harness with signals rebuilt as of each disclosure date (`backtest/backtest.py`).
- Regression cases: Java4Shell (rung 2), PHP2Shell (rung 5), SonicWall SNWLID-2026-0014 (rung 4).
- Java4Shell collectors for Linux and Windows, and the exposure triage ranker.
- Local configuration via git-ignored `sick-call.local.json`.
- The `vuln-brief` drafting skill.
- Licensing: Apache-2.0 for code, CC BY 4.0 for content.
- Manual runs (`--requested`) brief an advisory regardless of the SMB filter; every scored advisory emits a log record.
- SMB and edge matching anchored to vendor and product, so third-party apps and plugins that mention a platform don't count as that platform.
- Scheduled-release vendors are grouped into one advisory per release date (Patch Tuesday, Chrome releases, Oracle CPU), configurable with `release_groups`. Grouping by calendar month was tried first and dropped: it folded early out-of-band CVEs into Patch Tuesday and set day 0 too early.
- Edge floor no longer requires recent KEV history for the vendor (cost in the first backtest: 20 SMB advisories over 90 days moved from the normal cycle to 7 days).
- Remote-access floor: internet-facing remote access and RMM tools get at least a 72-hour window.
- Baseline additions from the first backtest: MikroTik (SMB and edge), Ahsay (SMB).
- Named the published output the Binnacle List, with an explainer in the README.
