#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Steven Lorenz. Part of sick-call.
"""
commandos.py - the sick call commandos: vendors that keep turning up at sick call, by the numbers.

Counts only, no commentary. Built from the daily intake log (log/*.jsonl.gz), SMB-relevant advisories
only, dated by disclosure. The same rule applies to every vendor:

  ranked by short-window bulletins (needs action or light duty), then CVEs on KEV, then total CVEs.

The daily run puts the rolling 90-day top 5 on the Binnacle List. Run it on its own for any period,
for example the annual hall of fame for client reports:

  commandos.py --kev kev.json --since 2026-01-01 --until 2026-12-31 --top 10 --out hall-of-fame-2026.md

To build a longer history than the repo has logged yet, seed logs into a scratch folder first:
  daily.py --cvelist cvelistV5 --kev kev.json --lookback 365 --root /tmp/year
  commandos.py --kev kev.json --log-dir /tmp/year/log --days 365
"""
import argparse, datetime as dt, glob, gzip, json, os, statistics, sys
from collections import defaultdict, Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "backtest"))
import fud_meter as fm                    # noqa: E402
from backtest import d, load_kev          # noqa: E402

SHORT_WINDOW_DAYS = 7
RULE = ("Ranked by short-window bulletins (needs action or light duty), then CVEs on CISA KEV, then total CVEs. "
        "SMB-relevant advisories only, counted by disclosure date. Same rule for every vendor.")


def read_logs(log_dir, start, end):
    """Latest log record per advisory whose disclosure date falls in [start, end]."""
    latest = {}
    for path in sorted(glob.glob(os.path.join(log_dir, "*.jsonl.gz"))):
        with gzip.open(path, "rt") as fh:
            for line in fh:
                r = json.loads(line)
                day0 = d(r.get("day0") or r.get("scored_on"))
                if not r.get("smb_match") or not day0 or not (start <= day0 <= end):
                    continue
                latest[r["advisory"]] = r
    return list(latest.values())


def tally(records, kev, end):
    by = defaultdict(lambda: {"names": Counter(), "bulletins": 0, "cves": 0, "short": 0, "kev": 0, "lags": []})
    for r in records:
        vendors = r.get("vendors") or []
        if not vendors:
            continue
        key = fm.canonical_vendor(vendors[0])
        v = by[key]
        v["names"].update(vendors)
        v["bulletins"] += 1
        v["cves"] += r.get("cve_count", len(r.get("cves", [])))
        if r.get("rung", 0) >= 3 or r.get("window_days", 99) <= SHORT_WINDOW_DAYS:
            v["short"] += 1
        day0 = d(r["day0"])
        for c in r.get("cves", []):
            k = kev.get(c)
            if k and k["added"] <= end:
                v["kev"] += 1
                v["lags"].append(max(0, (k["added"] - day0).days))
    rows = []
    for key, v in by.items():
        rows.append({"vendor": v["names"].most_common(1)[0][0], "bulletins": v["bulletins"], "cves": v["cves"],
                     "short_window": v["short"], "kev_cves": v["kev"],
                     "median_days_to_kev": statistics.median(v["lags"]) if v["lags"] else None})
    rows.sort(key=lambda x: (-x["short_window"], -x["kev_cves"], -x["cves"], x["vendor"].lower()))
    return rows


def table(rows):
    out = ["| Vendor | Bulletins | CVEs | Short-window | CVEs on KEV | Median days to KEV |",
           "| --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        lag = "-" if r["median_days_to_kev"] is None else f"{r['median_days_to_kev']:g}"
        out.append(f"| {r['vendor']} | {r['bulletins']} | {r['cves']:,} | {r['short_window']} | {r['kev_cves']} | {lag} |")
    return out


def binnacle_section(log_dir, kev, today, days=90, top=5):
    records = read_logs(log_dir, today - dt.timedelta(days=days), today)
    rows = tally(records, kev, today)[:top]
    first = min((d(r["day0"]) for r in records), default=today)
    span = (today - first).days + 1
    have = "" if span >= days else f" ({span} days of history so far)"
    out = [f"## Sick call commandos ({len(rows)}): the last {days} days{have}", "",
           "The vendors that keep turning up at sick call. " + RULE, ""]
    return out + (table(rows) if rows else ["Not enough history yet."]) + [""]


def report(log_dir, kev, start, end, top):
    rows = tally(read_logs(log_dir, start, end), kev, end)
    shown = rows[:top]
    total_b = sum(r["bulletins"] for r in rows)
    out = [f"# Sick call hall of fame: {start} to {end}", "",
           "The vendors that kept turning up at sick call. Counts only, no commentary.", "",
           f"{total_b:,} SMB-relevant bulletins from {len(rows)} vendors in this period. "
           f"The top {len(shown)} accounted for {sum(r['bulletins'] for r in shown):,} of them.", ""]
    out += table(shown)
    out += ["", f"**How the list is made.** {RULE} \"Short-window\" means the bulletin needed action inside "
            "seven days: exploited, weaponized, or internet-facing edge or remote-access gear. "
            "\"Median days to KEV\" is the time from disclosure to a CISA KEV listing, for the CVEs that got one.",
            "", "Source: sick-call (github.com/pslorenz/sick-call), built from public feeds: "
            "the CVE List, CISA KEV, and Nuclei templates.", ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kev", required=True)
    ap.add_argument("--log-dir", default=os.path.join(ROOT, "log"))
    ap.add_argument("--since"); ap.add_argument("--until")
    ap.add_argument("--days", type=int, default=365, help="period ending --until (or today) if --since isn't set")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--out", help="write markdown here instead of printing")
    a = ap.parse_args()
    end = d(a.until) if a.until else dt.date.today()
    start = d(a.since) if a.since else end - dt.timedelta(days=a.days)
    md = report(a.log_dir, load_kev(a.kev), start, end, a.top)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(md)
        print(f"Wrote {a.out}")
    else:
        print(md)


if __name__ == "__main__":
    sys.exit(main())
