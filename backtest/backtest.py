#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Steven Lorenz. Part of sick-call.
"""
backtest.py - score the sick-call ladder against the last N days of disclosures.

The honest question: if we had followed the ladder (plus the watch list) from the day each
advisory dropped, what would we have told people, and how did it turn out?

Rules that keep it honest:
  * Day 0 is the advisory's disclosure date (earliest datePublished among its CVEs).
  * Signals are rebuilt as of day 0 only: KEV by dateAdded, CISA SSVC by its own timestamp,
    EPSS by its historical date, Nuclei templates by the commit that added them.
    Nothing learned later leaks into the day-0 rung.
  * Only feed-derived evidence is used. Analyst evidence (researcher demos, scanning reports)
    can raise a rung but can't be rebuilt reliably after the fact, so the backtest measures the
    automated floor. Rung 2 ("Demonstrated") is therefore never assigned here.
  * KEV's knownRansomwareCampaignUse has no date, so it is reported but never used at day 0.

Inputs (all local; nothing here needs an API key):
  --cvelist   clone of github.com/CVEProject/cvelistV5
  --kev       known_exploited_vulnerabilities.json from CISA
  --nuclei    (optional) clone of github.com/projectdiscovery/nuclei-templates, full history
  --epss      (optional) fetch historical EPSS from api.first.org (network, ~1 call per 100 CVEs)

Outputs: backtest/out/scorecard.csv and backtest/out/scorecard.md
"""
import argparse, csv, datetime as dt, glob, json, os, re, subprocess, sys, urllib.request
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import fud_meter as fm  # noqa: E402  (loads sick-call.local.json if present)
from fud_meter import climb, LADDER, WINDOWS, WINDOW_DAYS, EDGE_FLOOR  # noqa: E402

def d(s):
    return dt.date.fromisoformat(s[:10]) if s else None

def load_kev(path):
    kev = {}
    for v in json.load(open(path)).get("vulnerabilities", []):
        kev[v["cveID"]] = {"added": d(v["dateAdded"]), "vendor": v.get("vendorProject", ""),
                           "ransomware": v.get("knownRansomwareCampaignUse", "").lower() == "known"}
    return kev

def records_in_window(cvelist, start, end):
    """Yield (cve_id, record) for CVEs published in [start, end]. Scans the year dirs that can hold them."""
    years = {str(y) for y in range(start.year - 1, end.year + 1)}   # IDs can be older than their publish date
    for yr in sorted(years):
        for path in glob.iglob(f"{cvelist}/cves/{yr}/*/CVE-*.json"):
            try:
                rec = json.load(open(path))
            except (OSError, ValueError):
                continue
            meta = rec.get("cveMetadata", {})
            if meta.get("state") != "PUBLISHED":
                continue
            pub = d(meta.get("datePublished"))
            if pub and start <= pub <= end:
                yield meta["cveId"], rec

def facts(rec):
    cna = rec.get("containers", {}).get("cna", {})
    adv = sorted({r["url"] for r in cna.get("references", []) if "vendor-advisory" in r.get("tags", [])})
    products = sorted({f'{a.get("vendor", "")} {a.get("product", "")}'.strip() for a in cna.get("affected", [])})
    score = None
    containers = [cna] + rec.get("containers", {}).get("adp", [])
    for c in containers:
        for m in c.get("metrics", []):
            for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if k in m and m[k].get("baseScore") is not None:
                    score = max(score or 0, m[k]["baseScore"])
    ssvc = {}
    for adp in rec.get("containers", {}).get("adp", []):
        for m in adp.get("metrics", []):
            o = m.get("other", {})
            if o.get("type") == "ssvc":
                content = o.get("content", {})
                ssvc = {k.lower(): str(v).lower() for opt in content.get("options", []) for k, v in opt.items()}
                ssvc["_ts"] = d(content.get("timestamp") or adp.get("providerMetadata", {}).get("dateUpdated"))
    return {"advisories": adv, "products": products, "score": score, "ssvc": ssvc,
            "published": d(rec["cveMetadata"].get("datePublished"))}

def nuclei_dates(nuclei_dir):
    """CVE id -> date its Nuclei template was first committed."""
    if not nuclei_dir:
        return {}
    out = subprocess.run(["git", "-C", nuclei_dir, "log", "--diff-filter=A", "--name-only", "--format=@%cs"],
                         capture_output=True, text=True).stdout
    dates, cur = {}, None
    for line in out.splitlines():
        if line.startswith("@"):
            cur = d(line[1:])
        else:
            m = re.search(r"(CVE-\d{4}-\d+)", line, re.I)
            if m and cur:
                cid = m.group(1).upper()
                dates[cid] = min(dates.get(cid, cur), cur)
    return dates

def epss_on(cves, day):
    """Historical EPSS percentile per CVE as of `day`. Network; batches of 100."""
    out = {}
    cves = sorted(cves)
    for i in range(0, len(cves), 100):
        url = f"https://api.first.org/data/v1/epss?cve={','.join(cves[i:i+100])}&date={day.isoformat()}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "sick-call"}), timeout=30) as r:
                for row in json.load(r).get("data", []):
                    out[row["cve"]] = float(row["percentile"])
        except Exception as e:  # keep going; missing EPSS just means no proxy signal
            print(f"  EPSS fetch failed for {day}: {e}", file=sys.stderr)
    return out

def evidence_as_of(cid, f, day, kev, ndates, epss):
    e = {}
    k = kev.get(cid)
    if k and k["added"] <= day:
        e["kev"] = True
    if f["ssvc"].get("_ts") and f["ssvc"]["_ts"] <= day:
        e["ssvc_exploitation"] = f["ssvc"].get("exploitation")
        e["ssvc_automatable"] = f["ssvc"].get("automatable")
    if cid in ndates and ndates[cid] <= day:
        e["public_working_exploit"] = "Nuclei template"
    if cid in epss:
        e["epss_percentile"] = epss[cid]
    return e

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cvelist", required=True); ap.add_argument("--kev", required=True)
    ap.add_argument("--nuclei"); ap.add_argument("--epss", action="store_true")
    ap.add_argument("--days", type=int, default=90); ap.add_argument("--end", help="YYYY-MM-DD, default today")
    ap.add_argument("--smb-only", action="store_true", help="drop advisories with no SMB-stack product")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "out"))
    a = ap.parse_args()

    end = d(a.end) if a.end else dt.date.today()
    start = end - dt.timedelta(days=a.days)
    kev = load_kev(a.kev)
    ndates = nuclei_dates(a.nuclei)

    # Group CVEs by advisory: shared vendor-advisory URL, else the CVE stands alone.
    groups = defaultdict(dict)
    for cid, rec in records_in_window(a.cvelist, start, end):
        f = facts(rec)
        key = f["advisories"][0] if f["advisories"] else cid
        groups[key][cid] = f

    rows = []
    for key, members in groups.items():
        day0 = min(f["published"] for f in members.values())
        products = sorted({p for f in members.values() for p in f["products"]})
        text = " ".join(products).lower()
        smb = any(k in text for k in fm.SMB_PRODUCTS)
        if a.smb_only and not smb:
            continue
        edge = any(w in text for w in fm.EDGE_WORDS)
        vendors = {k_["vendor"].lower() for c in members if (k_ := kev.get(c))} | \
                  {p.split(" ")[0].lower() for p in products if p}
        vendor_kev = sum(1 for v in kev.values() if v["vendor"].lower() in vendors
                         and day0 - dt.timedelta(days=365) <= v["added"] < day0)
        epss = epss_on(list(members), day0 + dt.timedelta(days=1)) if a.epss else {}

        def rung_on(day):
            best = 0
            for cid, f in members.items():
                r, _, _ = climb(evidence_as_of(cid, f, day, kev, ndates, epss if day <= day0 + dt.timedelta(days=1) else {}))
                best = max(best, r)
            return best

        r0 = rung_on(day0 + dt.timedelta(days=1))          # one-day grace: same-day KEV adds count as day 0
        wr = max(r0, int(EDGE_FLOOR["floor_rung"])) if (EDGE_FLOOR["enabled"] and edge
                                                         and vendor_kev >= EDGE_FLOOR["min_vendor_kev_12mo"]) else r0
        window = WINDOWS[wr][2]                             # internet-facing: the promise peers will hold us to
        wdays = WINDOW_DAYS[window]
        # When did it first reach rung 3 (public exploit) and rung 4 (exploited), if ever, through `end`?
        esc3 = min([ndates[c] for c in members if c in ndates] or [None], key=lambda x: x or dt.date.max)
        esc4 = min([kev[c]["added"] for c in members if c in kev] or [None], key=lambda x: x or dt.date.max)
        r_now = rung_on(end)
        ransomware = any(kev.get(c, {}).get("ransomware") for c in members)
        top_score = max([f["score"] for f in members.values() if f["score"] is not None] or [0])

        if r0 >= 3:
            outcome = "urgent on day 0"
        elif esc4 and (esc4 - day0).days <= wdays:
            outcome = "escalated inside window"        # watch list had to do the work
        elif esc4:
            outcome = "escalated after window"
        else:
            outcome = "deferral held"
        rows.append({
            "advisory": key, "cves": " ".join(sorted(members)), "day0": day0.isoformat(),
            "products": "; ".join(products)[:200], "smb": "yes" if smb else "no", "edge": "yes" if edge else "no",
            "vendor_kev_12mo": vendor_kev, "max_cvss": top_score, "rung_day0": r0, "label_day0": LADDER[r0][1],
            "window_internet": window, "first_public_exploit": esc3.isoformat() if esc3 else "",
            "first_kev": esc4.isoformat() if esc4 else "",
            "days_to_kev": (esc4 - day0).days if esc4 else "", "rung_now": r_now,
            "ransomware_known_now": "yes" if ransomware else "", "outcome": outcome,
            "panic_avoided": "yes" if (top_score >= fm.PANIC_CVSS and r0 <= 2 and not esc4) else "",
        })

    rows.sort(key=lambda r: (r["day0"], r["advisory"]))
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "scorecard.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["advisory"])
        w.writeheader(); w.writerows(rows)

    n = len(rows)
    count = lambda k, v: sum(1 for r in rows if r[k] == v)
    inside = [r for r in rows if r["outcome"] == "escalated inside window"]
    md = [f"# sick-call backtest: {start} to {end}", "",
          f"Advisories scored: {n}" + (" (SMB-relevant only)" if a.smb_only else f" ({count('smb', 'yes')} SMB-relevant)"), "",
          "| Outcome | Count | What it means |", "| --- | --- | --- |",
          f"| Urgent on day 0 | {count('outcome', 'urgent on day 0')} | Rung 3+ at disclosure. Act now was right. |",
          f"| Deferral held | {count('outcome', 'deferral held')} | Normal cycle, never exploited through {end}. |",
          f"| Escalated after window | {count('outcome', 'escalated after window')} | Exploited, but after the deferral window closed. The window was enough. |",
          f"| Escalated inside window | {len(inside)} | Exploited before the window closed. The watch list had to catch these. |",
          "", f"Panic avoided (CVSS {fm.PANIC_CVSS}+, deferred, never exploited): {count('panic_avoided', 'yes')}", "",
          "## Escalated inside the window (the misses to study)", ""]
    md += [f"- {r['advisory']} ({r['cves']}): day 0 rung {r['rung_day0']}, window {r['window_internet']}, "
           f"on KEV after {r['days_to_kev']} days" for r in inside] or ["- None."]
    if fm.CONFIG_PATH:
        md += ["", f"Local config applied: {os.path.basename(fm.CONFIG_PATH)}. Results reflect your windows and product list."]
    md += ["", "Method: signals rebuilt as of day 0 from feeds only (KEV dateAdded, SSVC timestamp, Nuclei commit date"
           + (", historical EPSS" if a.epss else "") + "). Analyst evidence is not reconstructed, so rungs here are the "
           "automated floor. Windows assume internet-facing exposure."]
    open(os.path.join(a.out, "scorecard.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md[:12]))
    print(f"\nWrote {a.out}/scorecard.csv and scorecard.md")

if __name__ == "__main__":
    sys.exit(main())
