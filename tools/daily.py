#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Steven Lorenz. Part of sick-call.
"""
daily.py - sick-call's daily run: intake, watch, and the Binnacle List. No LLM.

  1. Intake: score every advisory published in the last few days, the same way the backtest does.
     SMB-relevant ones go on the watch list; everything is logged.
  2. Watch: re-score every open item against today's KEV, CISA SSVC, and Nuclei templates.
     A rung going up is an escalation: new window, new due date, and an issue.
  3. Follow-through: deferrals past their window with no change are cleared as "held";
     accepted risk past its expiry comes back as needing action.
  4. Publish: watchlist.json (the record) and BINNACLE.md (what leadership reads).

Statuses:
  needs action   confined to quarters: rung 3+, or escalated. Stays until marked done, or ages off past due
                 (14 days by default; set age_off.needs_action_days to null in a working copy to keep it until done).
  light duty     a short patch-by window from a floor (72 hours or 7 days). Ages off past due (7 days by default).
  watching       deferred to the normal cycle and re-scored daily. Clears as "held" once quiet past its window.
  accepted       risk accepted by a named owner until `expires`. Comes back when it lapses.
  done | held | window passed   closed. Kept in the record.

Every item carries recheck_by (the date a person looks again, whatever the feeds say), owner,
and expires (only for accepted risk).

Usage:
  daily.py --cvelist CVELIST --kev kev.json [--nuclei TEMPLATES] [--today YYYY-MM-DD]
           [--requested CVE-ID --requested-by NAME]
"""
import argparse, datetime as dt, glob, gzip, json, os, sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "backtest"))
import fud_meter as fm                                        # noqa: E402  (loads sick-call.local.json)
from backtest import d, load_kev, records_in_window, facts    # noqa: E402

OPEN = ("needs action", "light duty", "watching", "accepted")
REVOKE_RUNG = 3      # a rung jump to Weaponized or higher cancels a risk acceptance
SHORT_WINDOW_DAYS = 7        # a window this short is a patch-by date, not a deferral
# Age-off after the due date comes from fud_meter.AGE_OFF (config key "age_off"); None means never.
RECHECK_MAX_DAYS = 30        # nobody's deferral goes longer than this without a person looking at it
CLOSED_KEEP_DAYS = 90        # closed items stay in watchlist.json this long, then live only in git history


def record_path(cvelist, cid):
    _, yr, num = cid.split("-")
    return os.path.join(cvelist, "cves", yr, num[:-3] + "xxx", cid + ".json")


def load_record(cvelist, cid):
    try:
        with open(record_path(cvelist, cid)) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def nuclei_present(nuclei_dir):
    """CVE ids with a public Nuclei template today. A shallow clone is enough."""
    found = set()
    if not nuclei_dir:
        return found
    for path in glob.iglob(os.path.join(nuclei_dir, "**", "CVE-*.yaml"), recursive=True):
        cid = fm.template_cve(path)
        if cid:
            found.add(cid)
    return found


def evidence_today(cid, f, today, kev, nuclei):
    e = {}
    k = kev.get(cid)
    if k and k["added"] <= today:
        e["kev"] = True
        e["kev_ransomware"] = k["ransomware"]
    if f["ssvc"].get("_ts") and f["ssvc"]["_ts"] <= today:
        e["ssvc_exploitation"] = f["ssvc"].get("exploitation")
        e["ssvc_automatable"] = f["ssvc"].get("automatable")
    if cid in nuclei:
        e["public_working_exploit"] = "Nuclei template"
    return e


def group_key(cid, f):
    return fm.advisory_key(cid, f["assigner"], f["published"], f["advisories"], f["pairs"])


def score(members, today, kev, nuclei):
    """members: {cve_id: facts}. Returns the scored advisory."""
    best, nxt, driver = -1, None, None
    for cid, f in members.items():
        r, _, n = fm.climb(evidence_today(cid, f, today, kev, nuclei))
        if r > best:
            best, nxt, driver = r, n, cid
    pairs = {pr for f in members.values() for pr in f["pairs"]}
    smb_hits = sorted({h for v, p in pairs if (h := fm.smb_pair(v, p))})
    edge = any(fm.edge_pair(v, p) for v, p in pairs)
    remote = any(fm.remote_access_pair(v, p) for v, p in pairs)
    vendors = {p[0].lower() for p in pairs if p[0]}
    vendor_kev = sum(1 for v in kev.values() if v["vendor"].lower() in vendors
                     and today - dt.timedelta(days=365) <= v["added"] <= today)
    wr = fm.floor_rung(best, edge, vendor_kev, remote)
    window = fm.WINDOWS[wr][2]
    products = sorted({f"{v} {p}".strip() for v, p in pairs})
    return {"rung": best, "label": fm.LADDER[best][1], "driven_by": driver, "tripwire": nxt,
            "window": window, "window_days": fm.WINDOW_DAYS[window], "smb_match": smb_hits,
            "edge": edge, "remote_access": remote, "products": products,
            "kev_cves": sorted(c for c in members if c in kev and kev[c]["added"] <= today),
            "max_cvss": max([f["score"] for f in members.values() if f["score"] is not None] or [0])}


def product_label(vendor, product):
    """'Cisco' + 'Cisco Secure Firewall ASA' reads as 'Cisco Secure Firewall ASA', not 'Cisco Cisco ...'."""
    v, p = (vendor or "").strip(), (product or "").strip()
    return p if p.lower().startswith(v.lower()) or not v else f"{v} {p}".strip()


def make_title(key, members):
    pairs = sorted({pr for f in members.values() for pr in f["pairs"]})
    vendors = sorted({v.strip() for v, _ in pairs if v and v.strip()})
    # "Citrix" and "Citrix NetScaler" are one vendor: title it once, under the shortest spelling.
    if len({fm.canonical_vendor(v) for v in vendors}) == 1 and len(vendors) > 1:
        short = min(vendors, key=len)
        pairs = sorted({(short, (f"{v} {p}"[len(short):].strip() if f"{v} {p}".lower().startswith(short.lower())
                                 else p)) for v, p in pairs})
        vendors = [short]
    if "-release-" in key:                                   # Patch Tuesday, Chrome, Oracle CPU...
        return f"{' / '.join(vendors[:2]) or key.split('-release-')[0].title()} release, {key.split('-release-')[1]}"
    if len(vendors) == 1:
        v = vendors[0]
        prods = sorted({product_label("", p) if p.lower().startswith(v.lower()) else p for _, p in pairs if p})
        prods = [p[len(v):].strip() if p.lower().startswith(v.lower()) else p for p in prods]
        prods = [p for p in prods if p]
        shown = ", ".join(prods[:3]) + (f" and {len(prods) - 3} more" if len(prods) > 3 else "")
        return f"{v} ({shown})" if shown else v
    labels = sorted({product_label(v, p) for v, p in pairs})
    return "; ".join(labels[:3]) + (" ..." if len(labels) > 3 else "")


def short_name(key):
    """Readable name for an advisory key: the last path segment of a URL, else the key itself."""
    if key.startswith("http"):
        parts = [p for p in key.split("?")[0].split("/") if p]
        return parts[-1] if parts else key
    return key


def status_for(rung, window_days):
    if rung >= 3:
        return "needs action"
    return "light duty" if window_days <= SHORT_WINDOW_DAYS else "watching"


def new_item(key, members, s, today, requested_by=None):
    day0 = min(f["published"] for f in members.values())
    due = day0 + dt.timedelta(days=s["window_days"])        # the clock starts at disclosure, not when we noticed
    if requested_by:
        # Someone asked about it today: give it a full window from today so it's on the list to look at,
        # even when its original window closed months ago.
        due = max(due, today + dt.timedelta(days=s["window_days"]))
    status = status_for(s["rung"], s["window_days"])
    item = {
        "advisory": key, "name": short_name(key), "title": make_title(key, members),
        "cves": sorted(members), "cve_count": len(members), "kev_cves": s["kev_cves"],
        "day0": day0.isoformat(), "added": today.isoformat(),
        "rung": s["rung"], "label": s["label"], "driven_by": s["driven_by"],
        "window": s["window"], "due": due.isoformat(),
        "recheck_by": min(due, max(day0, today if requested_by else day0) + dt.timedelta(days=RECHECK_MAX_DAYS)).isoformat(),
        "owner": fm.PUBLISHER.get("reviewer", ""), "expires": None,
        "status": status, "tripwire": s["tripwire"],
        "smb_match": s["smb_match"], "edge": s["edge"], "remote_access": s["remote_access"],
        "max_cvss": s["max_cvss"],
        "history": [{"date": today.isoformat(), "rung": s["rung"], "status": status, "note": "intake"}],
    }
    if requested_by:
        item["requested_by"] = requested_by
        item["history"][0]["note"] = f"requested by {requested_by}"
    return item


def issue(kind, item, extra=""):
    title = f"[sick-call] {kind}: {item.get('name', item['advisory'])} (rung {item['rung']}, {item['label']})"
    body = (f"**{item['title']}**\n\nAdvisory: {item['advisory']}\n\n"
            f"- Rung {item['rung']} ({item['label']}), driven by {item['driven_by']}\n"
            f"- Exploited CVEs: {', '.join(item['kev_cves']) or 'none on KEV'}\n"
            f"- Window: {item['window']}, due {item['due']}\n"
            f"- Owner: {item['owner'] or 'unassigned'}\n" + (f"\n{extra}\n" if extra else "") +
            "\nsick-call triages; it isn't incident response. Credible signs of compromise in your own "
            "environment go to your IR plan, not this queue.")
    return {"title": title, "body": body, "labels": ["sick-call", kind.split()[0].lower()]}


def run(a):
    today = d(a.today) if a.today else dt.datetime.now(dt.timezone.utc).date()
    kev = load_kev(a.kev)
    nuclei = nuclei_present(a.nuclei)
    wl_path = os.path.join(a.root, "watchlist.json")
    with open(wl_path) as fh:
        wl = json.load(fh)
    wl.setdefault("items", []); wl.setdefault("closed", [])
    wl["version"] = 2
    known = {i["advisory"] for i in wl["items"] + wl["closed"]}
    open_by_key = {i["advisory"]: i for i in wl["items"] if i["status"] in OPEN}
    issues, log, counts = [], [], defaultdict(int)

    # 1. Intake
    groups = defaultdict(dict)
    for cid, rec in records_in_window(a.cvelist, today - dt.timedelta(days=a.lookback), today):
        f = facts(rec)
        groups[group_key(cid, f)][cid] = f
    if a.requested:
        rec = load_record(a.cvelist, a.requested)
        if not rec:
            raise SystemExit(f"--requested {a.requested}: no record in {a.cvelist}")
        f = facts(rec)
        key = group_key(a.requested, f)
        groups[key][a.requested] = f
        # Pull in the rest of its advisory: everything published the same day under the same key
        # (the whole Patch Tuesday, the whole vendor bulletin), so a lookup isn't a one-CVE fragment.
        if f["published"]:
            for cid, r2 in records_in_window(a.cvelist, f["published"], f["published"]):
                f2 = facts(r2)
                if group_key(cid, f2) == key:
                    groups[key][cid] = f2
    for key, members in groups.items():
        s = score(members, today, kev, nuclei)
        requested = a.requested in members if a.requested else False
        smb = bool(s["smb_match"])
        log.append({"advisory": key, "title": make_title(key, members), "cves": sorted(members),
                    "cve_count": len(members), "day0": min(f["published"] for f in members.values()).isoformat(),
                    "vendors": sorted({v.strip() for f in members.values() for v, _ in f["pairs"] if v and v.strip()}),
                    "rung": s["rung"], "smb_match": s["smb_match"], "edge": s["edge"],
                    "remote_access": s["remote_access"], "window": s["window"], "window_days": s["window_days"],
                    "scored_on": today.isoformat(),
                    "decision": "watch" if (smb or requested) else "log: not SMB-relevant"})
        counts["scored"] += 1
        # Late siblings: a vendor adds a CVE to a bulletin we're already watching. Fold it into the
        # open item so step 2 rescores the whole advisory instead of never seeing the new CVE.
        if key in open_by_key:
            item = open_by_key[key]
            new = sorted(set(members) - set(item["cves"]))
            if new:
                item["cves"] = sorted(set(item["cves"]) | set(new))
                item["cve_count"] = len(item["cves"])
                item["history"].append({"date": today.isoformat(), "rung": item["rung"], "status": item["status"],
                                        "note": f"added {len(new)} CVE(s) to the advisory: {', '.join(new)}"})
                counts["merged"] += 1
            continue
        if key in known or not (smb or requested):
            continue
        item = new_item(key, members, s, today, a.requested_by if requested else None)
        wl["items"].append(item); known.add(key)
        counts["added"] += 1
        if item["status"] == "needs action":
            issues.append(issue("Brief needed", item, "New advisory at rung 3 or higher."))

    # 2. Watch and 3. follow-through
    still_open = []
    for item in wl["items"]:
        if item["status"] not in OPEN:
            item.setdefault("closed_on", today.isoformat())
            wl["closed"].append(item); continue
        members = {}
        for cid in item["cves"]:
            rec = load_record(a.cvelist, cid)
            if rec:
                members[cid] = facts(rec)
        if members:
            s = score(members, today, kev, nuclei)
            # Keep the exploited list current even without a rung jump: a second Patch Tuesday CVE
            # landing on KEV leaves the rung at 4, but the brief still needs to name it.
            newly = sorted(set(s["kev_cves"]) - set(item.get("kev_cves") or []))
            item["kev_cves"] = s["kev_cves"]
            if newly and s["rung"] <= item["rung"]:
                item["history"].append({"date": today.isoformat(), "rung": item["rung"], "status": item["status"],
                                        "note": f"now on KEV: {', '.join(newly)}"})
            if s["rung"] > item["rung"]:
                old = item["rung"]
                due = today + dt.timedelta(days=s["window_days"])
                item.update(rung=s["rung"], label=s["label"], driven_by=s["driven_by"], tripwire=s["tripwire"],
                            window=s["window"], due=due.isoformat(), kev_cves=s["kev_cves"],
                            recheck_by=min(due, today + dt.timedelta(days=RECHECK_MAX_DAYS)).isoformat())
                note = f"escalated from rung {old}"
                if item["status"] == "accepted" and s["rung"] >= REVOKE_RUNG:
                    # An acceptance covers the risk that was signed for. Exploitation is a different risk.
                    item["status"] = status_for(s["rung"], s["window_days"])
                    note += f"; risk acceptance by {item.get('owner') or '-'} revoked at rung {s['rung']}"
                    item["revoked_acceptance"] = {"owner": item.get("owner"), "expires": item.get("expires"),
                                                  "on": today.isoformat()}
                    item["owner"], item["expires"] = None, None
                elif item["status"] != "accepted":
                    new = status_for(s["rung"], s["window_days"])
                    order = ["watching", "light duty", "needs action"]
                    if order.index(new) > order.index(item["status"]):
                        item["status"] = new
                item["history"].append({"date": today.isoformat(), "rung": s["rung"], "status": item["status"],
                                        "note": note})
                issues.append(issue("Rung up", item, f"Escalated from rung {old} to {s['rung']}. "
                                                     f"New window starts today."
                                                     + (" Risk acceptance revoked." if "revoked" in note else "")))
                counts["escalated"] += 1
        if item["status"] == "accepted" and item.get("expires") and d(item["expires"]) < today:
            item["status"] = "needs action"
            item["history"].append({"date": today.isoformat(), "rung": item["rung"], "status": item["status"],
                                    "note": f"risk acceptance expired {item['expires']}"})
            issues.append(issue("Acceptance expired", item, f"Accepted until {item['expires']}. Re-decide."))
        na, ld = fm.AGE_OFF.get("needs_action_days"), fm.AGE_OFF.get("light_duty_days")
        if item["status"] == "needs action" and na is not None and today > d(item["due"]) + dt.timedelta(days=na):
            item["status"] = "window passed"
            item["closed_on"] = today.isoformat()
            item["history"].append({"date": today.isoformat(), "rung": item["rung"], "status": "window passed",
                                    "note": f"{na} days past due and never marked done"})
            wl["closed"].append(item); counts["aged off"] += 1
            continue
        if item["status"] == "light duty" and ld is not None and today > d(item["due"]) + dt.timedelta(days=ld):
            item["status"] = "window passed"
            item["closed_on"] = today.isoformat()
            item["history"].append({"date": today.isoformat(), "rung": item["rung"], "status": "window passed",
                                    "note": f"{ld} days past due with no escalation"})
            wl["closed"].append(item); counts["aged off"] += 1
            continue
        if item["status"] == "watching":
            start = d(item["added"]) if item.get("requested_by") else d(item["day0"])
            quiet_until = max(d(item["due"]), start + dt.timedelta(days=30))
            if today > quiet_until:
                item["status"] = "held"
                item["closed_on"] = today.isoformat()
                item["history"].append({"date": today.isoformat(), "rung": item["rung"], "status": "held",
                                        "note": "quiet past its window; deferral held"})
                wl["closed"].append(item); counts["held"] += 1
                continue
        still_open.append(item)
    wl["items"] = still_open
    wl["closed"] = [i for i in wl["closed"]
                    if d(i.get("closed_on", today.isoformat())) >= today - dt.timedelta(days=CLOSED_KEEP_DAYS)]
    wl["updated"] = today.isoformat()

    # 4. Publish
    with open(wl_path, "w") as fh:
        json.dump(wl, fh, indent=1)
    os.makedirs(os.path.join(a.root, "log"), exist_ok=True)
    with gzip.open(os.path.join(a.root, "log", f"{today.isoformat()}.jsonl.gz"), "wt") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in log)
    import commandos
    extra = commandos.binnacle_section(os.path.join(a.root, "log"), kev, today)
    with open(os.path.join(a.root, "BINNACLE.md"), "w") as fh:
        fh.write(binnacle(wl, today, extra))
    if a.issues_out:
        with open(a.issues_out, "w") as fh:
            json.dump(issues, fh, indent=1)
    print(f"{today}: scored {counts['scored']}, added {counts['added']}, escalated {counts['escalated']}, merged {counts['merged']}, "
          f"held {counts['held']}, aged off {counts['aged off']}, issues {len(issues)}, open {len(wl['items'])}")
    return wl, issues


def binnacle(wl, today, extra=None):
    items = wl["items"]
    iso, week = today.isoformat(), (today - dt.timedelta(days=7)).isoformat()
    soon = (today + dt.timedelta(days=7)).isoformat()
    qtrs = sorted([i for i in items if i["status"] == "needs action"], key=lambda i: (i["due"], -i["rung"]))
    light = sorted([i for i in items if i["status"] == "light duty"], key=lambda i: i["due"])
    watch = sorted([i for i in items if i["status"] == "watching"], key=lambda i: i["recheck_by"])
    acc = sorted([i for i in items if i["status"] == "accepted"], key=lambda i: i.get("expires") or "")
    escalated = [i for i in items if any(h["date"] >= week and h["note"].startswith("escalated") for h in i["history"])]
    cleared = [i for i in wl["closed"] if i.get("closed_on", "") >= week]
    overdue = [i for i in watch if i["recheck_by"] < iso]
    due_soon = [i for i in watch if iso <= i["recheck_by"] <= soon]

    def what(i):
        name = i.get("title") or i.get("name", i["advisory"])
        n = i.get("cve_count", len(i["cves"]))
        label = f"{name}: {n} CVE{'s' if n != 1 else ''}"
        return f"[{label}]({i['advisory']})" if i["advisory"].startswith("http") else label

    def row(i):
        due = i["due"] + (" (overdue)" if i["due"] < iso else "")
        return (f"| {what(i)} | {i['rung']} {i['label']} | {i['window']} | {due} | "
                f"{', '.join(i['kev_cves'][:3]) or '-'} |")

    out = ["# The Binnacle List", "",
           f"Updated {iso}. What came through sick call, and what it means for the plan of the day.", "",
           "sick-call triages; it isn't incident response. Credible signs of compromise in your own environment "
           "go to your IR plan, not this list.", "",
           f"## Confined to quarters ({len(qtrs)}): needs action", "",
           "Being exploited, or working exploit code is public. Act inside the window.", ""]
    out += (["| What | Rung | Window | Due | Exploited |", "| --- | --- | --- | --- | --- |"]
            + [row(i) for i in qtrs]) if qtrs else ["None."]
    out += ["", f"## Light duty ({len(light)}): patch by the due date (or your SLA, if sooner)", "",
            "Nothing public yet, but internet-facing edge or remote-access gear gets a short window anyway. "
            "Due dates here are sick-call's defaults. If your contract SLA is shorter, it wins.", ""]
    out += [f"- {what(i)}. {i['window']}, due {i['due']}" + (" (overdue)" if i["due"] < iso else "")
            for i in light] or ["None."]
    out += ["", f"## Escalated ({len(escalated)}): in the last 7 days", ""]
    out += [f"- {what(i)}: now rung {i['rung']} ({i['label']}), {i['window']}, due {i['due']}"
            for i in escalated] or ["None."]
    out += ["", f"## On the list ({len(watch)}): watching", "",
            "Deferred to the normal patch cycle and re-scored every day. Any one of them moves up the day a public "
            "PoC, working exploit code, or a KEV listing appears.", ""]
    if overdue:
        out += [f"**Recheck overdue ({len(overdue)}):**", ""] + \
               [f"- {what(i)}, recheck was due {i['recheck_by']}" for i in overdue] + [""]
    out += [f"Rechecks due in the next 7 days: {len(due_soon)}."]
    if acc:
        out += ["", f"## Accepted risk ({len(acc)})", ""] + \
               [f"- {what(i)}: accepted by {i['owner'] or '-'} until {i.get('expires') or '?'}" for i in acc]
    held = sum(1 for i in cleared if i["status"] == "held")
    passed = sum(1 for i in cleared if i["status"] == "window passed")
    done = sum(1 for i in cleared if i["status"] == "done")
    if extra:
        out += [""] + extra
    out += ["", f"## Cleared ({len(cleared)}): this week", "",
            f"Deferral held: {held}. Window passed: {passed}. Marked done: {done}.", "",
            "The full record, with every item's history, is in [watchlist.json](watchlist.json).", ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cvelist", required=True); ap.add_argument("--kev", required=True)
    ap.add_argument("--nuclei", help="nuclei-templates checkout; a shallow clone is fine")
    ap.add_argument("--today", help="YYYY-MM-DD, default today (UTC)")
    ap.add_argument("--lookback", type=int, default=3, help="days of new disclosures to take in (overlap is safe)")
    ap.add_argument("--requested", metavar="CVE-ID", help="add this CVE's advisory regardless of the SMB filter")
    ap.add_argument("--requested-by", default="manual run")
    ap.add_argument("--root", default=ROOT, help="repo root holding watchlist.json")
    ap.add_argument("--issues-out", help="write issues to open as JSON (the workflow uses this)")
    run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())
