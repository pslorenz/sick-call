#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Steven Lorenz. Part of sick-call.
"""
fud_meter.py - put a vuln on a six-rung urgency ladder, from "too theoretical to ever get a
PoC" to "the best time to patch was days ago."

The rung is the highest rung whose evidence is met. Nothing is a weighted sum, so every
verdict can be explained in one line and challenged with one source. Headline noise is
reported beside the rung, never mixed into it: "loud but rung 1" is the FUD callout.

SMB filter: list "products" (or set "smb_relevance": yes|indirect|no with "smb_note"). The meter
then says whether to write an action brief (rung 3+), a calm-down brief (rung 2 or below with loud
headlines), or just log it, and whether the brief may ship tagged Unreviewed or must be held.

A brand covering several CVEs goes in one file under "cves"; the highest rung wins.
Record source disagreements under "conflicts" so the writeup carries them.

If you pass an exposure level (from the inventory match), the meter also gives an action window.

Usage:
  fud_meter.py signals.json                      # offline
  fud_meter.py signals.json --fetch              # live CVE record, EPSS, KEV
  fud_meter.py signals.json --nuclei-dir ~/nuclei-templates   # public template = weaponized
  fud_meter.py signals.json --cvelist-dir ~/cvelistV5           # add sibling CVEs from the same advisory

Signals for edge gear: "edge_device": true and "vendor" (KEV vendorProject name). With --fetch the
meter counts that vendor's KEV entries from the last 12 months; offline, set "vendor_kev_12mo".
"""
import argparse, json, os, re, sys, urllib.request

CVE_API = "https://cveawg.mitre.org/api/cve/{}"
EPSS_API = "https://api.first.org/data/v1/epss?cve={}"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

LADDER = [
    (0, "Theoretical",  "This never had a PoC because it's too theoretical."),
    (1, "Proof of concept", "Someone made it crash or corrupt memory. Nobody has shown it doing harm."),
    (2, "Demonstrated", "Researchers showed real impact on real products. Exploits not public."),
    (3, "Weaponized",   "Working exploit code is public. Assume scanning starts this week."),
    (4, "Exploited",    "Confirmed exploitation in the wild."),
    (5, "Mass targeting", "The best time to patch this was days ago, so go do it now."),
]

# Default action windows by rung x exposure. Tune to your SLAs.
WINDOWS = {  # rung: (none, internal, internet)
    5: ("confirm inventory today", "24 hours", "now, hours not days"),
    4: ("next patch cycle", "72 hours", "24 hours"),
    3: ("next patch cycle", "7 days", "72 hours"),
    2: ("next patch cycle", "30 days", "7 days"),
    1: ("next patch cycle", "30 days", "30 days"),
    0: ("normal cycle", "normal cycle", "normal cycle"),
}

# Products a typical 120-500 seat SMB runs or depends on. Match is a case-insensitive substring.
SMB_PRODUCTS = ["windows", "microsoft 365", "m365", "exchange", "outlook", "office", "teams", "sharepoint", "onedrive",
    "intune", "entra", "chrome", "edge", "firefox", "fortinet", "fortigate", "fortios", "sonicwall", "watchguard",
    "meraki", "ubiquiti", "unifi", "sophos", "palo alto", "globalprotect", "cisco asa", "anyconnect", "vpn",
    "ninjaone", "connectwise", "screenconnect", "kaseya", "datto", "n-able", "teamviewer", "anydesk",
    "veeam", "synology", "qnap", "wordpress", "woocommerce", "php", "quickbooks", "sage", "adobe acrobat",
    "zoom", "vmware esxi", "hyper-v", "citrix", "printer", "ivanti", "openssh", "7-zip", "winrar",
    "java", "openjdk", "tomcat", ".net", "node.js", "log4j", "spring"]   # runtimes inside SMB web apps

# Vendor-anchored SMB baseline, used when vendor and product arrive separately (CVE records).
# A product keyword only counts for its own vendor, so "Acme Agent for Windows" isn't Windows and
# "Payment Gateway for WooCommerce" by some plugin author isn't WooCommerce. [] = every product
# from that vendor counts.
SMB_VENDOR_PRODUCTS = {
    "microsoft": ["windows", "office", "microsoft 365", "365", "exchange", "outlook", "teams", "sharepoint",
                  "onedrive", "intune", "entra", "edge", ".net", "hyper-v", "sql server", "remote desktop"],
    "google": ["chrome"], "mozilla": ["firefox", "thunderbird"],
    "apple": ["macos", "ios", "ipados", "safari"],
    "fortinet": [], "sonicwall": [], "watchguard": [], "sophos": [], "ubiquiti": [], "ivanti": [], "zyxel": [],
    "cisco": ["meraki", "asa", "anyconnect", "secure client", "firepower"],
    "palo alto networks": ["pan-os", "globalprotect"],
    "ninjaone": [], "connectwise": [], "kaseya": [], "datto": [], "n-able": [], "teamviewer": [], "anydesk": [],
    "veeam": [], "synology": [], "qnap": [], "ahsay": [], "mikrotik": [],
    "beyondtrust": ["remote support", "privileged remote access"], "splashtop": [], "atera": [], "simplehelp": [],
    "wordpress": ["wordpress"], "automattic": ["wordpress", "woocommerce", "jetpack"], "woocommerce": ["woocommerce"],
    "php group": ["php"], "php": ["php"],
    "intuit": ["quickbooks"], "adobe": ["acrobat", "reader"], "zoom": [], "citrix": [],
    "vmware": ["esxi"], "broadcom": ["esxi"], "openbsd": ["openssh"], "openssh": [], "7-zip": [], "rarlab": ["winrar"],
    "oracle": ["java", "jdk", "jre"], "eclipse foundation": ["temurin"], "amazon": ["corretto"],
    "apache software foundation": ["tomcat", "log4j"], "spring": [], "vmware tanzu": ["spring"],
}

# Vendors whose products sit on the internet edge, for the edge-device floor (same rules as above).
EDGE_VENDOR_PRODUCTS = {
    "fortinet": ["fortios", "fortigate", "fortiproxy", "fortiweb", "fortivoice", "fortimanager", "fortisiem", "fortiswitch"],
    "sonicwall": [], "watchguard": [], "sophos": ["firewall", "sfos"], "zyxel": [], "ivanti": ["connect secure", "policy secure", "epmm"],
    "palo alto networks": ["pan-os", "globalprotect"], "cisco": ["asa", "firepower", "ftd", "meraki"],
    "citrix": ["netscaler", "gateway", "adc"], "connectwise": ["screenconnect"], "progress": ["moveit"],
    "fortra": ["goanywhere"], "barracuda": [], "f5": ["big-ip"], "ubiquiti": ["unifi"], "mikrotik": ["routeros"],
}

# Remote access and RMM: the way into every client an MSP manages. These get their own, higher floor,
# with no KEV-history condition: the category has earned it.
REMOTE_ACCESS_VENDOR_PRODUCTS = {
    "connectwise": ["screenconnect", "control", "automate"], "kaseya": ["vsa"], "ninjaone": [],
    "n-able": ["n-central", "n-sight", "take control"], "teamviewer": [], "anydesk": [], "splashtop": [],
    "beyondtrust": ["remote support", "privileged remote access"], "atera": [], "simplehelp": [],
    "datto": ["rmm"], "solarwinds": ["dameware"],
}
REMOTE_ACCESS_WORDS = ["screenconnect", "connectwise control", "kaseya vsa", "teamviewer", "anydesk", "splashtop",
                       "beyondtrust", "simplehelp", "n-central", "take control", "datto rmm", "ninjaone", "atera"]

# Vendors that ship on a schedule. Their CVEs are grouped into one advisory per release, keyed by the
# CVE's assigning CNA and its publish date. A Patch Tuesday with 1,000+ CVEs is one brief, led by the
# few that are exploited, not 1,000 briefs. "day" is the default because scheduled releases publish
# all their CVEs on one day; grouping by calendar month folded early out-of-band CVEs into the next
# Patch Tuesday and made its day 0 too early. "month" is still available for vendors that dribble.
RELEASE_GROUPS = {"microsoft": "day", "adobe": "day", "oracle": "day", "chrome": "day", "mozilla": "day"}

def canonical_vendor(vendor):
    """'Citrix NetScaler' and 'Citrix', or 'Ubiquiti Inc' and 'Ubiquiti', are one vendor for grouping.
    Uses the vendor names in the baseline tables; anything unknown is kept as written."""
    v = (vendor or "").strip().lower()
    known = sorted(set(SMB_VENDOR_PRODUCTS) | set(EDGE_VENDOR_PRODUCTS) | set(REMOTE_ACCESS_VENDOR_PRODUCTS),
                   key=len, reverse=True)
    hit = _word_match(known, v)
    return max(hit, key=len) if hit else v

def advisory_key(cid, assigner, published, advisories, pairs):
    """One key per advisory, used by the backtest and the daily run alike:
    1. a scheduled release (Patch Tuesday, Chrome, Oracle CPU...),
    2. else a shared vendor-advisory URL (per-CVE pages don't count),
    3. else one vendor's bulletin day: every CVE from that vendor published that day,
    4. else the CVE on its own."""
    import re as _re
    k = release_key(assigner, published)
    if k:
        return k
    # A per-CVE page (psirt.vendor.com/CVE-2026-81434, or .../cve2026125878-...) isn't a shared
    # bulletin; only URLs that don't name this CVE can tie siblings together.
    norm = lambda x: _re.sub(r"[^a-z0-9]", "", x.lower())
    shared = [u for u in advisories if norm(cid) not in norm(u)]
    if shared:
        return shared[0]
    vendors = {canonical_vendor(v) for v, _ in pairs if v and v.strip()}
    if published and len(vendors) == 1:
        slug = _re.sub(r"[^a-z0-9]+", "-", vendors.pop()).strip("-")
        if slug:
            return f"{slug}-{published.isoformat()}"
    return cid

def release_key(assigner, published):
    """Advisory key for a scheduled-release CVE, or None if its CNA doesn't ship on a schedule."""
    rule = RELEASE_GROUPS.get((assigner or "").lower())
    if not rule or not published:
        return None
    stamp = published.strftime("%Y-%m") if rule == "month" else published.isoformat()
    return f"{assigner.lower()}-release-{stamp}"

# Internet-facing edge gear. Used by the edge-device floor and the backtest.
EDGE_WORDS = ["sonicos", "sonicwall", "fortios", "fortigate", "fortiproxy", "fortiweb", "pan-os", "globalprotect",
              "asa", "firepower", "ivanti connect", "pulse", "citrix", "netscaler", "sma", "watchguard", "fireware",
              "sophos firewall", "meraki", "screenconnect", "moveit", "goanywhere", "vpn", "firewall", "gateway"]

# Every window string the tools understand, in days. Config may only use these.
WINDOW_DAYS = {"now, hours not days": 0, "confirm inventory today": 0, "24 hours": 1, "72 hours": 3,
               "7 days": 7, "14 days": 14, "30 days": 30, "next patch cycle": 30, "normal cycle": 30}

# Edge floor: internet-facing edge gear gets at least the rung-2 window (7 days). It used to require a
# KEV entry for the vendor in the last 12 months; the first backtest showed MikroTik slipping through
# that condition and landing on KEV in 5 days, so the default is now 0. MSPs can raise it in config.
EDGE_FLOOR = {"enabled": True, "min_vendor_kev_12mo": 0, "floor_rung": 2}
REMOTE_ACCESS_FLOOR = {"enabled": True, "floor_rung": 3}   # internet-facing remote access: at least 72 hours

# How long closed-out-by-nobody items stay on the Binnacle List past their due date. The public list is a
# reference feed, not anyone's worklist, so it ages things off. A working copy where people mark items
# done can set either value to null: then nothing leaves until a person closes it.
AGE_OFF = {"needs_action_days": 14, "light_duty_days": 7}
PANIC_CVSS = 9.0          # what a peer group treats as drop-everything without reading further
PUBLISHER = {"name": "sick-call", "reviewer": "Steven"}

# ---- Local overrides ---------------------------------------------------------------------
# The baseline above is a wide SMB default. An MSP tunes it in sick-call.local.json at the
# repo root (git-ignored), or points SICK_CALL_CONFIG at another file. SICK_CALL_CONFIG=none
# forces the baseline (the tests do this). See sick-call.example.json.
def _load_config():
    global SMB_PRODUCTS, SMB_PRODUCTS_ADDED, EDGE_WORDS, PANIC_CVSS, PUBLISHER
    import os as _os
    path = _os.environ.get("SICK_CALL_CONFIG") or _os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "sick-call.local.json")
    if path.lower() == "none" or not _os.path.exists(path):
        return None
    c = json.load(open(path))
    drop = {x.lower() for x in c.get("smb_products_remove", [])}
    SMB_PRODUCTS_ADDED = [x.lower() for x in c.get("smb_products_add", [])]
    SMB_PRODUCTS = [x for x in SMB_PRODUCTS if x not in drop] + SMB_PRODUCTS_ADDED
    EDGE_WORDS = EDGE_WORDS + [x.lower() for x in c.get("edge_words_add", [])]
    for vendor, prods in c.get("smb_vendors_add", {}).items():
        SMB_VENDOR_PRODUCTS[vendor.lower()] = [x.lower() for x in prods]
    for vendor in drop:
        SMB_VENDOR_PRODUCTS.pop(vendor, None)
    for cna, rule in c.get("release_groups", {}).items():
        if rule not in ("month", "day", "none"):
            raise SystemExit(f"{path}: release_groups[{cna}] must be month, day, or none")
        if rule == "none":
            RELEASE_GROUPS.pop(cna.lower(), None)
        else:
            RELEASE_GROUPS[cna.lower()] = rule
    for rung, vals in c.get("windows", {}).items():
        vals = tuple(vals)
        bad = [v for v in vals if v not in WINDOW_DAYS]
        if len(vals) != 3 or bad:
            raise SystemExit(f"{path}: windows[{rung}] needs 3 values (none, internal, internet) from {sorted(WINDOW_DAYS)}")
        WINDOWS[int(rung)] = vals
    EDGE_FLOOR.update(c.get("edge_floor", {}))
    REMOTE_ACCESS_FLOOR.update(c.get("remote_access_floor", {}))
    AGE_OFF.update(c.get("age_off", {}))
    PANIC_CVSS = float(c.get("panic_cvss", PANIC_CVSS))
    PUBLISHER = {**PUBLISHER, **c.get("publisher", {})}
    return path

# Analyst additions, tracked on their own. Slicing SMB_PRODUCTS by the baseline length broke
# as soon as a config removed one product and added another (same length, empty slice).
SMB_PRODUCTS_ADDED = []
CONFIG_PATH = _load_config()

def _word_match(words, text):
    """Whole-word match: 'edge' must not hit 'knowledge', 'sage' must not hit 'message'."""
    import re as _re
    text = text.lower()
    return [w for w in words if _re.search(r"(?<![a-z0-9])" + _re.escape(w) + r"(?![a-z0-9])", text)]

def smb_match(text):
    return _word_match(SMB_PRODUCTS, text)

def edge_match(text):
    return _word_match(EDGE_WORDS, text)

def edge_match_words(words, text):
    return _word_match(words, text)

def _pair_match(table, vendor, product):
    """Match a (vendor, product) pair against a vendor-anchored table. Returns a label or None."""
    vendor, product = (vendor or "").lower(), (product or "").lower()
    for v in _word_match(list(table), vendor):
        keys = table[v]
        if not keys:
            return v
        hit = _word_match(keys, product)
        if hit:
            return f"{v}: {hit[0]}"
    return None

def smb_pair(vendor, product):
    """SMB match for structured data. Analyst additions in smb_products_add count for any vendor."""
    return _pair_match(SMB_VENDOR_PRODUCTS, vendor, product) or \
        next((f"added: {w}" for w in _word_match(SMB_PRODUCTS_ADDED, product)), None)

def edge_pair(vendor, product):
    return _pair_match(EDGE_VENDOR_PRODUCTS, vendor, product)

def remote_access_pair(vendor, product):
    return _pair_match(REMOTE_ACCESS_VENDOR_PRODUCTS, vendor, product)

def floor_rung(rung, edge=False, vendor_kev=0, remote_access=False):
    """The rung whose window applies, after the edge and remote-access floors. Never changes the rung itself."""
    r = rung
    if edge and EDGE_FLOOR["enabled"] and (vendor_kev or 0) >= EDGE_FLOOR["min_vendor_kev_12mo"]:
        r = max(r, int(EDGE_FLOOR["floor_rung"]))
    if remote_access and REMOTE_ACCESS_FLOOR["enabled"]:
        r = max(r, int(REMOTE_ACCESS_FLOOR["floor_rung"]))
    return r

def smb_relevance(sig):
    """yes | indirect | no. 'indirect' = reaches SMBs through a host, MSP, or vendor appliance."""
    if sig.get("exposure") in ("internal", "internet"):
        return "yes", "found in your fleet"
    if sig.get("smb_relevance") in ("yes", "indirect", "no"):
        return sig["smb_relevance"], sig.get("smb_note", "set by analyst")
    hits = [p for p in sig.get("products", []) if smb_match(p)]
    if hits:
        return "yes", "SMB stack: " + ", ".join(hits)
    return "no", "no product in the SMB list (set smb_relevance to override)"

def publish_decision(rung, level, relevance, sig):
    holds = [h for h, on in (("sources disagree", sig.get("conflicts")),
                             ("facts rest on secondary sources", sig.get("secondary_sources"))) if on]
    review = ("Held for review: " + ", ".join(holds)) if holds else "May ship tagged Unreviewed"
    # A person asked for this one by name: it always gets a brief. The filter only governs unattended runs.
    if sig.get("requested"):
        if rung >= 3: kind = "action brief"
        elif level == "loud": kind = "calm-down brief"
        else: kind = "requested brief"
        return kind + f" (requested: {sig['requested']})", review
    # A confirmed hit in the fleet outranks the product list and the headlines.
    if sig.get("exposure") in ("internal", "internet"):
        kind = "action brief" if rung >= 3 else "validation brief (confirm workaround or patch on every hit)"
        holds = [h for h, on in (("sources disagree", sig.get("conflicts")),
                                 ("facts rest on secondary sources", sig.get("secondary_sources"))) if on]
        return kind, ("Held for review: " + ", ".join(holds)) if holds else "May ship tagged Unreviewed"
    if relevance == "no":
        return "log", "not SMB-relevant; enterprise queue"
    if rung >= 3:
        kind = "action brief"
    elif level == "loud":
        kind = "calm-down brief"
    else:
        return "log", "low rung and quiet; nobody is asking yet"
    holds = []
    if sig.get("conflicts"): holds.append("sources disagree")
    if sig.get("secondary_sources"): holds.append("facts rest on secondary sources")
    review = ("Held for review: " + ", ".join(holds)) if holds else "May ship tagged Unreviewed"
    return kind, review

def get_json(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "fud-meter"}), timeout=30) as r:
        return json.load(r)

def parse_cve5(rec):
    out = {"cna_score": None, "ssvc": {}, "kev_adp": False}
    cont = rec.get("containers", {})
    for m in cont.get("cna", {}).get("metrics", []):
        for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            if k in m and out["cna_score"] is None:
                out["cna_score"] = m[k].get("baseScore")
    for adp in cont.get("adp", []):
        for m in adp.get("metrics", []):
            o = m.get("other", {})
            if o.get("type") == "ssvc":
                for opt in o.get("content", {}).get("options", []):
                    out["ssvc"].update({k.lower(): str(v).lower() for k, v in opt.items()})
            if o.get("type") == "kev":
                out["kev_adp"] = True
    return out

_TEMPLATE_CVE = re.compile(r"(?<![0-9])(CVE-\d{4}-\d{4,})(?![0-9])", re.I)

def template_cve(path):
    """CVE id from a Nuclei template file name, or None. Handles suffixed names
    (CVE-2026-12345-rce.yaml) and never lets CVE-2026-1234 match CVE-2026-12345.
    Shared by fud_meter, daily and backtest so the three can't drift apart."""
    m = _TEMPLATE_CVE.search(os.path.basename(path))
    return m.group(1).upper() if m else None

def nuclei_has(cve_id, root):
    want = cve_id.upper()
    for dp, _, files in os.walk(os.path.expanduser(root)):
        if any(f.endswith(".yaml") and template_cve(f) == want for f in files):
            return True
    return False

def climb(e):
    """Return (rung, reasons-met, what-would-raise-it)."""
    met = []
    rung = 0
    if e.get("poc_crash_or_corruption") or e.get("ssvc_exploitation") == "poc":
        rung, met = 1, met + ["public PoC shows crash or memory corruption" if e.get("poc_crash_or_corruption") else "SSVC exploitation: poc"]
    if e.get("researcher_impact_demo"):
        rung, met = 2, met + ["researcher demonstrated impact on named products"]
    if e.get("public_working_exploit"):
        rung, met = 3, met + ["working exploit public: " + e["public_working_exploit"]]
    if e.get("kev") or e.get("ssvc_exploitation") == "active" or e.get("vendor_confirms_itw"):
        rung, met = 4, met + ["exploited in the wild (" + ", ".join(
            x for x, ok in (("CISA KEV", e.get("kev")), ("SSVC active", e.get("ssvc_exploitation") == "active"),
                            ("vendor confirms", e.get("vendor_confirms_itw"))) if ok) + ")"]
    if rung == 4:
        trig = []
        if e.get("kev_ransomware"): trig.append("KEV: known ransomware use")
        if e.get("mass_scanning_observed"): trig.append("mass scanning: " + (e["mass_scanning_observed"] if isinstance(e["mass_scanning_observed"], str) else "observed"))
        if not trig and (e.get("epss_percentile") or 0) >= 0.99:
            trig.append("EPSS 99th percentile+ (proxy only, confirm with a scanning feed)")
        if trig:
            rung, met = 5, met + ["mass targeting: " + "; ".join(trig)]
    nxt = {0: "a public PoC", 1: "a demo of real impact", 2: "public working exploit code",
           3: "confirmed in-the-wild use (KEV, SSVC active, vendor)", 4: "a scanning feed showing mass targeting, or KEV ransomware use", 5: None}[rung]
    return rung, met, nxt

def noise(h, rung):
    pts = sum([2 * bool(h.get("branded_name")), bool(h.get("dedicated_site_or_logo")), bool(h.get("famous_comparison")),
               bool(h.get("absolute_language")), (h.get("media_articles_72h") or 0) >= 15,
               (h.get("researcher_score") or 0) - (h.get("cna_score") or 99) >= 1])
    level = "loud" if pts >= 4 else "moderate" if pts >= 2 else "quiet"
    if level == "loud" and rung <= 2: gap = "Headlines run ahead of the evidence. Patch on the window below, not the press cycle."
    elif level == "quiet" and rung >= 3: gap = "Quiet for how real it is. Don't wait for the press to catch up."
    else: gap = "Headlines roughly match the evidence."
    return level, gap

def expand_advisory(items, cvelist_dir):
    """Add every CVE in a local cvelistV5 clone that shares a vendor-advisory URL with an input CVE.
    The PHP2Shell and SonicWall cases both had the exploited bug sitting next to the one asked about."""
    import glob, subprocess
    have = {i["cve_id"] for i in items}
    urls, years = set(), set()
    for i in items:
        cid = i["cve_id"]; yr, num = cid.split("-")[1], cid.split("-")[2]
        years.add(yr)
        path = i.get("cve_record") or next(iter(glob.glob(f"{cvelist_dir}/cves/{yr}/*/{cid}.json")), None)
        if not path: continue
        i.setdefault("cve_record", path)
        rec = json.load(open(path))
        for ref in rec.get("containers", {}).get("cna", {}).get("references", []):
            if "vendor-advisory" in ref.get("tags", []) or "advisory" in ref.get("url", "").lower():
                urls.add(ref["url"])
    added = []
    for url in urls:
        for yr in years:
            out = subprocess.run(["grep", "-rlF", "--", url, f"{cvelist_dir}/cves/{yr}"], capture_output=True, text=True).stdout
            for f in out.split():
                cid = os.path.basename(f)[:-5]
                if cid not in have:
                    have.add(cid); added.append(cid)
                    items.append({"cve_id": cid, "cve_record": f, "evidence": {}, "sibling_of": url})
    return added

def evaluate(item, a):
    """One CVE: returns dict with rung and evidence."""
    cid = item["cve_id"]; e = dict(item.get("evidence", {}))
    rec = get_json(CVE_API.format(cid)) if a.fetch else (json.load(open(item["cve_record"])) if item.get("cve_record") else {})
    c = parse_cve5(rec) if rec else {}
    e.setdefault("ssvc_exploitation", c.get("ssvc", {}).get("exploitation"))
    e.setdefault("ssvc_automatable", c.get("ssvc", {}).get("automatable"))
    if c.get("kev_adp"): e["kev"] = True
    if a.fetch:
        d = get_json(EPSS_API.format(cid)).get("data", [])
        if d: e["epss_percentile"] = float(d[0]["percentile"])
        for v in get_json(KEV_FEED).get("vulnerabilities", []):
            if v["cveID"] == cid:
                e["kev"] = True; e["kev_ransomware"] = v.get("knownRansomwareCampaignUse", "").lower() == "known"
    if a.nuclei_dir and nuclei_has(cid, a.nuclei_dir):
        e.setdefault("public_working_exploit", "Nuclei template")
    rung, met, nxt = climb(e)
    return {"cve": cid, "rung": rung, "evidence": met, "next": nxt, "epss": e.get("epss_percentile"),
            "cna_score": c.get("cna_score")}

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("signals"); ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--nuclei-dir"); ap.add_argument("--json", action="store_true")
    ap.add_argument("--cvelist-dir", help="local cvelistV5 clone; pulls in sibling CVEs from the same advisory")
    ap.add_argument("--requested", metavar="WHO", help="manual run: brief it regardless of the SMB filter (e.g. --requested Steven)")
    a = ap.parse_args()
    sig = json.load(open(a.signals))
    if a.requested:
        import datetime as _dt
        sig["requested"] = f"{a.requested}, {_dt.date.today().isoformat()}"
    # A brand can cover several CVEs: list them under "cves". A single-CVE file still works.
    items = sig.get("cves") or [{k: sig[k] for k in ("cve_id", "cve_record", "evidence") if k in sig}]
    siblings = expand_advisory(items, a.cvelist_dir) if a.cvelist_dir else []
    results = [evaluate(i, a) for i in items]
    top = max(results, key=lambda r: r["rung"])
    rung = top["rung"]
    hype = dict(sig.get("hype", {})); hype.setdefault("cna_score", top["cna_score"])
    level, gap = noise(hype, rung)
    exposure = sig.get("exposure")
    # Edge-device floor: internet-facing edge gear from a vendor with recent KEV entries gets at
    # least the rung-2 window, even when this bug has no public exploit yet.
    vendor_kev = sig.get("vendor_kev_12mo")
    if a.fetch and sig.get("vendor") and vendor_kev is None:
        import datetime
        cutoff = (datetime.date.today() - datetime.timedelta(days=365)).isoformat()
        vendor_kev = sum(1 for v in get_json(KEV_FEED).get("vulnerabilities", [])
                         if v.get("vendorProject", "").lower() == sig["vendor"].lower() and v.get("dateAdded", "") >= cutoff)
    edge_floor = bool(EDGE_FLOOR["enabled"] and sig.get("edge_device")
                      and (vendor_kev or 0) >= EDGE_FLOOR["min_vendor_kev_12mo"])
    remote = bool(sig.get("remote_access") or any(edge_match_words(REMOTE_ACCESS_WORDS, p) for p in sig.get("products", [])))
    window_rung = floor_rung(rung, sig.get("edge_device"), vendor_kev, remote) if exposure == "internet" else rung
    window = WINDOWS[window_rung][["none", "internal", "internet"].index(exposure)] if exposure else None
    _, label, line = LADDER[rung]
    if rung == 0 and any(i.get("evidence", {}).get("vendor_confirmed", True) and not i.get("evidence", {}).get("theoretical")
                         for i in items):
        label, line = "No public details yet", "Vendor-confirmed, details withheld. Nobody has shown it working in public."
    conflicts = sig.get("conflicts", [])
    name = sig.get("name", top["cve"])
    relevance, rel_note = smb_relevance(sig)
    brief, review = publish_decision(rung, level, relevance, sig)
    # Everything scored leaves a record, including what the filter drops. The backtest and the
    # watch list depend on it, and a later fleet hit can pull a logged advisory back in.
    import datetime as _dt
    log_record = {"advisory": name, "cves": [r["cve"] for r in results], "rung": rung, "driven_by": top["cve"],
                  "products": sig.get("products", []), "smb_relevance": relevance, "publish": brief,
                  "reason": (review if brief == "log" else ""), "scored_on": _dt.date.today().isoformat()}

    if a.json:
        print(json.dumps({"name": name, "rung": rung, "label": label, "line": line, "driven_by": top["cve"],
                          "per_cve": results, "conflicts": conflicts, "headline_noise": level, "noise_note": gap,
                          "exposure": exposure, "action_window": window, "edge_floor": edge_floor, "remote_access": remote, "vendor_kev_12mo": vendor_kev,
                          "smb_relevance": relevance, "smb_note": rel_note, "publish": brief, "review": review,
                          "publisher": PUBLISHER, "config": CONFIG_PATH, "log_record": log_record}, indent=2))
        return
    print(name + ("" if len(results) > 1 else f" ({top['cve']})"))
    print("  " + "  ".join(("[" + str(n) + "]") if n == rung else str(n) for n, _, _ in LADDER) + f"   {label}")
    print(f"  \"{line}\"")
    for r in results:
        if len(results) > 1:
            print(f"  {r['cve']}: rung {r['rung']}" + ("  <- sets the rung" if r is top else ""))
        if r is top or len(results) == 1:
            for m in r["evidence"]: print(f"    + {m}")
            if r["next"]: print(f"    Would move up with: {r['next']}")
            if r["epss"] is not None: print(f"    EPSS percentile: {r['epss']:.2f}")
    if siblings:
        print(f"  Pulled in from the same advisory: {', '.join(siblings)}")
    for cf in conflicts:
        print(f"  Sources disagree: {cf}")
    print(f"  Headline noise: {level}. {gap}")
    if edge_floor:
        print(f"  Edge device, vendor has {vendor_kev} KEV entries in 12 months: internet-facing window floor is rung {EDGE_FLOOR['floor_rung']}.")
    if remote and REMOTE_ACCESS_FLOOR["enabled"]:
        print(f"  Remote access tool: internet-facing window floor is rung {REMOTE_ACCESS_FLOOR['floor_rung']}.")
    if window: print(f"  Your exposure: {exposure}. Action window: {window}")
    else: print("  Your exposure: not matched yet. Run the inventory match for an action window.")
    print(f"  SMB relevance: {relevance} ({rel_note})")
    if CONFIG_PATH: print(f"  Local config: {CONFIG_PATH}")
    print(f"  Publish: {brief}" + (f". {review}" if brief != "log" else f" ({review})"))

if __name__ == "__main__":
    sys.exit(main())
