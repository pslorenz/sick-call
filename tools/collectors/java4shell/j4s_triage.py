#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Steven Lorenz. Part of sick-call.
"""
j4s_triage.py - rank Java runtimes by Java4Shell (CVE-2026-114938) exposure.

This is not a scanner: it never touches a target. It joins facts you already have
(collector output, plus an optional exposure sheet) with a rule pack of preconditions
("gates") and ranks the result. Swap RULE for another CVE's gates and the engine is the same,
which is the shape a Winnow "precondition rule" would take.

Gate states: open | closed | mitigated | reduced | unknown. "reduced" never clears a host;
it drops it one tier and marks the tier with "-" (P2-).

Usage:
  j4s_triage.py collector1.csv [collector2.csv ...] [--exposure exposure.csv] [--out ranked.csv]

exposure.csv columns (any missing host is treated as "unknown reach"):
  host,internet_facing,products,outbound_untrusted
  jira01,yes,jira;confluence,no
"""
import argparse, csv, re, sys
from collections import Counter

# ---- Rule pack: everything CVE-specific lives here -------------------------------------
RULE = {
    "cve": "CVE-2026-114938",
    "name": "Java4Shell",
    # First fixed build per line (upstream numbering). Vendors number differently: verify.
    # Sources: Oracle Nov 2026 CPU affected list; Corgea write-up for upstream thresholds.
    "fixed": {17: (17, 0, 21, 1), 21: (21, 0, 13, 1), 25: (25, 0, 5, 1), 27: (27, 0, 1, 1)},
    "min_affected": {17: (17, 0, 6, 0)},
    "affected_special": [r"^1\.8\.0_511.*perf|8u511b33-perf"],   # Oracle 8 performance build
    "preauth_products": {"keycloak", "jira", "confluence", "artifactory", "jenkins", "pingfederate"},
    "postauth_products": {"kafka", "solr", "elasticsearch", "gerrit", "spinnaker"},
}

def vtuple(v):
    nums = [int(x) for x in re.findall(r"\d+", v or "")[:4]]
    if nums and nums[0] == 1 and len(nums) > 1:          # 1.8.0_xxx style
        nums = [8, 0, nums[3] if len(nums) > 3 else 0, 0]
    return tuple((nums + [0, 0, 0, 0])[:4])

def yes(v):
    return str(v).strip().lower() in {"yes", "y", "true", "1"}

def gate_cpu(r):
    if r["arch"].lower() not in {"x86_64", "amd64"}:
        return "closed", "not x86-64"
    return {"yes": ("open", "AVX-512 VBMI present"), "no": ("closed", "no AVX-512 VBMI")}.get(
        r["vbmi"].lower(), ("unknown", "VBMI not detected (run pwsh 7.4+ or check model)"))

def gate_jdk(r):
    rv = f'{r.get("runtime_version","")} {r["java_version"]}'
    if any(re.search(p, rv) for p in RULE["affected_special"]):
        return "open", "Oracle 8u511b33-perf build"
    v = vtuple(r["java_version"])
    major = v[0]
    if major not in RULE["fixed"]:
        return "closed", f"Java {major} line not affected by this CVE"
    lo = RULE["min_affected"].get(major)
    if lo and v < lo:
        return "closed", f"{r['java_version']} predates the vulnerable code"
    if v >= RULE["fixed"][major]:
        return "closed", "at or past fixed build (verify vendor numbering)"
    return "open", f"{r['java_version']} below fixed build"

def gate_intrinsic(r):
    avx, b64, live = r["use_avx"].strip(), r["base64_intrinsics"].strip().lower(), r["live_mitigation"].lower()
    if live == "yes":
        return "mitigated", "workaround flag on running process"
    if avx.isdigit() and int(avx) < 3:
        return "closed", f"JVM picks UseAVX={avx}"
    if b64 == "false":
        return "closed", "Base64 intrinsic off"
    if avx == "3" and b64 == "true":
        return "open", "UseAVX=3 + Base64 intrinsic"
    return "unknown", "JVM flags not collected"

def gate_reach(r, exp):
    e = exp.get(r["host"].lower()) or exp.get(r["host"].split(".")[0].lower())
    if not e:
        return "unknown", "no exposure data", set(), False
    prods = {p.strip().lower() for p in re.split(r"[;|]", e.get("products", "")) if p.strip()}
    inet, outbound = yes(e.get("internet_facing")), yes(e.get("outbound_untrusted"))
    if prods or inet or outbound:
        why = ", ".join(filter(None, ["internet-facing" if inet else "", "outbound TLS to untrusted" if outbound else "",
                                      "products: " + ";".join(sorted(prods)) if prods else ""]))
        return "open", why, prods, inet
    return "closed", "no service or outbound exposure recorded", prods, inet

def priority(g, prods, inet):
    states = [g["cpu"], g["jdk"], g["intrinsic"], g["reach"]]
    if "closed" in states:
        return "Clear", 0
    if g["intrinsic"] == "mitigated":
        return "P4", 10
    preauth = bool(prods & RULE["preauth_products"])
    unknowns = states.count("unknown")
    if unknowns:                                   # unknowns rank as P3 until data says otherwise
        return "P3?", 30 - unknowns
    if inet and preauth:
        tier, score = "P1", 100
    elif preauth or inet:
        tier, score = "P2", 70
    else:
        tier, score = "P3", 40
    # "reduced": a partial mitigation or a less-exploitable config (e.g. PHP-FPM vs mod_php,
    # memory_limit=-1). Still exposed, so it never clears; it drops one tier.
    if "reduced" in states:
        tier, score = {"P1": ("P2", 70), "P2": ("P3", 40), "P3": ("P3", 35)}[tier]
        tier += "-"
    return tier, score

def clearance(g, why):
    """Why a host is clear or mitigated, and whether that holds if the box changes.
    Durable: the software itself is fixed or the line was never affected.
    Conditional: something about the hardware or config holds the gate shut."""
    if g["jdk"] == "closed":
        return "durable", why["jdk"], "none"
    if g["cpu"] == "closed":
        return ("conditional: hardware", why["cpu"],
                "hardware refresh, host migration, or hypervisor CPU baseline change; take the vendor patch to make it durable")
    if g["intrinsic"] in ("closed", "mitigated"):
        return ("conditional: config", why["intrinsic"],
                "any restart, upgrade, or config push that drops the flag; take the vendor patch to make it durable")
    if g["reach"] == "closed":
        return "conditional: exposure", why["reach"], "any new service, listener, or outbound integration"
    return "", "", ""

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("collector_csv", nargs="+")
    ap.add_argument("--exposure")
    ap.add_argument("--out", default="j4s_ranked.csv")
    a = ap.parse_args()

    exp = {}
    if a.exposure:
        with open(a.exposure, newline="", encoding="utf-8-sig") as f:
            exp = {row["host"].strip().lower(): row for row in csv.DictReader(f)}

    rows = []
    for path in a.collector_csv:
        with open(path, newline="", encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                g, why = {}, {}
                g["cpu"], why["cpu"] = gate_cpu(r)
                g["jdk"], why["jdk"] = gate_jdk(r)
                g["intrinsic"], why["intrinsic"] = gate_intrinsic(r)
                g["reach"], why["reach"], prods, inet = gate_reach(r, exp)
                tier, score = priority(g, prods, inet)
                dur, basis, recheck = clearance(g, why) if tier in ("Clear", "P4") else ("", "", "")
                rows.append({"tier": tier, "score": score, "host": r["host"], "java_path": r["java_path"],
                             "java_version": r["java_version"], "vendor": r["java_vendor"],
                             **{f"gate_{k}": v for k, v in g.items()},
                             "why": " | ".join(f"{k}: {v}" for k, v in why.items()),
                             "clear_durability": dur, "clear_basis": basis, "recheck_when": recheck,
                             "evidence_collected": r.get("collected_utc", ""),
                             "running_pids": r.get("running_pids", "")})

    rows.sort(key=lambda x: (-x["score"], x["host"], x["java_path"]))
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["tier"])
        w.writeheader(); w.writerows(rows)

    c = Counter(r["tier"] for r in rows)
    print(f"{RULE['name']} ({RULE['cve']}): {len(rows)} runtimes on {len({r['host'] for r in rows})} hosts")
    for t in ["P1", "P2", "P2-", "P3", "P3-", "P3?", "P4", "Clear"]:
        if c[t]:
            print(f"  {t:5} {c[t]}")
    cond = [r for r in rows if r["clear_durability"].startswith("conditional")]
    if cond:
        print(f"  {len(cond)} clear or mitigated only conditionally; patch to make it durable:")
        for r in cond:
            print(f"    {r['host']:<14} {r['clear_durability']:<24} {r['clear_basis']}")
    print(f"Ranked list: {a.out}")
    for r in rows:
        if r["tier"] in {"P1", "P2", "P2-"}:
            print(f"  {r['tier']}  {r['host']:<14} {r['java_version']:<12} {r['java_path']}")

if __name__ == "__main__":
    sys.exit(main())
