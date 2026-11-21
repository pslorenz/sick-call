# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Steven Lorenz. Part of sick-call.
"""Builds a tiny cvelistV5 + KEV fixture that exercises every backtest outcome."""
import json, os


def _write_json(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh)

SW = "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0014"
PHP = "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"

def build(root):
    cves = os.path.join(root, "cvelist", "cves", "2026")
    def rec(cid, pub, vendor, product, score, adv=None, ssvc=None, state="PUBLISHED", assigner=""):
        r = {"cveMetadata": {"cveId": cid, "state": state, "datePublished": pub + "T18:00:00Z",
                             "assignerShortName": assigner},
             "containers": {"cna": {"affected": [{"vendor": vendor, "product": product}],
                                    "references": [{"url": adv, "tags": ["vendor-advisory"]}] if adv else [],
                                    "metrics": [{"cvssV3_1": {"baseScore": score}}]}, "adp": []}}
        if ssvc:
            ts, ex = ssvc
            r["containers"]["adp"].append({"metrics": [{"other": {"type": "ssvc", "content": {
                "timestamp": ts + "T19:00:00Z",
                "options": [{"Exploitation": ex}, {"Automatable": "no"}, {"Technical Impact": "total"}]}}}]})
        n = cid.split("-")[2]
        d = os.path.join(cves, n[:-3] + "xxx"); os.makedirs(d, exist_ok=True)
        _write_json(os.path.join(d, cid + ".json"), r)
    for c, s in [("107154", 8.8), ("107155", 8.8), ("82308", 7.5)]:
        rec("CVE-2026-" + c, "2026-11-06", "SonicWall", "SonicOS", s, SW, ("2026-11-06", "none"))
    rec("CVE-2026-19868", "2026-11-06", "SonicWall", "SonicOS", 7.1, SW)
    rec("CVE-2026-114938", "2026-11-17", "Oracle", "Java SE", 8.1, None, ("2026-11-17", "none"))
    rec("CVE-2026-109618", "2026-10-21", "PHP Group", "PHP", 9.2, PHP, ("2026-10-27", "active"))
    rec("CVE-2026-109619", "2026-10-21", "PHP Group", "PHP", 9.2, PHP)
    rec("CVE-2026-90001", "2026-09-10", "Acme", "Acme Kafka Connector", 9.8, None, ("2026-09-10", "none"))
    rec("CVE-2026-90002", "2026-09-15", "Microsoft", "Windows SMB", 9.8, None, ("2026-09-15", "none"))
    rec("CVE-2026-90003", "2026-08-01", "Old", "Thing", 7.0)
    rec("CVE-2026-90004", "2026-10-01", "Fortinet", "FortiOS", 8.0, None, ("2026-10-01", "none"), state="REJECTED")
    # A Patch Tuesday: three November CVEs (one exploited on release) and one from October.
    for n in ("70001", "70002", "70003"):
        rec("CVE-2026-" + n, "2026-11-10", "Microsoft", "Windows 11", 7.8, None, ("2026-11-10", "none"),
            assigner="microsoft")
    rec("CVE-2026-70004", "2026-10-13", "Microsoft", "Windows 11", 9.8, None, ("2026-10-13", "none"), assigner="microsoft")
    rec("CVE-2026-84869", "2026-09-20", "ConnectWise", "ScreenConnect", 9.0, None, ("2026-09-20", "none"))
    rec("CVE-2026-67277", "2026-09-02", "MikroTik", "RouterOS", 8.0, None, ("2026-09-02", "none"))
    kev = {"vulnerabilities": [
        {"cveID": "CVE-2026-84869", "vendorProject": "ConnectWise", "dateAdded": "2026-09-23", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2026-70002", "vendorProject": "Microsoft", "dateAdded": "2026-11-10", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2026-19868", "vendorProject": "SonicWall", "dateAdded": "2026-11-06", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2026-109618", "vendorProject": "PHP Group", "dateAdded": "2026-10-26", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2026-15409", "vendorProject": "SonicWall", "dateAdded": "2026-07-16", "knownRansomwareCampaignUse": "Known"}]}
    _write_json(os.path.join(root, "kev.json"), kev)
