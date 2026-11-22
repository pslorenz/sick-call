# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Steven Lorenz. Part of sick-call.
"""Regression tests. Each case is a judgment call we made once; a rule change must not silently flip it.
Run from the repo root: python3 -m unittest discover -s tests"""
import csv, json, os, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Regression tests always run against the baseline, whatever sick-call.local.json says.
BASE_ENV = {**os.environ, "SICK_CALL_CONFIG": "none"}
sys.path.insert(0, ROOT)
from tests.fixtures.build import build, _write_json  # noqa: E402

def _read_csv(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))

def meter(case, env=None):
    out = subprocess.run([sys.executable, "tools/fud_meter.py", f"cases/{case}", "--json"],
                         cwd=ROOT, capture_output=True, text=True, check=True, env=env or BASE_ENV).stdout
    return json.loads(out)

class Cases(unittest.TestCase):
    def test_java4shell_demonstrated_and_validated(self):
        m = meter("java4shell.signals.json")
        self.assertEqual(m["rung"], 2)                         # real impact shown, exploits withheld
        self.assertTrue(m["publish"].startswith("validation brief"))  # fleet hit beats "calm down"
        self.assertTrue(m["review"].startswith("Held"))        # leaned on secondary sources

    def test_php2shell_mass_targeting(self):
        m = meter("php2shell.signals.json")
        self.assertEqual(m["rung"], 5)
        self.assertEqual(m["driven_by"], "CVE-2026-109618")   # the brand rolls up to its worst CVE
        self.assertTrue(m["review"].startswith("Held"))        # Wiz vs BleepingComputer

    def test_sonicwall_advisory_sibling_sets_rung(self):
        m = meter("sonicwall-0014.signals.json")
        self.assertEqual(m["rung"], 4)
        self.assertEqual(m["driven_by"], "CVE-2026-19868")    # the 7.1, not the 8.8s
        self.assertEqual(m["publish"], "action brief")

class Backtest(unittest.TestCase):
    def test_outcomes(self):
        with tempfile.TemporaryDirectory() as t:
            build(t)
            subprocess.run([sys.executable, "backtest/backtest.py", "--cvelist", f"{t}/cvelist", "--kev", f"{t}/kev.json",
                            "--end", "2026-11-20", "--out", f"{t}/out"], cwd=ROOT, check=True, capture_output=True,
                           env=BASE_ENV)
            rows = {r["cves"].split()[0]: r for r in _read_csv(f"{t}/out/scorecard.csv")}
        self.assertNotIn("CVE-2026-90003", rows)                       # outside the window
        self.assertNotIn("CVE-2026-90004", rows)                       # rejected
        sw = rows["CVE-2026-107154"]
        self.assertEqual((sw["rung_day0"], sw["outcome"]), ("4", "urgent on day 0"))   # same-day KEV sibling
        php = rows["CVE-2026-109618"]
        self.assertEqual(php["outcome"], "escalated inside window")    # feeds alone deferred it; watch list catches day 5
        self.assertEqual(rows["CVE-2026-90002"]["panic_avoided"], "yes")
        wg = rows["CVE-2026-81430"]                                     # same vendor, product, day: one advisory
        self.assertEqual((wg["advisory"], wg["cve_count"]), ("watchguard-2026-11-20", "3"))
        sc = rows["CVE-2026-84869"]                                     # remote access gets the 72-hour floor
        self.assertEqual((sc["remote_access"], sc["window_internet"]), ("yes", "72 hours"))
        mt = rows["CVE-2026-67277"]
        self.assertEqual((mt["smb"], mt["edge"]), ("yes", "yes"))      # MikroTik: in the baseline, on the edge
        self.assertEqual(mt["window_internet"], "7 days")               # edge floor no longer needs KEV history
        nov = rows["CVE-2026-70001"]                                    # one row for the whole Patch Tuesday
        self.assertEqual((nov["advisory"], nov["cve_count"], nov["kev_cves"]),
                         ("microsoft-release-2026-11-10", "3", "CVE-2026-70002"))
        self.assertEqual(nov["outcome"], "urgent on day 0")
        self.assertEqual(rows["CVE-2026-70004"]["advisory"], "microsoft-release-2026-10-13")
        self.assertEqual(rows["CVE-2026-114938"]["outcome"], "too new to judge")   # 3 days old at --end
        self.assertEqual(rows["CVE-2026-90002"]["outcome"], "deferral held")

class Matching(unittest.TestCase):
    def test_whole_words_only(self):
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import fud_meter as fm
        self.assertEqual(fm.smb_match("Acme KnowledgeBase message usage"), [])     # not edge, sage
        self.assertIn("edge", fm.smb_match("Microsoft Edge"))
        self.assertIn(".net", fm.smb_match("Microsoft .NET"))

    def test_vendor_anchored(self):
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import fud_meter as fm
        self.assertIsNone(fm.smb_pair("Acme", "Acme Agent for Windows"))           # third-party Windows app
        self.assertIsNone(fm.smb_pair("SomeDev", "Payment Gateway for WooCommerce"))  # plugin, not WooCommerce
        self.assertIsNone(fm.edge_pair("SomeDev", "Payment Gateway for WooCommerce"))
        self.assertEqual(fm.smb_pair("Microsoft", "Windows 11"), "microsoft: windows")
        self.assertEqual(fm.smb_pair("Fortinet", "FortiOS"), "fortinet")
        self.assertTrue(fm.edge_pair("Fortinet", "FortiOS"))

    def test_bulletin_grouping(self):
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import datetime
        import fud_meter as fm
        day = datetime.date(2026, 11, 12)
        cit = [("Citrix", "NetScaler ADC"), ("Citrix", "NetScaler Gateway")]
        self.assertEqual(fm.advisory_key("CVE-2026-1", "", day, [], cit), "citrix-2026-11-12")   # multi-product, one vendor
        nable = "https://me.n-able.com/s/security-advisory/aArV/cve2026125878-ognl-injection"
        self.assertEqual(fm.advisory_key("CVE-2026-125878", "", day, [nable], [("N-able", "N-central")]),
                         "n-able-2026-11-12")                                               # per-CVE page, no dashes
        self.assertEqual(fm.advisory_key("CVE-2026-2", "", day, [], [("Citrix NetScaler", "ADC")]),
                         "citrix-2026-11-12")                                               # vendor spelled two ways

class LocalConfig(unittest.TestCase):
    def test_overrides_apply(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = os.path.join(t, "local.json")
            _write_json(cfg, {"windows": {"4": ["next patch cycle", "72 hours", "72 hours"]},
                              "smb_products_remove": ["sonicwall", "sonicos"],
                              "publisher": {"name": "Example MSP"}})
            m = meter("sonicwall-0014.signals.json", env={**os.environ, "SICK_CALL_CONFIG": cfg})
        self.assertEqual(m["rung"], 4)                            # config never moves the rung
        self.assertEqual(m["publish"], "log")                     # their product list, their call
        self.assertEqual(m["publisher"]["name"], "Example MSP")

    def test_manual_run_bypasses_filter(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = os.path.join(t, "local.json")
            _write_json(cfg, {"smb_products_remove": ["sonicwall"]})
            env = {**os.environ, "SICK_CALL_CONFIG": cfg}
            dropped = meter("sonicwall-0014.signals.json", env=env)
            out = subprocess.run([sys.executable, "tools/fud_meter.py", "cases/sonicwall-0014.signals.json", "--json",
                                  "--requested", "Steven"], cwd=ROOT, capture_output=True, text=True, check=True, env=env).stdout
            forced = json.loads(out)
        self.assertEqual(dropped["publish"], "log")
        self.assertEqual(dropped["log_record"]["reason"], "not SMB-relevant; enterprise queue")
        self.assertTrue(forced["publish"].startswith("action brief (requested: Steven"))

    def test_bad_window_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = os.path.join(t, "local.json")
            _write_json(cfg, {"windows": {"4": ["soonish", "72 hours", "24 hours"]}})
            r = subprocess.run([sys.executable, "tools/fud_meter.py", "cases/sonicwall-0014.signals.json"],
                               cwd=ROOT, capture_output=True, text=True, env={**os.environ, "SICK_CALL_CONFIG": cfg})
        self.assertNotEqual(r.returncode, 0)

    def test_remove_one_add_one(self):
        """Removing a baseline product and adding your own must still match the addition,
        even for a vendor the vendor-anchored table has never heard of."""
        with tempfile.TemporaryDirectory() as t:
            cfg = os.path.join(t, "local.json")
            _write_json(cfg, {"smb_products_remove": ["quickbooks"], "smb_products_add": ["dentrix"]})
            out = subprocess.run([sys.executable, "-c",
                                  "import sys; sys.path.insert(0, 'tools'); import fud_meter as fm; "
                                  "print(fm.smb_pair('Henry Schein One', 'Dentrix Ascend'))"],
                                 cwd=ROOT, capture_output=True, text=True, check=True,
                                 env={**os.environ, "SICK_CALL_CONFIG": cfg}).stdout.strip()
        self.assertEqual(out, "added: dentrix")

class Nuclei(unittest.TestCase):
    def test_template_names(self):
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import fud_meter as fm
        self.assertEqual(fm.template_cve("http/cves/2026/CVE-2026-12345.yaml"), "CVE-2026-12345")
        self.assertEqual(fm.template_cve("CVE-2026-12345-rce.yaml"), "CVE-2026-12345")
        self.assertEqual(fm.template_cve("cve-2026-12345.yaml"), "CVE-2026-12345")
        self.assertIsNone(fm.template_cve("wordpress-plugin-rce.yaml"))
        with tempfile.TemporaryDirectory() as t:
            for name in ("CVE-2026-12345-rce.yaml", "CVE-2026-123456.yaml"):
                open(os.path.join(t, name), "w").close()
            self.assertTrue(fm.nuclei_has("CVE-2026-12345", t))
            self.assertFalse(fm.nuclei_has("CVE-2026-1234", t))      # prefix of another id: no match

class Daily(unittest.TestCase):
    """The v0.2 daily run: intake, watch, escalation, follow-through, manual requests."""

    def run_daily(self, t, today, *extra):
        r = subprocess.run([sys.executable, "tools/daily.py", "--cvelist", f"{t}/cvelist", "--kev", f"{t}/kev.json",
                            "--today", today, "--lookback", "2", "--root", f"{t}/repo",
                            "--issues-out", f"{t}/issues.json", *extra],
                           cwd=ROOT, capture_output=True, text=True, env=BASE_ENV)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(f"{t}/repo/watchlist.json") as fh:
            wl = json.load(fh)
        with open(f"{t}/issues.json") as fh:
            iss = json.load(fh)
        return wl, iss

    def item(self, wl, cve):
        return next(i for i in wl["items"] + wl["closed"] if cve in i["cves"])

    def test_lifecycle(self):
        with tempfile.TemporaryDirectory() as t:
            build(t)
            os.makedirs(f"{t}/repo")
            _write_json(f"{t}/repo/watchlist.json", {"version": 1, "items": []})

            # Windows bug lands quiet: light duty with a recheck date and an owner.
            wl, iss = self.run_daily(t, "2026-09-16")
            w = self.item(wl, "CVE-2026-90002")
            self.assertEqual((w["status"], w["rung"]), ("watching", 0))
            self.assertTrue(w["recheck_by"] and w["owner"] == "Steven" and w["expires"] is None)

            # SonicWall advisory with a same-day KEV sibling: needs action, and an issue.
            wl, iss = self.run_daily(t, "2026-11-07")
            sw = self.item(wl, "CVE-2026-19868")
            self.assertEqual(sw["status"], "needs action")
            self.assertTrue(any("Brief needed" in i["title"] for i in iss))
            # ...and the quiet Windows bug has cleared as held.
            self.assertEqual(self.item(wl, "CVE-2026-90002")["status"], "held")

            # Java4Shell arrives quiet, then lands on KEV: escalation.
            wl, _ = self.run_daily(t, "2026-11-18")
            self.assertEqual(self.item(wl, "CVE-2026-114938")["status"], "watching")
            with open(f"{t}/kev.json") as fh:
                kev = json.load(fh)
            kev["vulnerabilities"].append({"cveID": "CVE-2026-114938", "vendorProject": "Oracle",
                                           "dateAdded": "2026-11-19", "knownRansomwareCampaignUse": "Unknown"})
            _write_json(f"{t}/kev.json", kev)
            wl, iss = self.run_daily(t, "2026-11-19")
            j = self.item(wl, "CVE-2026-114938")
            self.assertEqual((j["status"], j["rung"]), ("needs action", 4))
            self.assertEqual(j["history"][-1]["note"], "escalated from rung 0")
            self.assertTrue(any(i["title"].startswith("[sick-call] Rung up") for i in iss))

            # Accepted risk comes back when it expires.
            for i in wl["items"]:
                if "CVE-2026-114938" in i["cves"]:
                    i.update(status="accepted", expires="2026-11-25")
            _write_json(f"{t}/repo/watchlist.json", wl)
            wl, iss = self.run_daily(t, "2026-11-26")
            self.assertEqual(self.item(wl, "CVE-2026-114938")["status"], "needs action")
            self.assertTrue(any("Acceptance expired" in i["title"] for i in iss))

            # Binnacle List is written, with its sections.
            with open(f"{t}/repo/BINNACLE.md") as fh:
                md = fh.read()
            self.assertIn("Confined to quarters", md)
            self.assertIn("Light duty (", md)
            self.assertIn("patch by the due date (or your SLA, if sooner)", md)
            self.assertNotIn("owner", md.lower())                         # assignment lives in tickets
            self.assertIn("On the list (", md)
            self.assertNotIn("tripwire", md)

    def test_late_sibling_merged(self):
        """A vendor adds a CVE to a bulletin already on the list: it joins the open item."""
        with tempfile.TemporaryDirectory() as t:
            build(t)
            os.makedirs(f"{t}/repo")
            _write_json(f"{t}/repo/watchlist.json", {"version": 1, "items": []})
            wl, _ = self.run_daily(t, "2026-11-07")
            self.assertEqual(self.item(wl, "CVE-2026-19868")["cve_count"], 4)
            with open(f"{t}/cvelist/cves/2026/107xxx/CVE-2026-107154.json") as fh:
                late = json.load(fh)
            late["cveMetadata"].update(cveId="CVE-2026-119999", datePublished="2026-11-08T18:00:00Z")
            os.makedirs(f"{t}/cvelist/cves/2026/119xxx", exist_ok=True)
            _write_json(f"{t}/cvelist/cves/2026/119xxx/CVE-2026-119999.json", late)
            wl, _ = self.run_daily(t, "2026-11-09")
            sw = self.item(wl, "CVE-2026-19868")
            self.assertIn("CVE-2026-119999", sw["cves"])
            self.assertEqual(sw["cve_count"], 5)
            self.assertIn("added 1 CVE(s)", sw["history"][-1]["note"])
            self.assertEqual(sum(1 for i in wl["items"] if "CVE-2026-119999" in i["cves"]), 1)   # no second item

    def test_kev_list_updates_without_rung_jump(self):
        """Already at rung 4: a second CVE landing on KEV still shows up on the item."""
        with tempfile.TemporaryDirectory() as t:
            build(t)
            os.makedirs(f"{t}/repo")
            _write_json(f"{t}/repo/watchlist.json", {"version": 1, "items": []})
            wl, _ = self.run_daily(t, "2026-11-07")
            self.assertEqual(self.item(wl, "CVE-2026-19868")["kev_cves"], ["CVE-2026-19868"])
            with open(f"{t}/kev.json") as fh:
                kev = json.load(fh)
            kev["vulnerabilities"].append({"cveID": "CVE-2026-107154", "vendorProject": "SonicWall",
                                           "dateAdded": "2026-11-08", "knownRansomwareCampaignUse": "Unknown"})
            _write_json(f"{t}/kev.json", kev)
            wl, iss = self.run_daily(t, "2026-11-08")
            sw = self.item(wl, "CVE-2026-19868")
            self.assertEqual(sw["kev_cves"], ["CVE-2026-107154", "CVE-2026-19868"])
            self.assertEqual(sw["history"][-1]["note"], "now on KEV: CVE-2026-107154")
            self.assertFalse(any("Rung up" in i["title"] for i in iss))      # same rung: no new issue

    def test_acceptance_revoked_on_exploitation(self):
        """An acceptance signed at rung 0 doesn't survive the bug landing on KEV."""
        with tempfile.TemporaryDirectory() as t:
            build(t)
            os.makedirs(f"{t}/repo")
            _write_json(f"{t}/repo/watchlist.json", {"version": 1, "items": []})
            wl, _ = self.run_daily(t, "2026-11-18")
            for i in wl["items"]:
                if "CVE-2026-114938" in i["cves"]:
                    i.update(status="accepted", owner="Client CFO", expires="2027-06-30")
            _write_json(f"{t}/repo/watchlist.json", wl)
            with open(f"{t}/kev.json") as fh:
                kev = json.load(fh)
            kev["vulnerabilities"].append({"cveID": "CVE-2026-114938", "vendorProject": "Oracle",
                                           "dateAdded": "2026-11-19", "knownRansomwareCampaignUse": "Unknown"})
            _write_json(f"{t}/kev.json", kev)
            wl, iss = self.run_daily(t, "2026-11-19")
            j = self.item(wl, "CVE-2026-114938")
            self.assertEqual(j["status"], "needs action")
            self.assertEqual(j["revoked_acceptance"]["owner"], "Client CFO")
            self.assertIn("revoked at rung 4", j["history"][-1]["note"])
            self.assertTrue(any("Risk acceptance revoked" in i["body"] for i in iss))

    def test_light_duty(self):
        """Edge gear with nothing public: a 7-day patch-by date, shown once, aging off after."""
        with tempfile.TemporaryDirectory() as t:
            build(t)
            os.makedirs(f"{t}/repo")
            _write_json(f"{t}/repo/watchlist.json", {"version": 1, "items": []})
            wl, _ = self.run_daily(t, "2026-11-21")
            wg = self.item(wl, "CVE-2026-81430")
            self.assertEqual((wg["status"], wg["window"], wg["cve_count"]), ("light duty", "7 days", 3))
            self.assertEqual(wg["due"], "2026-11-27")               # 7 days from disclosure, not from intake
            with open(f"{t}/repo/BINNACLE.md") as fh:
                self.assertIn("WatchGuard (Dimension): 3 CVEs", fh.read())
            wl, _ = self.run_daily(t, "2026-12-10")
            self.assertEqual(self.item(wl, "CVE-2026-81430")["status"], "window passed")

    def test_age_off_config(self):
        """Public list ages off; a working copy with null keeps items until someone closes them."""
        with tempfile.TemporaryDirectory() as t:
            build(t)
            for name, cfg, expect in (("public", None, "window passed"),
                                      ("worklist", {"age_off": {"needs_action_days": None}}, "needs action")):
                os.makedirs(f"{t}/{name}")
                _write_json(f"{t}/{name}/watchlist.json", {"version": 1, "items": []})
                env = dict(BASE_ENV)
                if cfg:
                    _write_json(f"{t}/{name}.json", cfg); env["SICK_CALL_CONFIG"] = f"{t}/{name}.json"
                for day in ("2026-11-07", "2026-12-20"):
                    subprocess.run([sys.executable, "tools/daily.py", "--cvelist", f"{t}/cvelist", "--kev", f"{t}/kev.json",
                                    "--today", day, "--lookback", "2", "--root", f"{t}/{name}"],
                                   cwd=ROOT, check=True, capture_output=True, env=env)
                with open(f"{t}/{name}/watchlist.json") as fh:
                    wl = json.load(fh)
                sw = next(i for i in wl["items"] + wl["closed"] if "CVE-2026-19868" in i["cves"])
                self.assertEqual(sw["status"], expect, name)

    def test_commandos(self):
        """Repeat offenders on the Binnacle List, and the standalone hall-of-fame report."""
        with tempfile.TemporaryDirectory() as t:
            build(t)
            os.makedirs(f"{t}/repo")
            _write_json(f"{t}/repo/watchlist.json", {"version": 1, "items": []})
            self.run_daily(t, "2026-11-21", "--lookback", "30")
            with open(f"{t}/repo/BINNACLE.md") as fh:
                md = fh.read()
            self.assertIn("## Sick call commandos", md)
            self.assertIn("days of history so far", md)                 # 30-day seed, 90-day window: says so
            self.assertIn("| SonicWall | 1 | 4 | 1 | 1 | 0 |", md)       # one bulletin, 4 CVEs, short window, 1 on KEV same day
            out = subprocess.run([sys.executable, "tools/commandos.py", "--kev", f"{t}/kev.json",
                                  "--log-dir", f"{t}/repo/log", "--since", "2026-10-01", "--until", "2026-11-21"],
                                 cwd=ROOT, capture_output=True, text=True, check=True, env=BASE_ENV).stdout
            self.assertIn("# Sick call hall of fame: 2026-10-01 to 2026-11-21", out)
            self.assertIn("Counts only, no commentary.", out)

    def test_same_day_rerun_keeps_log(self):
        """A 30-day seed and a 2-day re-run on the same day: the log keeps both."""
        import gzip
        with tempfile.TemporaryDirectory() as t:
            build(t)
            os.makedirs(f"{t}/repo")
            _write_json(f"{t}/repo/watchlist.json", {"version": 1, "items": []})
            self.run_daily(t, "2026-11-21", "--lookback", "30")
            self.run_daily(t, "2026-11-21")                              # default 2-day lookback in run_daily
            with gzip.open(f"{t}/repo/log/2026-11-21.jsonl.gz", "rt") as fh:
                advisories = {json.loads(l)["advisory"] for l in fh}
            self.assertTrue(any("sonicwall" in x.lower() or "SNWLID" in x for x in advisories), advisories)
            with open(f"{t}/repo/BINNACLE.md") as fh:
                self.assertIn("| SonicWall |", fh.read())

    def test_manual_request(self):
        with tempfile.TemporaryDirectory() as t:
            build(t)
            os.makedirs(f"{t}/repo")
            _write_json(f"{t}/repo/watchlist.json", {"version": 1, "items": []})
            wl, _ = self.run_daily(t, "2026-11-20", "--requested", "CVE-2026-90001", "--requested-by", "Steven")
            k = self.item(wl, "CVE-2026-90001")                       # Kafka: not SMB, in by request
            self.assertEqual(k["requested_by"], "Steven")

    def test_manual_request_old_exploited(self):
        """Asking about an old, exploited CVE puts it on the list now instead of aging it straight off."""
        with tempfile.TemporaryDirectory() as t:
            build(t)
            os.makedirs(f"{t}/repo")
            _write_json(f"{t}/repo/watchlist.json", {"version": 1, "items": []})
            wl, iss = self.run_daily(t, "2026-11-21", "--requested", "CVE-2026-70004", "--requested-by", "Steven")
            ms = self.item(wl, "CVE-2026-70004")                       # Oct Patch Tuesday CVE, quiet: watching
            self.assertEqual((ms["status"], ms["requested_by"]), ("watching", "Steven"))
            wl, iss = self.run_daily(t, "2026-11-21", "--requested", "CVE-2026-70002", "--requested-by", "Steven")
            nov = self.item(wl, "CVE-2026-70002")                      # Nov Patch Tuesday, exploited on release
            self.assertEqual(nov["status"], "needs action")
            self.assertEqual(nov["due"], "2026-11-22")                 # a window from today, not from Nov 10
            self.assertEqual(nov["cve_count"], 3)                      # the whole release came with it

class Hardening(unittest.TestCase):
    def test_actions_pinned_to_sha(self):
        """Tags can be moved by whoever controls an action; a commit SHA can't. The daily run can push."""
        r = subprocess.run([sys.executable, "tools/pin_actions.py", "--check"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, "Unpinned actions; run `python tools/pin_actions.py`:\n" + r.stdout)

if __name__ == "__main__":
    unittest.main()
