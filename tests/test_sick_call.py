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

if __name__ == "__main__":
    unittest.main()
