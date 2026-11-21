# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Steven Lorenz. Part of sick-call.
"""Regression tests. Each case is a judgment call we made once; a rule change must not silently flip it.
Run from the repo root: python3 -m unittest discover -s tests"""
import csv, json, os, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Regression tests always run against the baseline, whatever sick-call.local.json says.
BASE_ENV = {**os.environ, "SICK_CALL_CONFIG": "none"}
sys.path.insert(0, ROOT)
from tests.fixtures.build import build  # noqa: E402

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
            rows = {r["cves"].split()[0]: r for r in csv.DictReader(open(f"{t}/out/scorecard.csv"))}
        self.assertNotIn("CVE-2026-90003", rows)                       # outside the window
        self.assertNotIn("CVE-2026-90004", rows)                       # rejected
        sw = rows["CVE-2026-107154"]
        self.assertEqual((sw["rung_day0"], sw["outcome"]), ("4", "urgent on day 0"))   # same-day KEV sibling
        php = rows["CVE-2026-109618"]
        self.assertEqual(php["outcome"], "escalated inside window")    # feeds alone deferred it; watch list catches day 5
        self.assertEqual(rows["CVE-2026-90002"]["panic_avoided"], "yes")
        self.assertEqual(rows["CVE-2026-114938"]["outcome"], "deferral held")

class LocalConfig(unittest.TestCase):
    def test_overrides_apply(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = os.path.join(t, "local.json")
            json.dump({"windows": {"4": ["next patch cycle", "72 hours", "72 hours"]},
                       "smb_products_remove": ["sonicwall", "sonicos"],
                       "publisher": {"name": "Example MSP"}}, open(cfg, "w"))
            m = meter("sonicwall-0014.signals.json", env={**os.environ, "SICK_CALL_CONFIG": cfg})
        self.assertEqual(m["rung"], 4)                            # config never moves the rung
        self.assertEqual(m["publish"], "log")                     # their product list, their call
        self.assertEqual(m["publisher"]["name"], "Example MSP")

    def test_manual_run_bypasses_filter(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = os.path.join(t, "local.json")
            json.dump({"smb_products_remove": ["sonicwall"]}, open(cfg, "w"))
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
            json.dump({"windows": {"4": ["soonish", "72 hours", "24 hours"]}}, open(cfg, "w"))
            r = subprocess.run([sys.executable, "tools/fud_meter.py", "cases/sonicwall-0014.signals.json"],
                               cwd=ROOT, capture_output=True, text=True, env={**os.environ, "SICK_CALL_CONFIG": cfg})
        self.assertNotEqual(r.returncode, 0)

if __name__ == "__main__":
    unittest.main()
