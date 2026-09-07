#!/usr/bin/env python3
"""Deterministic offline tests for MO4 — Android manifest scanner."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import firmware.android_scan as mo4
from firmware.android_scan import (
    AndroidManifestScanner, create_fixtures, FIXTURE_HARDENED, run_demo)


class TestVulnerableManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scanner = AndroidManifestScanner(mo4.SAMPLE_MANIFEST)
        cls.scanner.run()

    def test_findings_present(self):
        self.assertGreaterEqual(len(self.scanner.findings), 10)

    def test_critical_severity_present(self):
        sev = {f["severity"] for f in self.scanner.findings}
        self.assertIn("CRITICAL", sev)

    def test_debuggable_finding(self):
        cats = {f["category"] for f in self.scanner.findings}
        self.assertIn("debuggable", cats)

    def test_backup_and_cleartext(self):
        cats = {f["category"] for f in self.scanner.findings}
        self.assertIn("backup", cats)
        self.assertIn("cleartext", cats)

    def test_permissions_parsed(self):
        self.assertIn("android.permission.SEND_SMS", self.scanner.permissions)

    def test_components_parsed(self):
        self.assertGreater(len(self.scanner.components["activities"]), 0)
        exported = [c for c in self.scanner.components["providers"] if c["exported"]]
        self.assertEqual(len(exported), 1)

    def test_sms_network_combo_detected(self):
        cats = {f["category"] for f in self.scanner.findings}
        self.assertIn("sms_network_combo", cats)

    def test_summary_jsonable(self):
        s = self.scanner.summary()
        json.dumps(s)
        self.assertEqual(s["package"], "com.example.vulnerableapp")
        self.assertIn("findings", s)


class TestHardenedManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scanner = AndroidManifestScanner(FIXTURE_HARDENED)
        cls.scanner.run()

    def test_few_findings(self):
        self.assertLess(len(self.scanner.findings), 3)

    def test_no_exported_components(self):
        for key, comps in self.scanner.components.items():
            self.assertFalse(any(c["exported"] for c in comps))

    def test_no_debuggable(self):
        cats = {f["category"] for f in self.scanner.findings}
        self.assertNotIn("debuggable", cats)


class TestNetsecConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmp:
            create_fixtures(tmp)
            with open(os.path.join(tmp, "network_security_config.xml")) as f:
                cls.config = f.read()

    def test_domain_cleartext_detected(self):
        sc = AndroidManifestScanner(mo4.SAMPLE_MANIFEST)
        sc.check_netsec_config(self.config)
        cats = {f["category"] for f in sc.findings}
        self.assertIn("netsec_domain_cleartext", cats)

    def test_pin_expiry_detected(self):
        sc = AndroidManifestScanner(mo4.SAMPLE_MANIFEST)
        sc.check_netsec_config(self.config)
        cats = {f["category"] for f in sc.findings}
        self.assertIn("netsec_pin_expiry", cats)

    def test_base_config_secure_not_flagged(self):
        sc = AndroidManifestScanner(mo4.SAMPLE_MANIFEST)
        sc.check_netsec_config(self.config)
        for f in sc.findings:
            self.assertNotEqual(f["category"], "netsec_cleartext")

    def test_invalid_config(self):
        sc = AndroidManifestScanner(mo4.SAMPLE_MANIFEST)
        sc.check_netsec_config("<network-security-config>")
        cats = {f["category"] for f in sc.findings}
        self.assertIn("netsec_parse", cats)


class TestFixturesAndDemo(unittest.TestCase):
    def test_fixture_factory(self):
        with tempfile.TemporaryDirectory() as tmp:
            created = create_fixtures(tmp)
            self.assertEqual(len(created), 3)
            self.assertTrue(os.path.exists(os.path.join(tmp, "vulnerable_manifest.xml")))
            self.assertTrue(os.path.exists(os.path.join(tmp, "hardened_manifest.xml")))

    def test_demo_exits_zero_with_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = run_demo(os.path.join(tmp, "reports"))
            self.assertEqual(rc, 0)
            report = os.path.join(tmp, "reports", "mo4_demo_report.json")
            self.assertTrue(os.path.exists(report))
            with open(report) as f:
                data = json.load(f)
            self.assertIn("vulnerable", data)
            self.assertIn("hardened", data)
            self.assertGreater(len(data["vulnerable"]["findings"]),
                               len(data["hardened"]["findings"]))

    def test_invalid_manifest_stdout(self):
        sc = AndroidManifestScanner("<manifest><broken>")
        sc.run()
        cats = {f["category"] for f in sc.findings}
        self.assertIn("parse_error", cats)


if __name__ == "__main__":
    unittest.main()