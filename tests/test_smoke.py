"""Smoke tests for CERTSEARCH. No network. Run with: python -m pytest (or unittest)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certsearch import TOOL_NAME, TOOL_VERSION, analyze, parse_export  # noqa: E402
from certsearch.cli import _render_html, main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "ct_export.json",
)

JSON_SAMPLE = """[
  {"issuer_name":"O=Let's Encrypt","name_value":"example.com\\nwww.example.com",
   "not_after":"2026-12-01T00:00:00"},
  {"issuer_name":"CN=Sketchy Root CA","name_value":"vpn.example.com",
   "not_after":"2027-01-01T00:00:00"}
]"""

CSV_SAMPLE = (
    "common_name,issuer,not_after\n"
    "blog.example.com,Let's Encrypt,2026-12-01T00:00:00\n"
    "shop.example.com,DigiCert,2026-12-01T00:00:00\n"
)


class TestParsing(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "certsearch")
        self.assertTrue(TOOL_VERSION)

    def test_parse_json(self):
        certs = parse_export(JSON_SAMPLE)
        self.assertEqual(len(certs), 2)
        self.assertIn("www.example.com", certs[0].names)

    def test_parse_csv(self):
        certs = parse_export(CSV_SAMPLE)
        self.assertEqual(len(certs), 2)
        names = {c.primary for c in certs}
        self.assertEqual(names, {"blog.example.com", "shop.example.com"})

    def test_parse_jsonl(self):
        jsonl = "\n".join(json.dumps(o) for o in json.loads(JSON_SAMPLE))
        certs = parse_export(jsonl)
        self.assertEqual(len(certs), 2)

    def test_parse_empty(self):
        self.assertEqual(parse_export("   "), [])


class TestAnalysis(unittest.TestCase):
    def setUp(self):
        with open(DEMO, encoding="utf-8") as fh:
            self.certs = parse_export(fh.read())
        self.res = analyze(self.certs, "example.com")

    def test_subdomains_found(self):
        self.assertIn("api.example.com", self.res.subdomains)
        self.assertIn("login.example.com", self.res.subdomains)
        # external lookalike must NOT be counted as a subdomain
        self.assertNotIn("secure-example-login.com", self.res.subdomains)

    def test_wildcard(self):
        self.assertIn("*.example.com", self.res.wildcards)

    def test_unknown_issuer_flagged(self):
        kinds = {(f.kind, f.name) for f in self.res.findings}
        self.assertIn(("unknown_issuer", "vpn.example.com"), kinds)

    def test_lookalike_flagged_critical(self):
        look = [f for f in self.res.findings if f.kind == "lookalike"]
        self.assertTrue(look)
        self.assertTrue(all(f.severity == "critical" for f in look))

    def test_sensitive_subdomain_flagged(self):
        self.assertTrue(
            any(f.kind == "sensitive_subdomain" and f.name == "login.example.com"
                for f in self.res.findings))

    def test_expired_flagged(self):
        self.assertTrue(any(f.kind == "expired" for f in self.res.findings))

    def test_max_severity(self):
        self.assertEqual(self.res.max_severity, "critical")

    def test_json_roundtrip(self):
        d = self.res.to_dict()
        json.dumps(d)  # must be serializable
        self.assertEqual(d["base_domain"], "example.com")
        self.assertTrue(d["findings"])

    def test_unrelated_cert_ignored(self):
        certs = parse_export(
            '[{"issuer_name":"O=Foo CA","name_value":"unrelated.org"}]')
        res = analyze(certs, "example.com")
        self.assertEqual(res.subdomains, [])
        self.assertEqual([f for f in res.findings if f.kind == "unknown_issuer"], [])


class TestHTML(unittest.TestCase):
    def test_html_self_contained(self):
        res = analyze(parse_export(open(DEMO, encoding="utf-8").read()), "example.com")
        html = _render_html(res)
        self.assertIn("<!doctype html>", html)
        self.assertIn("<style>", html)  # inline CSS, no external deps
        self.assertNotIn("http://", html.replace("https://", ""))  # no remote refs
        self.assertIn("CRITICAL", html)


class TestCLI(unittest.TestCase):
    def test_exit_nonzero_on_findings(self):
        rc = main(["analyze", DEMO, "-d", "example.com", "--format", "json"])
        self.assertEqual(rc, 1)

    def test_exit_zero_clean(self, ):
        # write a clean export to a temp file
        import tempfile
        clean = '[{"issuer_name":"O=DigiCert Inc","name_value":"www.clean.com",' \
                '"not_after":"2030-01-01T00:00:00"}]'
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False, encoding="utf-8") as tf:
            tf.write(clean)
            path = tf.name
        try:
            rc = main(["analyze", path, "-d", "clean.com", "--format", "table"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_bad_path(self):
        rc = main(["analyze", "/no/such/file.json", "-d", "example.com"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
