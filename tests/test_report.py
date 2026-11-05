import contextlib
import copy
import csv
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("report", ROOT / "security-audit/scripts/render_report.py")
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "examples/synthetic-audit.json").read_text())

    def test_report_preserves_uncertainty_and_coverage(self):
        md, sheet = report.render(self.data)
        rows = list(csv.DictReader(io.StringIO(sheet)))
        self.assertEqual([r["id"] for r in rows], ["F-002", "F-003", "F-001"])
        self.assertEqual(rows[2]["state"], "candidate")
        self.assertIn("blocked", md)
        self.assertIn("No credentials read", md)
        self.assertIn("Review the broad write grant first", md)
        self.assertIn("unknown-state findings: 1", md)
        decisions = md.split("### Decisions available now")[1].split("### Verification requiring more evidence")[0]
        self.assertIn("F-002", decisions)
        self.assertNotIn("F-001", decisions)
        self.assertIn("Have the owner decide", md.split("## Next step")[1])

    def test_empty_findings_is_not_clean_bill(self):
        self.data["findings"] = []
        md, sheet = report.render(self.data)
        self.assertIn("does not establish safety", md)
        self.assertIn("blocked", md)
        self.assertEqual(len(list(csv.reader(io.StringIO(sheet)))), 1)

    def test_spreadsheet_formulas_are_neutralized(self):
        for payload in ('=HYPERLINK("https://example.invalid","click")', '+1+1', '-1+1', '@SUM(1)', '  =1+1', '\t=1+1', '\n=1+1'):
            with self.subTest(payload=payload):
                self.data["findings"][0]["item"] = payload
                _, sheet = report.render(self.data)
                cell = next(r["item"] for r in csv.DictReader(io.StringIO(sheet)) if r["id"] == "F-001")
                self.assertTrue(cell.startswith("'"))

    def test_markdown_injection_is_text(self):
        self.data["findings"][0]["item"] = '<script>alert(1)</script> [open](https://example.invalid) | table\n# forged'
        md, _ = report.render(self.data)
        self.assertNotIn("<script>", md)
        self.assertNotIn("[open](", md)
        self.assertIn("\\|", md)

    def test_secret_like_values_rejected_without_echo(self):
        payloads = ['ghp_' + 'A' * 36, 'sk-' + 'B' * 25, '-----BEGIN PRIVATE KEY-----', 'Authorization: Bearer fake-value', 'https://example.invalid/?token=fake', 'https://user:pass@example.invalid/']
        for payload in payloads:
            with self.subTest(kind=payload[:3]):
                self.data["findings"][0]["evidence"] = payload
                with self.assertRaises(report.InvalidReport) as caught:
                    report.render(self.data)
                self.assertNotIn(payload, str(caught.exception))

    def test_extra_field_rejected_even_if_secret_is_unrecognized(self):
        self.data["findings"][0]["password"] = "invented fixture only"
        with self.assertRaises(report.InvalidReport):
            report.render(self.data)

    def test_missing_and_duplicate_coverage_rejected(self):
        for change in (lambda d: d["coverage"].pop(), lambda d: d["coverage"].__setitem__(1, d["coverage"][0])):
            d = copy.deepcopy(self.data)
            change(d)
            with self.assertRaises(report.InvalidReport):
                report.render(d)

    def test_duplicate_id_and_future_evidence_rejected(self):
        for key, value in (("id", "F-001"), ("observed_at", "2099-01-01"), ("confidence", "certain")):
            d = copy.deepcopy(self.data)
            d["findings"][1][key] = value
            with self.assertRaises(report.InvalidReport):
                report.render(d)

    def test_findings_cannot_claim_unchecked_category(self):
        self.data["findings"][0]["category"] = "keys"
        with self.assertRaises(report.InvalidReport):
            report.render(self.data)

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaises(report.InvalidReport):
            json.loads('{"scope":"one","scope":"two"}', object_pairs_hook=report.reject_duplicates)

    def test_private_outputs_no_overwrite_and_no_input_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, dest = root / "input.json", root / "output"
            source.write_text(json.dumps(self.data))
            before = source.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(report.main([str(source), "--output-dir", str(dest)]), 0)
                contents = (dest / "report.md").read_bytes()
                self.assertEqual(report.main([str(source), "--output-dir", str(dest)]), 2)
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual((dest / "report.md").read_bytes(), contents)
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((dest / "report.md").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((dest / "findings.csv").stat().st_mode), 0o600)

    def test_invalid_input_does_not_write_or_echo(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, dest = root / "input.json", root / "output"
            sensitive = "SYNTHETIC_PRIVATE_MARKER"
            source.write_text('{"invalid": "' + sensitive)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(report.main([str(source), "--output-dir", str(dest)]), 2)
            self.assertFalse(dest.exists())
            self.assertNotIn(sensitive, stdout.getvalue() + stderr.getvalue())

    def test_symlink_input_and_output_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "input.json"
            source.write_text(json.dumps(self.data))
            link = root / "linked.json"
            link.symlink_to(source)
            dest = root / "output"
            dest.symlink_to(root, target_is_directory=True)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(report.main([str(link), "--output-dir", str(root / 'new')]), 2)
                self.assertEqual(report.main([str(source), "--output-dir", str(dest)]), 2)
            self.assertFalse((root / "report.md").exists())


if __name__ == "__main__":
    unittest.main()
