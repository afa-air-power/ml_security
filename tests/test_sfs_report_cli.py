"""The CI command must explain a rejected gate without corrupting its artifacts."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend import sfs_report
from backend.sfs_scan import SCOPES


class SFSReportCLITests(unittest.TestCase):
    def setUp(self):
        self.folder = TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.registry = self.root / "triage.json"
        self.registry.write_text('{"decisions": {}}', encoding="utf-8")
        for scope in SCOPES:
            self.write_check(scope)

    def write_check(self, scope, findings=None):
        (self.root / f"{scope}.json").write_text(json.dumps({
            "id": scope, "status": "ok", "findings": findings or [], "scanned_files": [],
        }), encoding="utf-8")

    def invoke(self):
        stdout, stderr = StringIO(), StringIO()
        args = ["sfs_report", "--reports", str(self.root), "--triage", str(self.registry),
                "--markdown", str(self.root / "triage.md"), "--gitlab-dir", str(self.root)]
        code = 0
        with patch("sys.argv", args), redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                sfs_report.main()
            except SystemExit as exc:
                code = exc.code
        report = json.loads(stdout.getvalue())
        self.assertTrue((self.root / "triage.md").read_text(encoding="utf-8"))
        for name in ("gl-sast-report.json", "gl-dependency-scanning-report.json"):
            native = json.loads((self.root / name).read_text(encoding="utf-8"))
            self.assertIn("scan", native)
        return code, report, stderr.getvalue()

    @staticmethod
    def finding():
        return {"id": "TEST", "object": "src/api/service.py:1", "evidence": "Evidence.",
                "severity": "low", "key": "finding-fingerprint"}

    def test_reviewed_finding_passes_and_keeps_stdout_as_json(self):
        item = self.finding()
        self.write_check("api", [item])
        self.registry.write_text(json.dumps({"decisions": {
            item["key"]: {"status": "true_positive", "comment": "Reviewed."},
        }}), encoding="utf-8")
        code, report, log = self.invoke()
        self.assertEqual(code, 0)
        self.assertTrue(report["summary"]["gate_passed"])
        self.assertEqual(report["summary"]["total_findings"], 1)
        self.assertIn("sfs_report: passed", log)
        self.assertIn("unresolved=0; blocking_warnings=0", log)

    def test_unreviewed_finding_fails_with_key_and_preserves_reports(self):
        item = self.finding()
        self.write_check("api", [item])
        code, report, log = self.invoke()
        self.assertEqual(code, 1)
        self.assertFalse(report["summary"]["gate_passed"])
        self.assertIn(report["summary"]["gate_reason"], log)
        self.assertIn("sfs_report: blocked", log)
        self.assertIn("unresolved=1", log)
        self.assertIn("[api/TEST]", log)
        self.assertIn(item["object"], log)
        self.assertIn(f"key={item['key']}", log)
        self.assertIn(str(self.registry), log)

    def test_missing_scan_artifact_fails_with_scope_and_filename(self):
        (self.root / "api.json").unlink()
        code, report, log = self.invoke()
        self.assertEqual(code, 1)
        self.assertEqual(report["summary"]["overall_status"], "error")
        self.assertIn("blocking_warnings=1", log)
        self.assertIn("[api/CHECK_ERROR]", log)
        self.assertIn("api.json", log)

    def test_missing_or_corrupt_registry_fails_with_registry_path(self):
        for content in (None, "broken JSON"):
            with self.subTest(content=content):
                if content is None:
                    self.registry.unlink()
                else:
                    self.registry.write_text(content, encoding="utf-8")
                code, report, log = self.invoke()
                self.assertEqual(code, 1)
                self.assertFalse(report["summary"]["gate_passed"])
                self.assertIn("[model/TRIAGE_REGISTRY_ERROR]", log)
                self.assertIn(str(self.registry), log)
