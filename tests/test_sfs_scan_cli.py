"""Scanner jobs must fail visibly on missing inputs and still export JSON."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend import sfs_scan


class SFSScanCLITests(unittest.TestCase):
    def invoke(self, scope, root, cache):
        stdout, stderr = StringIO(), StringIO()
        args = ["sfs_scan", scope, "--input", str(root), "--cache", str(cache)]
        code = 0
        with patch("sys.argv", args), patch.dict(os.environ, {}), redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                sfs_scan.main()
            except SystemExit as exc:
                code = exc.code
        return code, json.loads(stdout.getvalue()), stderr.getvalue()

    def test_missing_input_fails_every_scope_with_json_and_resolved_path(self):
        with TemporaryDirectory() as folder:
            root = Path(folder) / "missing-export"
            for scope in sfs_scan.SCOPES:
                with self.subTest(scope=scope):
                    code, report, log = self.invoke(scope, root, Path(folder) / "cache")
                    self.assertEqual(code, 1)
                    self.assertEqual(report["id"], scope)
                    self.assertEqual(report["status"], "error")
                    self.assertEqual(report["findings"], [])
                    self.assertIn(str(root.absolute()), log)
                    self.assertIn(report["message"], log)
                    self.assertIn("SFS_INPUT_DIR", log)
                    self.assertFalse((Path(folder) / "cache" / f"{scope}.json").exists())

    def test_valid_api_input_passes_even_with_findings(self):
        with TemporaryDirectory() as folder:
            root = Path(folder) / "export"
            api = root / "src/api"
            api.mkdir(parents=True)
            (api / "server.py").write_text(
                "def _authorized(token):\n    if token == 'test-token':\n        return True\n", encoding="utf-8",
            )
            code, report, log = self.invoke("api", root, Path(folder) / "cache")
            self.assertEqual(code, 0)
            self.assertEqual(report["status"], "ok")
            self.assertTrue(report["findings"])
            self.assertIn(str(root.absolute()), log)
