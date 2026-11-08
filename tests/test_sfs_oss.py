import json
from pathlib import Path
import tempfile
from textwrap import dedent
import unittest

from backend import sfs_oss, sfs_scan
from backend.sfs_dependencies import extra_dependencies
from backend.sfs_rules import source_findings


class OperationalRulesTests(unittest.TestCase):
    def test_detects_dangerous_constructs_but_not_safe_alternatives(self):
        source = dedent("""
            import subprocess as sub
            from sqlite3 import connect as open_db
            SETTINGS = {"host": "0.0.0.0"}
            DB = "/tmp/example.db"
            def service(self):
                open_db(DB)
                sub.run(["date"])
                self.rfile.read(int(self.headers["Content-Length"]))
                open_db("/srv/private/example.db")
                sub.run(["/bin/date"])
                self.rfile.read(min(4096, int(self.headers["Content-Length"])))
                return {"host": "127.0.0.1", "example": "0.0.0.0"}
        """).strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "app.py"
            path.write_text(source)
            hits = {(item["id"], item["object"]) for item in source_findings(path, root)}
        self.assertEqual(hits, {
            ("SFS-WILDCARD-BIND", "app.py:3"),
            ("SFS-SQLITE-SHARED-TEMP", "app.py:6"),
            ("SFS-SUBPROCESS-PATH-SEARCH", "app.py:7"),
            ("SFS-HTTP-BODY-UNBOUNDED", "app.py:8"),
        })

    def test_documented_credential_links_to_api_scope_without_exporting_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "src/api/server.py"
            path.parent.mkdir(parents=True)
            secret = "synthetic-test-token-38"
            path.write_text(f"API_TOKEN = {secret!r}\n")
            doc = root / "docs/README.md"
            doc.parent.mkdir()
            doc.write_text("Authorization: Bearer $API_TOKEN\n")
            cache = root / "reports"
            initial = sfs_scan.run("api", root, cache)
            doc.write_text(doc.read_text() + f"Authorization: Bearer {secret}\n")
            result = sfs_scan.run("api", root, cache)
            self.assertNotEqual(initial["execution"]["fingerprint"], result["execution"]["fingerprint"])
        self.assertEqual([f["object"] for f in result["findings"] if f["id"] == "SFS-DOC-CREDENTIAL-EXPOSURE"],
                         ["docs/README.md:2"])
        self.assertNotIn(secret, json.dumps(result))

    def test_reviewed_advisory_matches_pins_and_respects_patch_branches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(
                "urllib3==1.26.17\nurllib3==1.26.18\nurllib3==2.0.6\nurllib3==2.0.7\nurllib3>=1.26.9\n"
            )
            hits = extra_dependencies(root)
        self.assertEqual(
            [item["object"] for item in hits if item["id"] == "SFS-DEP-CVE-2023-45803"],
            ["requirements.txt:1", "requirements.txt:3"],
        )


class OSSImportTests(unittest.TestCase):
    def test_normalizes_aliases_and_redacts_evidence_before_linking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("requests==2.19.1\n")
            (root / "a.py").touch()
            secret = "SENSITIVE_INPUT_MUST_NOT_APPEAR"
            dep = {"name": "requests", "version": "2.19.1", "vulns": [
                {"id": "PYSEC-2018-28", "aliases": ["CVE-2018-18074"], "description": secret},
                {"id": "GHSA-x84v-xcm2-53pg", "aliases": ["PYSEC-2018-28"], "fix_versions": ["2.20.0"]},
            ]}
            bandit = {"results": [
                {"filename": "a.py", "line_number": 3, "test_id": "B608", "issue_severity": "MEDIUM", "code": secret},
                {"filename": "a.py", "line_number": 3, "test_id": "B104", "issue_severity": "MEDIUM"},
            ], "errors": []}
            report = {"checks": [{"findings": [
                {"object": "a.py:3", "id": "WRP-SQLI-DYNAMIC", "status": "true_positive"},
                {"object": "requirements.txt:1", "id": "SFS-DEP-CVE-2018-18074", "status": "true_positive"},
            ]}]}
            results = sfs_oss.compare(root, report, {"bandit": bandit, "pip-audit": {"dependencies": [dep]}})["tools"]
            self.assertNotIn(secret, json.dumps(results))
            self.assertEqual(results["pip-audit"]["raw_count"], 2)
            self.assertEqual(results["pip-audit"]["normalized_count"], 1)
            self.assertEqual(results["pip-audit"]["linked"], 1)
            self.assertEqual(results["bandit"]["linked"], 1)
            dep["version"] = "2.20.0"
            with self.assertRaises(ValueError):
                sfs_oss.normalize("pip-audit", {"dependencies": [dep]}, root)

    def test_refuses_external_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                sfs_oss.normalize("gitleaks", [
                    {"RuleID": "key", "File": "/etc/hosts", "StartLine": 1, "EndLine": 1},
                ], root)
