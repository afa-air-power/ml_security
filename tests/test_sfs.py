import json
import tempfile
import unittest
from pathlib import Path
from textwrap import dedent
from unittest.mock import patch

from backend import sfs_scan, sfs_report
from backend.scanners import model, wrapper

ROOT = Path(__file__).resolve().parents[1]


class SFSTests(unittest.TestCase):
    def test_sql_tracks_assignments_and_branch_alternatives(self):
        source = dedent("""
            def find(cursor, user, variant):
                stmt = f"SELECT * FROM users WHERE name='{user}'"
                alias: str = stmt
                cursor.execute(alias)  # f-string and alias
                if variant:
                    stmt = "SELECT * FROM users WHERE name='{}'".format(user)
                else:
                    stmt = "SELECT * FROM users WHERE name=?"
                cursor.execute(stmt, (user,))  # dynamic in one branch
                stmt = "SELECT * FROM users WHERE name='%s'" % user
                cursor.executemany(stmt, [(user,)])  # percent interpolation
                stmt = "SELECT * FROM "
                stmt += user
                cursor.executescript(stmt)  # concatenation
        """)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.py"
            path.write_text(source, encoding="utf-8")
            result = wrapper.scan(path)
        self.assertEqual(result["status"], "ok")
        lines = {int(f["object"].rsplit(":", 1)[1]) for f in result["findings"] if f["id"] == "WRP-SQLI-DYNAMIC"}
        expected = {number for number, line in enumerate(source.splitlines(), 1) if "cursor.execute" in line}
        self.assertEqual(lines, expected)

    def test_sql_ignores_bound_parameters_static_parts_and_other_scopes(self):
        source = dedent("""
            def unrelated(name):
                stmt = f"SELECT * FROM users WHERE name='{name}'"

            async def find(cursor, name):
                cursor.execute(stmt)
                stmt = f"SELECT * FROM users WHERE name='{name}'"
                stmt = "SELECT " + "* FROM users WHERE name=?"
                cursor.execute(stmt, (name,))
                table = "users"
                stmt = f"SELECT * FROM {table} WHERE name=?"
                cursor.execute(stmt, (name,))
        """)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.py"
            path.write_text(source, encoding="utf-8")
            result = wrapper.scan(path)
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("WRP-SQLI-DYNAMIC", {f["id"] for f in result["findings"]})

    def test_only_declared_numeric_pins_match_advisories(self):
        ambiguous = [
            "requests>=2.19.1", "requests==2.19.*", "requests", "requests==2.19.1,!=2.19.1",
            "requests==2.19.1; python_version < '3.8'", "requests==2.32.0rc1",
            "requests==1!2.19.1", "requests @ https://example.invalid/sensitive-path",
            "-r ../sensitive-path.txt",
        ]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "model").mkdir()
            (root / "model/config.json").write_text("{}")
            (root / "requirements.txt").write_text("\n".join([
                "requests[security]==2.19.1 # vulnerable",
                "requests==2.32.0.0",
                *ambiguous,
            ]))
            (root / "docker-constraints.txt").write_text("urllib3==1.26.9\n")
            result = sfs_scan.scan_scope("model", root)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            {item["object"] for item in result["findings"]},
            {"requirements.txt:1 (requests==2.19.1)", "requirements.txt:1",
             "docker-constraints.txt:1 (urllib3==1.26.9)", "docker-constraints.txt:1"},
        )
        self.assertEqual(len(result["warnings"]), len(ambiguous))
        self.assertTrue(all(w["code"] == "DEPENDENCY_VERSION_UNRESOLVED" and not w["blocking"]
                            for w in result["warnings"]))
        self.assertNotIn("sensitive-path", json.dumps(result))

    def test_urllib3_advisory_respects_both_patched_branches(self):
        pins = ["1.26.18", "1.26.19", "1.26.20", "2.2.1", "2.2.2"]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "requirements.txt"
            path.write_text("\n".join(f"urllib3=={version}" for version in pins))
            result = model.scan(path)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            [f["object"] for f in result["findings"] if f["id"] == "MDL-DEP-CVE-2024-37891"],
            ["requirements.txt:1 (urllib3==1.26.18)", "requirements.txt:4 (urllib3==2.2.1)"],
        )

    def test_pin_in_hashed_requirements_and_structured_toml(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "requirements.txt").write_text(
                "requests==2.19.1 \\\n    --hash=sha256:" + "a" * 64 + "\n"
            )
            (root / "pyproject.toml").write_text(
                '[project]\ndependencies = ["requests>=2.19.1", "requests==2.19.1"]\n'
                '[tool.fake]\npackage = "requests==2.19.1"\n'
            )
            result = model.scan(root)
        self.assertEqual(result["status"], "ok")
        self.assertEqual({item["object"] for item in result["findings"]}, {
            "requirements.txt:1 (requests==2.19.1)",
            "pyproject.toml:project.dependencies[2] (requests==2.19.1)",
        })
        self.assertEqual([warning["object"] for warning in result["warnings"]],
                         ["pyproject.toml:project.dependencies[1]"])

    def test_docker_range_rule_does_not_match_version_prefix(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "model").mkdir()
            (root / "model/config.json").write_text("{}")
            (root / "Dockerfile").write_text(
                'RUN pip install "requests>=2.31,<2.32.1"\n'
                'RUN pip install "requests>=2.31,<2.32"\n'
            )
            result = sfs_scan.scan_scope("model", root)
        self.assertEqual([f["object"] for f in result["findings"]], ["Dockerfile:2"])

    def test_bonus_detection_is_static(self):
        root = ROOT / "examples/sfs-bonus"
        model = sfs_scan.scan_scope("model", root)
        api = sfs_scan.scan_scope("api", root)
        self.assertIn("SFS-SYSTEM-PROMPT-INJECTION", {f["id"] for f in model["findings"]})
        self.assertIn("SFS-AUTH-BYPASS", {f["id"] for f in api["findings"]})

    def test_fingerprint_is_independent_per_component(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for scope in sfs_scan.SCOPES:
                path = root / ("model" if scope == "model" else f"src/{scope}")
                path.mkdir(parents=True)
                if scope == "model":
                    (path / "config.json").write_text("{}")
                else:
                    (path / "service.py").write_text("value = 1")
            snapshot = root / "snapshots"
            self.assertTrue(all(sfs_scan.run(scope, root, snapshot)["execution"]["cache"] == "miss"
                                for scope in sfs_scan.SCOPES))
            (root / "src/llm/service.py").write_text("value = 2")
            with patch("backend.sfs_scan.scan_scope", wraps=sfs_scan.scan_scope) as scanner:
                modes = {scope: sfs_scan.run(scope, root, snapshot)["execution"]["cache"]
                         for scope in sfs_scan.SCOPES}
                scanner.assert_called_once_with("llm", root)
            self.assertEqual([scope for scope, mode in modes.items() if mode == "miss"], ["llm"])

    def test_stale_decision_does_not_follow_changed_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "src/api/server.py"
            path.parent.mkdir(parents=True)
            path.write_text("def _authorized(t):\n    if t == 'synthetic':\n        return True\n")
            before = sfs_scan.run("api", root, root / "cache")
            path.write_text(path.read_text() + "\n# modified input\n")
            after = sfs_scan.run("api", root, root / "cache")
        key = before["findings"][0]["key"]
        triage = {key: {"status": "true_positive", "comment": "Резервный пропуск авторизации."}}
        self.assertTrue(sfs_report.build_report([before], triage)["summary"]["gate_passed"])
        self.assertFalse(sfs_report.build_report([after], triage)["summary"]["gate_passed"])

    def test_each_unresolved_or_uncommented_finding_fails_even_if_low(self):
        finding = {"id": "TEST", "object": "file.py:1", "key": "test", "severity": "low",
                   "evidence": "evidence"}
        check = {"id": "api", "status": "ok", "findings": [finding]}
        for verdict in (None, {"status": "false_positive", "comment": "  "}, {"status": "fixed", "comment": "check"}):
            result = sfs_report.build_report([check], {"test": verdict})
            self.assertFalse(result["summary"]["gate_passed"])
            self.assertIn("blocks", [edge["type"] for edge in result["decision_graph"]["edges"]])
        for status in sfs_report.STATUSES:
            result = sfs_report.build_report([check], {"test": {"status": status, "comment": "Обоснование"}})
            self.assertTrue(result["summary"]["gate_passed"])
            self.assertEqual(result["summary"]["by_status"][status], 1)

    def test_scanner_does_not_echo_credential(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "src/api/server.py"
            path.parent.mkdir(parents=True)
            secret = "SFS_fake_credential_for_test"
            path.write_text(f"API_TOKEN = {secret!r}\n")
            result = sfs_scan.run("api", root, root / "cache")
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual([item["id"] for item in result["findings"]], ["SFS-HARDCODED-CREDENTIAL"])
