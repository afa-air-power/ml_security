from datetime import datetime, timezone
from io import BytesIO
import json
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

from backend import archive_limits, sfs_report, sfs_scan
from backend.gitlab_reports import build_gitlab_reports
from backend.scanners import model


class ArchiveSafetyTests(unittest.TestCase):
    def test_bomb_is_rejected_before_open_and_cannot_pass_triage(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "model"
            source.mkdir()
            with ZipFile(source / "model.pt", "w", compression=ZIP_DEFLATED) as archive:
                archive.writestr("model/data.pkl", b"\x00" * (2 * 1024 * 1024))
            with patch.object(ZipFile, "open", side_effect=AssertionError("member must not open")):
                result = sfs_scan.run("model", root, root / "cache")
            finding, = result["findings"]
            self.assertEqual(finding["id"], "MDL-ARCHIVE-REJECTED")
            self.assertEqual(result["warnings"][0]["code"], "ARCHIVE_REJECTED")
            self.assertFalse((root / "cache/model.json").exists())
            report = sfs_report.build_report([result], {
                finding["key"]: {"status": "accepted_risk", "comment": "test"},
            })
            self.assertFalse(report["summary"]["gate_passed"])

    def test_metadata_cap_precedes_zip_construction(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "model.pt"
            with ZipFile(path, "w") as archive:
                archive.writestr("model/data.pkl", b"N.")
            with patch.object(archive_limits, "MAX_DIRECTORY", 32), patch(
                "backend.archive_limits.zipfile.ZipFile", side_effect=AssertionError("directory must not allocate"),
            ):
                result = model.scan(path)
        self.assertEqual(result["findings"][0]["id"], "MDL-ARCHIVE-REJECTED")

    def test_small_archives_still_scan_and_nested_archives_fail_closed(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "model.keras"
            with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
                archive.writestr("config.json", '{"class_name": "Lambda"}')
            result = model.scan(path)
            self.assertEqual([f["id"] for f in result["findings"]], ["MDL-KERAS-LAMBDA"])
            nested = BytesIO()
            with ZipFile(nested, "w") as archive:
                archive.writestr("data", b"safe")
            with ZipFile(path, "w") as archive:
                archive.writestr("config.json", nested.getvalue())
            result = model.scan(path)
        self.assertEqual([f["id"] for f in result["findings"]], ["MDL-ARCHIVE-REJECTED"])
        self.assertTrue(result["warnings"][0]["blocking"])

    def test_compressed_input_budget_applies_during_member_reads(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "model.keras"
            with ZipFile(path, "w") as archive:
                archive.writestr("config.json", b" " * 2048)
            with patch.object(archive_limits, "MAX_ZIP_INPUT_READ", 512):
                result = model.scan(path)
        finding, = result["findings"]
        self.assertEqual(finding["id"], "MDL-ARCHIVE-REJECTED")
        self.assertIn("Чтение сжатого ZIP", finding["evidence"])


class FullWeightCoverageTests(unittest.TestCase):
    def test_tail_peak_and_row_beyond_old_prefix_are_detected(self):
        shape = [512, 256]
        count = shape[0] * shape[1]
        body = b"\x00" * ((count - 1) * 2) + struct.pack("<H", 0x41c0)  # BF16 24
        header = json.dumps({"weights": {"dtype": "BF16", "shape": shape, "data_offsets": [0, len(body)]}}).encode()
        with TemporaryDirectory() as folder:
            path = Path(folder) / "weights.safetensors"
            path.write_bytes(struct.pack("<Q", len(header)) + header + body)
            result = model.scan(path)
        self.assertEqual(result["weight_coverage"], {
            "values_total": count, "values_inspected": count, "tensors_total": 1, "tensors_inspected": 1,
        })
        hits = {item["id"]: item["point"] for item in result["findings"] if "point" in item}
        self.assertEqual(hits["MDL-BACKDOOR-OUTLIER"]["coordinates"], [511, 255])
        self.assertEqual(hits["MDL-BACKDOOR-NEURON"]["coordinates"], [511])
        self.assertLess(hits["MDL-BACKDOOR-OUTLIER"]["metrics"]["sample_size"], count)


class GitLabReportTests(unittest.TestCase):
    def test_native_reports_preserve_binary_sites_and_group_exact_pins(self):
        def finding(rule, obj, **extra):
            return {"id": rule, "object": obj, "severity": "high", "evidence": "Evidence.",
                    "status": "true_positive", **extra}

        report = {
            "generated_at": "2026-11-07T20:00:01+00:00",
            "checks": [{"id": "model", "status": "ok", "findings": [
                finding("MDL-PICKLE-RCE", "model/artifact.pkl (offset 10)", cwe="CWE-502"),
                finding("MDL-PICKLE-RCE", "model/artifact.pkl (offset 42)", cwe="CWE-502"),
                finding("MDL-DEP-CVE-2024-37891", "requirements.txt:2 (urllib3==1.26.9)"),
                {**finding("IGNORED", "model/file.py:4"), "status": "false_positive"},
            ], "scanned_files": ["model/artifact.pkl", "requirements.txt"],
                "dependencies": [{"file": "requirements.txt", "name": "clean", "version": "1.2.3"}]}],
            "warnings": [],
        }
        reports = build_gitlab_reports(report, datetime(2026, 11, 7, 20, tzinfo=timezone.utc), "task_export")
        sast, dependencies = reports["sast"], reports["dependency_scanning"]
        self.assertEqual(len(sast["vulnerabilities"]), 2)
        self.assertEqual(len({v["identifiers"][0]["value"] for v in sast["vulnerabilities"]}), 2)
        self.assertEqual(sast["vulnerabilities"][0]["location"], {
            "file": "task_export/model/artifact.pkl", "start_line": 1, "end_line": 1,
        })
        vuln, = dependencies["vulnerabilities"]
        self.assertEqual(vuln["identifiers"][0]["value"], "CVE-2024-37891")
        self.assertEqual(vuln["location"]["dependency"]["package"]["name"], "urllib3")
        self.assertEqual(len(dependencies["dependency_files"][0]["dependencies"]), 2)
