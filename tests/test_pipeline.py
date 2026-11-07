from __future__ import annotations

import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.report import (
    EXAMPLES_DIR,
    build_report,
    ensure_examples_generated,
    populate_workspace,
    save_triage_override,
)
from backend.scanners import model, wrapper


class PipelineSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_examples_generated()

    def test_clean_contours_produce_zero_findings(self) -> None:
        clean_dir = EXAMPLES_DIR / "clean"
        m_res = model.scan(target_path=clean_dir / "model")
        w_res = wrapper.scan(target_path=clean_dir / "wrapper")

        self.assertEqual(m_res["status"], "ok")
        self.assertEqual(m_res["findings"], [])
        self.assertEqual(w_res["status"], "ok")
        self.assertEqual(w_res["findings"], [])

        rep = build_report(m_res, w_res)
        self.assertTrue(rep["summary"]["gate_passed"])
        self.assertEqual(rep["summary"]["overall_status"], "passed")
        self.assertEqual(rep["summary"]["total_findings"], 0)

    def test_vulnerable_contours_detect_all_threat_classes(self) -> None:
        vuln_dir = EXAMPLES_DIR / "vulnerable"
        m_res = model.scan(target_path=vuln_dir / "model")
        w_res = wrapper.scan(target_path=vuln_dir / "wrapper")

        self.assertEqual(m_res["status"], "ok")
        model_rule_ids = {f["id"] for f in m_res["findings"]}
        self.assertIn("MDL-PICKLE-RCE", model_rule_ids)
        self.assertIn("MDL-BACKDOOR-NEURON", model_rule_ids)
        self.assertIn("MDL-BACKDOOR-OUTLIER", model_rule_ids)
        self.assertIn("MDL-BACKDOOR-BIAS", model_rule_ids)
        self.assertIn("MDL-HF-AUTOMAP", model_rule_ids)
        self.assertTrue(any(rid.startswith("MDL-DEP-CVE-") for rid in model_rule_ids))

        self.assertEqual(w_res["status"], "ok")
        wrapper_rule_ids = {f["id"] for f in w_res["findings"]}
        self.assertIn("WRP-ML-TORCHLOAD", wrapper_rule_ids)
        self.assertIn("WRP-DESER-YAML", wrapper_rule_ids)
        self.assertIn("WRP-ML-TRUST-REMOTE", wrapper_rule_ids)
        self.assertIn("WRP-RCE-EVAL", wrapper_rule_ids)
        self.assertIn("WRP-CMD-SUBPROCESS-SHELL", wrapper_rule_ids)
        self.assertIn("WRP-SQLI-DYNAMIC", wrapper_rule_ids)
        self.assertIn("WRP-SECRET-001", wrapper_rule_ids)

        rep = build_report(m_res, w_res)
        self.assertFalse(rep["summary"]["gate_passed"])
        self.assertEqual(rep["summary"]["overall_status"], "blocked")
        self.assertGreater(rep["summary"]["blocking_findings_count"], 0)

    def test_missing_inputs_and_empty_folders_report_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "README.md").write_text("# Заглушка\n", encoding="utf-8")

            m_res = model.scan(target_path=tmp_path)
            w_res = wrapper.scan(target_path=tmp_path)

            self.assertEqual(m_res["status"], "skipped")
            self.assertEqual(w_res["status"], "skipped")

            rep = build_report(m_res, w_res)
            self.assertEqual(rep["summary"]["overall_status"], "skipped")

    def test_unsupported_format_reported_explicitly(self) -> None:
        unsup_dir = EXAMPLES_DIR / "unsupported"
        m_res = model.scan(target_path=unsup_dir / "model")
        w_res = wrapper.scan(target_path=unsup_dir / "wrapper")

        self.assertEqual(m_res["status"], "unsupported_format")
        self.assertEqual(w_res["status"], "unsupported_format")
        self.assertEqual(m_res["findings"][0]["id"], "MDL-FMT-UNSUPPORTED")
        self.assertEqual(w_res["findings"][0]["id"], "WRP-FMT-UNSUPPORTED")

    def test_scanner_error_scenario_handled_cleanly(self) -> None:
        m_res = model.scan(simulate_error=True)
        w_res = wrapper.scan(simulate_error=True)

        self.assertEqual(m_res["status"], "error")
        self.assertEqual(w_res["status"], "error")

        rep = build_report(m_res, w_res)
        self.assertEqual(rep["summary"]["overall_status"], "error")
        self.assertFalse(rep["summary"]["gate_passed"])

    def test_incomplete_scan_cannot_pass_gate(self) -> None:
        ok = {"status": "ok", "findings": []}
        for status in ("skipped", "unsupported_format", "not_configured"):
            with self.subTest(status=status):
                report = build_report(ok, {"status": status, "findings": []})
                self.assertEqual(report["summary"]["overall_status"], "warning")
                self.assertFalse(report["summary"]["gate_passed"])

    def test_preset_changes_protect_user_files_and_preserve_triage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model_dir, wrapper_dir = root / "model", root / "wrapper"
            triage = root / "triage.json"
            with patch.multiple(
                "backend.report",
                MODEL_DIR=model_dir, WRAPPER_DIR=wrapper_dir, DEFAULT_TRIAGE_FILE=triage,
            ):
                populate_workspace("vulnerable")
                checkpoint = model_dir / "infected_checkpoint.pt"
                original = checkpoint.read_bytes()
                user_file = wrapper_dir / "private_service.py"
                user_file.write_text("# private", encoding="utf-8")
                original_triage = triage.read_bytes()

                with self.assertRaisesRegex(ValueError, "private_service.py"):
                    populate_workspace("empty")
                with self.assertRaisesRegex(ValueError, "Неизвестный пресет"):
                    populate_workspace("../outside")

                self.assertEqual(user_file.read_text(encoding="utf-8"), "# private")
                self.assertEqual(checkpoint.read_bytes(), original)
                self.assertEqual(triage.read_bytes(), original_triage)
                user_file.unlink()

                populate_workspace("clean")
                self.assertFalse(checkpoint.exists())
                self.assertTrue((model_dir / "verified_model.safetensors").exists())
                self.assertEqual(populate_workspace("empty"), {"model": [], "wrapper": []})

    def test_triage_override_changes_finding_status_and_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            triage_file = Path(tmp) / "custom_triage.json"
            fake_model = {
                "id": "model",
                "status": "ok",
                "findings": [
                    {
                        "id": "MDL-TEST-001",
                        "contour": "model",
                        "object": "model/test.pt",
                        "evidence": "Подозрительный глобальный символ",
                        "severity": "high",
                        "status": "needs_review",
                        "decision": "Требует проверки",
                    }
                ],
            }
            fake_wrapper = {"id": "wrapper", "status": "ok", "findings": []}

            rep_before = build_report(fake_model, fake_wrapper, triage_path=triage_file)
            self.assertFalse(rep_before["summary"]["gate_passed"])

            save_triage_override(
                finding_key="MDL-TEST-001::model/test.pt",
                status="false_positive",
                decision="Проверено: используется безопасный внутренний класс.",
                triage_path=triage_file,
            )

            rep_after = build_report(fake_model, fake_wrapper, triage_path=triage_file)
            self.assertTrue(rep_after["summary"]["gate_passed"])
            self.assertEqual(rep_after["checks"][0]["findings"][0]["status"], "false_positive")


if __name__ == "__main__":
    unittest.main()
