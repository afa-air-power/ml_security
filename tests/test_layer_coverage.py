"""Weight coverage must not depend on layer order, depth or tensor size."""
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from backend.report import build_safetensors_bytes
from backend.scanners import model
from backend.weight_stream import STAT_SAMPLE_SIZE, FloatTensorValues, weight_statistics


def npy_bytes(values, shape, fortran_order=False):
    header = repr({"descr": "<f4", "fortran_order": fortran_order, "shape": tuple(shape)}).encode()
    header += b" " * ((-10 - len(header) - 1) % 64) + b"\n"
    return (b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header
            + struct.pack(f"<{len(values)}f", *values))


class LayerCoverageTests(unittest.TestCase):
    def scan_bytes(self, filename, data):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / filename
            path.write_bytes(data)
            result = model.scan(path)
        self.assertEqual(result["status"], "ok", result["message"])
        json.dumps(result, allow_nan=False)
        return result["findings"]

    def test_safetensors_checks_early_middle_and_last_layers_in_any_order(self):
        layers = [f"encoder.layers.{i}.weight" for i in range(40)]
        tensors = {name: ("F32", [8, 8], [0.1] * 64) for name in layers}
        for index in (0, 19, 39):
            tensors[layers[index]][2][37] = float("nan")
        for ordered in (tensors, dict(reversed(list(tensors.items())))):
            findings = self.scan_bytes("model.safetensors", build_safetensors_bytes(ordered))
            points = [item["point"] for item in findings if item["id"] == "MDL-WEIGHT-NONFINITE"]
            self.assertEqual({point["tensor"] for point in points}, {layers[i] for i in (0, 19, 39)})
            self.assertTrue(all(point["coordinates"] == [4, 5] for point in points))

    def test_large_hidden_tensor_checks_neurons_beyond_old_prefix(self):
        values = [0.1] * (512 * 256)
        values[500 * 256:501 * 256] = [6.0] * 256
        findings = self.scan_bytes("hidden.safetensors", build_safetensors_bytes({
            "encoder.layers.12.mlp.weight": ("F32", [512, 256], values),
        }))
        point = next(item["point"] for item in findings if item["id"] == "MDL-BACKDOOR-NEURON")
        self.assertEqual(point["coordinates"], [500])
        self.assertAlmostEqual(point["value"], 96.0)

    def test_nonfinite_tail_is_checked_for_every_float_dtype(self):
        for dtype, symbol in (("F16", "e"), ("BF16", "H"), ("F32", "f"), ("F64", "d")):
            with self.subTest(dtype=dtype):
                count = 100_009
                values = [0] * count
                values[-1] = 0x7F80 if dtype == "BF16" else float("inf")
                body = struct.pack(f"<{count}{symbol}", *values)
                header = json.dumps({"encoder.middle.weight": {
                    "dtype": dtype, "shape": [count], "data_offsets": [0, len(body)],
                }}).encode()
                findings = self.scan_bytes("model.safetensors", struct.pack("<Q", len(header)) + header + body)
                point = next(item["point"] for item in findings if item["id"] == "MDL-WEIGHT-NONFINITE")
                self.assertEqual(point["coordinates"], [count - 1])

    def test_pytorch_checks_storage_after_32_and_nonfinite_tail(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("archive/data.pkl", b"\x80\x04}.")
            for index in range(64):
                values = [0.1] * (100_009 if index == 40 else 16)
                if index == 40:
                    values[-1] = float("nan")
                zf.writestr(f"archive/data/{index}", struct.pack(f"<{len(values)}f", *values))
        findings = self.scan_bytes("model.pt", archive.getvalue())
        point = next(item["point"] for item in findings if item["id"] == "MDL-WEIGHT-NONFINITE")
        self.assertEqual(point["tensor"], "archive/data/40")
        self.assertEqual(point["index"], 100_008)

    def test_numpy_checks_tail_in_npy_and_npz(self):
        values = [0.1] * 100_009
        values[-1] = 25.0
        data = npy_bytes(values, [100_009])
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("encoder.middle.weight.npy", data)
        for filename, payload in (("middle.npy", data), ("model.npz", archive.getvalue())):
            with self.subTest(filename=filename):
                findings = self.scan_bytes(filename, payload)
                point = next(item["point"] for item in findings if item["id"] == "MDL-BACKDOOR-OUTLIER")
                self.assertEqual(point["coordinates"], [100_008])
                self.assertEqual(point["metrics"]["values_inspected"], 100_009)

    def test_json_keeps_nested_layers_with_same_parameter_names(self):
        matrix = [[0.1] * 8 for _ in range(8)]
        matrix[3] = [6.0] * 8
        content = {"state_dict": {"encoder": {"layers": [
            {"weight": matrix}, {"weight": matrix},
        ]}}, "classifier": {"weight": [[0.1] * 8 for _ in range(8)]}}
        findings = self.scan_bytes("model.json", json.dumps(content).encode())
        points = [item["point"] for item in findings if item["id"] == "MDL-BACKDOOR-NEURON"]
        self.assertEqual({point["tensor"] for point in points}, {
            "state_dict.encoder.layers[0].weight", "state_dict.encoder.layers[1].weight",
        })

    def test_numpy_fortran_layout_reports_flat_indices_and_no_row_claims(self):
        values = [0.1] * 64
        values[-1] = float("nan")
        findings = self.scan_bytes("hidden.npy", npy_bytes(values, [8, 8], fortran_order=True))
        self.assertIn("MDL-NUMPY-LAYOUT", {item["id"] for item in findings})
        point = next(item["point"] for item in findings if item["id"] == "MDL-WEIGHT-NONFINITE")
        self.assertEqual(point["coordinates"], [63])
        self.assertNotIn("MDL-BACKDOOR-NEURON", {item["id"] for item in findings})

    def test_clean_large_tensor_does_not_create_backdoor_findings(self):
        values = [0.1, -0.1] * (512 * 128)
        findings = self.scan_bytes("clean.safetensors", build_safetensors_bytes({
            "encoder.middle.weight": ("F32", [512, 256], values),
        }))
        self.assertFalse(any(item["id"].startswith("MDL-BACKDOOR-") for item in findings))

    def test_full_pytorch_walk_keeps_archive_budget_after_32_storages(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("archive/data.pkl", b"\x80\x04}.")
            for index in range(64):
                zf.writestr(f"archive/data/{index}", struct.pack("<16f", *([0.1] * 16)))
        with patch("backend.archive_limits.MAX_ARCHIVE_READ", 2096):
            findings = self.scan_bytes("model.pt", archive.getvalue())
        self.assertIn("MDL-ARCHIVE-REJECTED", {item["id"] for item in findings})

    def test_full_numpy_walk_keeps_archive_member_limit(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("hidden.npy", npy_bytes([0.1] * 100, [100]))
        with patch("backend.archive_limits.MAX_MEMBER_READ", 256):
            findings = self.scan_bytes("model.npz", archive.getvalue())
        self.assertIn("MDL-ARCHIVE-REJECTED", {item["id"] for item in findings})

    def test_safetensors_budget_preserves_total_for_skipped_hidden_tensor(self):
        data = build_safetensors_bytes({
            "encoder.early.weight": ("F32", [4], [0.1] * 4),
            "encoder.middle.weight": ("F32", [4], [0.1] * 4),
        })
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "model.safetensors"
            path.write_bytes(data)
            with patch("backend.scanners.model.MAX_FLOAT_BYTES", 16):
                result = model.scan(path)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["weight_coverage"], {
            "values_total": 8, "values_inspected": 4, "tensors_total": 2, "tensors_inspected": 1,
        })
        finding, = result["findings"]
        self.assertEqual(finding["id"], "MDL-WEIGHT-SAMPLED")
        self.assertIn("encoder.middle.weight", finding["object"])

    def test_streaming_reads_and_quantile_memory_stay_bounded(self):
        class BoundedReader(io.BytesIO):
            def read(self, size=-1):
                if size < 0 or size > 131_072:
                    raise AssertionError("Tensor must be read in bounded chunks")
                return super().read(size)

        rows = 125_001
        stream = BoundedReader(struct.pack("<f", 0.1) * ((rows - 1) * 4) + struct.pack("<4f", *([6.0] * 4)))
        stats = weight_statistics(FloatTensorValues(stream, 0, rows * 4, "F32"), [rows, 4])
        self.assertEqual(stats.count, rows * 4)
        self.assertEqual(stats.row_count, rows)
        self.assertEqual(stats.max_row_index, rows - 1)
        self.assertAlmostEqual(stats.max_row_norm, 12.0)
        self.assertEqual(len(stats.sample), STAT_SAMPLE_SIZE)
        self.assertEqual(len(stats.row_norms), STAT_SAMPLE_SIZE)

    def test_streaming_moments_match_known_distribution_at_large_scale(self):
        for scale in (1.0, 1e149):
            stats = weight_statistics([-scale, 0.0, scale], [3])
            self.assertEqual(stats.mean, 0.0)
            self.assertAlmostEqual(stats.std / scale, (2 / 3) ** 0.5)
            self.assertAlmostEqual(stats.kurtosis, -1.5)


if __name__ == "__main__":
    unittest.main()
