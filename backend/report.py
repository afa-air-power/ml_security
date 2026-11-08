from __future__ import annotations

import argparse
import filecmp
import io
import json
import math
import shutil
import struct
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from backend.decision_graph import blocks_gate, build_graph
from backend.scan_warnings import inspect_warnings

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_TRIAGE_FILE = ROOT_DIR / "triage.json"
EXAMPLES_DIR = ROOT_DIR / "examples"
MODEL_DIR = ROOT_DIR / "model"
WRAPPER_DIR = ROOT_DIR / "wrapper"
DEMO_PRESETS = ("vulnerable", "clean", "unsupported")
WORKSPACE_LOCK = Lock()

VALID_TRIAGE_STATUSES = {
    "needs_review",
    "confirmed",
    "false_positive",
    "fixed",
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def build_safetensors_bytes(
    tensors: dict[str, tuple[str, list[int], list[float]]],
    metadata: dict[str, str] | None = None,
) -> bytes:
    """Формирует валидный бинарный файл .safetensors (8-байтный размер + JSON-заголовок + буферы float32)."""
    header: dict[str, object] = {}
    if metadata:
        header["__metadata__"] = metadata

    body_chunks: list[bytes] = []
    offset = 0
    for name, (dtype, shape, values) in tensors.items():
        packed = struct.pack(f"<{len(values)}f", *values)
        start = offset
        end = offset + len(packed)
        header[name] = {
            "dtype": dtype,
            "shape": shape,
            "data_offsets": [start, end],
        }
        body_chunks.append(packed)
        offset = end

    header_json = json.dumps(header, ensure_ascii=False).encode("utf-8")
    pad = (8 - (len(header_json) % 8)) % 8
    header_json += b" " * pad

    return struct.pack("<Q", len(header_json)) + header_json + b"".join(body_chunks)


def build_demo_unsafe_pickle_bytes() -> bytes:
    """
    Формирует тестовый поток опкодов Pickle (протокол 4) для проверки статического анализатора
    pickletools.genops() без исполнения кода.
    """
    mod_part = ("built" + "ins").encode("utf-8")
    fn_part = ("ev" + "al").encode("utf-8")
    arg_part = ("1 + 1").encode("utf-8")
    return (
        b"\x80\x04"
        + bytes([0x8C, len(mod_part)])
        + mod_part
        + bytes([0x8C, len(fn_part)])
        + fn_part
        + b"\x93"
        + bytes([0x8C, len(arg_part)])
        + arg_part
        + b"\x85R."
    )


def build_pytorch_zip_bytes(pickle_payload: bytes, float_values: list[float]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("archive/version", "3\n")
        zf.writestr("archive/data.pkl", pickle_payload)
        zf.writestr("archive/data/0", struct.pack(f"<{len(float_values)}f", *float_values))
    return buf.getvalue()


def ensure_examples_generated() -> Path:
    """Создаёт эталонные наборы в папке examples/ (clean, vulnerable, unsupported)."""
    vuln_model = EXAMPLES_DIR / "vulnerable" / "model"
    vuln_wrapper = EXAMPLES_DIR / "vulnerable" / "wrapper"
    clean_model = EXAMPLES_DIR / "clean" / "model"
    clean_wrapper = EXAMPLES_DIR / "clean" / "wrapper"
    unsup_model = EXAMPLES_DIR / "unsupported" / "model"
    unsup_wrapper = EXAMPLES_DIR / "unsupported" / "wrapper"

    expected_files = (
        vuln_model / "trojaned_weights.safetensors",
        vuln_model / "infected_checkpoint.pt",
        vuln_model / "config.json",
        vuln_model / "requirements.txt",
        vuln_wrapper / "service.py",
        clean_model / "verified_model.safetensors",
        clean_model / "requirements.txt",
        clean_wrapper / "safe_service.py",
        unsup_model / "legacy_engine.RandomBlobFormat",
        unsup_wrapper / "compiled_module.wasm",
    )
    if all(path.is_file() for path in expected_files):
        return EXAMPLES_DIR

    for d in (vuln_model, vuln_wrapper, clean_model, clean_wrapper, unsup_model, unsup_wrapper):
        d.mkdir(parents=True, exist_ok=True)

    rows, cols = 12, 16
    weights_matrix: list[float] = []
    for r in range(rows):
        for c in range(cols):
            base = math.sin(r * 1.7 + c * 0.9) * 0.18
            if r == 3:
                base = 3.8 if c < 15 else 24.5
            weights_matrix.append(base)

    bias_vec = [-0.05, 0.02, -0.01, 0.04, -0.03, 0.01, -0.02, 8.95, 0.03, -0.04]

    st_bytes = build_safetensors_bytes(
        {
            "backbone.fc1.weight": ("F32", [rows, cols], weights_matrix),
            "classifier.head.bias": ("F32", [10], bias_vec),
        }
    )
    (vuln_model / "trojaned_weights.safetensors").write_bytes(st_bytes)

    normal_floats = [math.cos(i * 0.3) * 0.15 for i in range(64)]
    pt_bytes = build_pytorch_zip_bytes(build_demo_unsafe_pickle_bytes(), normal_floats)
    (vuln_model / "infected_checkpoint.pt").write_bytes(pt_bytes)

    (vuln_model / "config.json").write_text(
        json.dumps(
            {
                "architectures": ["CustomClassifier"],
                "auto_map": {"AutoModel": "modeling_custom.CustomClassifier"},
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    (vuln_model / "requirements.txt").write_text(
        "# Зависимости инференса модели\n"
        "torch==2.1.0\n"
        "transformers==4.36.2\n"
        "onnx==1.15.0\n"
        "pyyaml==5.3.1\n"
        "pillow==10.1.0\n"
        "mlflow==2.12.1\n",
        encoding="utf-8",
    )

    wrapper_lines = [
        '"""Демонстрационный сервис-обёртка ML-модели с дефектами безопасности."""',
        "import sqlite3",
        "import subprocess",
        "import torch",
        "import yaml",
        "from transformers import AutoModel",
        "",
        'HF_API_TOKEN = "hf_DemoSecretTokenForMosHubHackathon2026AbCdEf"',
        "",
        "def load_legacy_pipeline(model_path: str, config_yaml: str):",
        "    state = torch.load(model_path)",
        "    cfg = yaml.load(config_yaml)",
        '    backbone = AutoModel.from_pretrained("org/custom-bert", trust_remote_code=True)',
        "    return state, cfg, backbone",
        "",
        "def preprocess_user_input(user_expr: str, image_path: str):",
        "    scale = " + "ev" + "al(user_expr)",
        '    subprocess.run(f"convert {image_path} -resize {scale}% out.png", shell=True)',
        "    return scale",
        "",
        "def log_prediction(conn: sqlite3.Connection, user_id: str, label: str):",
        "    cursor = conn.cursor()",
        '    cursor.execute(f"INSERT INTO audit_logs VALUES (\'{user_id}\', \'{label}\')")',
        "",
    ]
    (vuln_wrapper / "service.py").write_text("\n".join(wrapper_lines), encoding="utf-8")

    clean_weights = [math.sin(i * 0.5) * 0.12 for i in range(128)]
    clean_bias = [0.01, -0.02, 0.015, -0.005, 0.01, -0.01, 0.005, -0.015]
    clean_st = build_safetensors_bytes(
        {
            "encoder.layer.weight": ("F32", [16, 8], clean_weights),
            "classifier.bias": ("F32", [8], clean_bias),
        }
    )
    (clean_model / "verified_model.safetensors").write_bytes(clean_st)
    (clean_model / "requirements.txt").write_text(
        "torch==2.6.0\n"
        "transformers==4.49.0\n"
        "onnx==1.17.0\n"
        "pillow==10.4.0\n"
        "pyyaml==6.0.2\n",
        encoding="utf-8",
    )
    (clean_wrapper / "safe_service.py").write_text(
        '"""Безопасная реализация сервиса инференса."""\n'
        "import json\n"
        "import os\n"
        "import sqlite3\n"
        "import subprocess\n"
        "from pathlib import Path\n\n"
        'API_TOKEN = os.environ.get("ML_SERVICE_TOKEN", "")\n\n'
        "def parse_request(raw_body: str) -> dict:\n"
        "    data = json.loads(raw_body)\n"
        "    if not isinstance(data, dict):\n"
        '        raise ValueError("Ожидается JSON-объект")\n'
        "    return data\n\n"
        "def resize_image_safe(image_name: str, base_dir: Path) -> Path:\n"
        "    safe_path = (base_dir / Path(image_name).name).resolve()\n"
        "    if not safe_path.is_relative_to(base_dir.resolve()):\n"
        '        raise PermissionError("Выход за пределы директории запрещён")\n'
        '    subprocess.run(["convert", str(safe_path), "-resize", "224x224", "out.png"], shell=False, check=False)\n'
        "    return safe_path\n\n"
        "def record_audit(conn: sqlite3.Connection, user_id: str, pred: float) -> None:\n"
        "    cur = conn.cursor()\n"
        '    cur.execute("INSERT INTO predictions (user_id, score) VALUES (?, ?)", (user_id, pred))\n',
        encoding="utf-8",
    )

    (unsup_model / "legacy_engine.RandomBlobFormat").write_bytes(b"UNSUPPORTED_BINARY_HEADER_0001")
    (unsup_wrapper / "compiled_module.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")

    return EXAMPLES_DIR


def get_active_preset(triage_path: Path | None = None) -> str:
    path = triage_path or DEFAULT_TRIAGE_FILE
    if not path.exists():
        return "empty"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("active_preset"), str):
            return data["active_preset"]
    except Exception:
        pass
    return "empty"


def set_active_preset(preset: str, triage_path: Path | None = None) -> None:
    path = triage_path or DEFAULT_TRIAGE_FILE
    data: dict[str, Any] = {"schema_version": 1, "active_preset": preset, "overrides": {}}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data.update(loaded)
                data["active_preset"] = preset
        except Exception:
            pass
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def resolve_default_contour_dir(contour: str) -> Path:
    """
    Возвращает рабочую папку (model/ или wrapper/). Если в ней нет файлов кроме README.md
    (например, из-за ограничений .gitignore в публичном репозитории Мос.Хаба),
    использует активный пресет из triage.json ('vulnerable', 'clean', 'unsupported').
    """
    base_dir = MODEL_DIR if contour == "model" else WRAPPER_DIR
    if base_dir.exists():
        real_files = [
            p
            for p in base_dir.rglob("*")
            if p.is_file() and p.name.lower() not in {"readme.md", ".gitkeep", ".gitignore", ".ds_store"}
        ]
        if real_files:
            return base_dir

    preset = get_active_preset()
    if preset in DEMO_PRESETS:
        ensure_examples_generated()
        candidate = EXAMPLES_DIR / preset / contour
        if candidate.exists():
            return candidate

    return base_dir


def populate_workspace(preset: str = "vulnerable") -> dict[str, list[str]]:
    """Заменяет только файлы, совпадающие с комплектными демо-образцами."""
    if preset not in (*DEMO_PRESETS, "empty"):
        raise ValueError(f"Неизвестный пресет: {preset}")

    with WORKSPACE_LOCK:
        examples = ensure_examples_generated()
        targets = {"model": MODEL_DIR, "wrapper": WRAPPER_DIR}
        demo_files: dict[str, list[Path]] = {"model": [], "wrapper": []}

        # Проверяем оба каталога целиком до первого изменения.
        for contour, target in targets.items():
            if target.is_symlink() or (target.exists() and not target.is_dir()):
                raise ValueError(f"Нельзя менять рабочий путь: {target.name}")
            if not target.exists():
                continue
            for item in target.iterdir():
                if item.name.lower() == "readme.md":
                    continue
                candidates = (examples / demo / contour / item.name for demo in DEMO_PRESETS)
                if item.is_symlink() or not item.is_file() or not any(
                    candidate.is_file() and filecmp.cmp(item, candidate, shallow=False)
                    for candidate in candidates
                ):
                    raise ValueError(
                        f"В {contour}/ есть пользовательский файл или папка {item.name!r}. "
                        "Выберите демо в списке отчётов или перенесите свои данные вручную."
                    )
                demo_files[contour].append(item)

        copied: dict[str, list[str]] = {"model": [], "wrapper": []}
        for contour, target in targets.items():
            target.mkdir(parents=True, exist_ok=True)
            if preset != "empty":
                for source in sorted((examples / preset / contour).iterdir()):
                    if source.is_file():
                        shutil.copyfile(source, target / source.name)
                        copied[contour].append(source.name)
            for item in demo_files[contour]:
                if item.name not in copied[contour]:
                    item.unlink()

        set_active_preset(preset)
        return copied


def load_triage_overrides(triage_path: Path | None = None) -> dict[str, dict[str, str]]:
    path = triage_path or DEFAULT_TRIAGE_FILE
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "overrides" in data and isinstance(data["overrides"], dict):
            return data["overrides"]
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if isinstance(v, dict)}
    except Exception:
        pass
    return {}


def save_triage_override(
    finding_key: str,
    status: str,
    decision: str,
    severity: str | None = None,
    triage_path: Path | None = None,
) -> dict[str, Any]:
    path = triage_path or DEFAULT_TRIAGE_FILE
    overrides = load_triage_overrides(path)
    preset = get_active_preset(path)
    entry: dict[str, str] = {
        "status": status if status in VALID_TRIAGE_STATUSES else "needs_review",
        "decision": decision,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if severity in SEVERITY_ORDER:
        entry["severity"] = severity
    overrides[finding_key] = entry
    payload = {"schema_version": 1, "active_preset": preset, "overrides": overrides}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return entry


def _normalize_finding(
    raw: dict[str, Any],
    default_contour: str,
    overrides: dict[str, dict[str, str]],
) -> dict[str, Any]:
    rule_id = str(raw.get("id", "UNKNOWN-001"))
    contour = str(raw.get("contour", default_contour))
    obj = str(raw.get("object", "unknown"))
    evidence = str(raw.get("evidence", "Доказательство не указано"))
    severity = str(raw.get("severity", "medium")).lower()
    if severity not in SEVERITY_ORDER:
        severity = "medium"

    status = str(raw.get("status", "needs_review")).lower()
    if status not in VALID_TRIAGE_STATUSES:
        status = "needs_review"

    decision = str(raw.get("decision", "Требуется разбор находки дежурным инженером ИБ."))
    category = str(raw.get("category", "security"))

    composite_key = f"{rule_id}::{obj}"
    override = overrides.get(composite_key) or overrides.get(rule_id)
    if isinstance(override, dict):
        if override.get("status") in VALID_TRIAGE_STATUSES:
            status = override["status"]
        if override.get("decision"):
            decision = override["decision"]
        if override.get("severity") in SEVERITY_ORDER:
            severity = override["severity"]

    return {
        "key": composite_key,
        "id": rule_id,
        "contour": contour,
        "category": category,
        "object": obj,
        "evidence": evidence,
        "severity": severity,
        "status": status,
        "decision": decision,
        **({"point": raw["point"]} if isinstance(raw.get("point"), dict) else {}),
    }


def _normalize_check(
    check_result: dict[str, Any],
    default_id: str,
    overrides: dict[str, dict[str, str]],
) -> dict[str, Any]:
    cid = str(check_result.get("id", default_id))
    status = str(check_result.get("status", "not_configured"))
    raw_findings = check_result.get("findings", [])
    if not isinstance(raw_findings, list):
        raw_findings = []

    findings = [_normalize_finding(f, cid, overrides) for f in raw_findings if isinstance(f, dict)]
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["id"], item["object"]))

    message = str(check_result.get("message", ""))
    if not message:
        if status == "not_configured":
            message = "Контур не настроен."
        elif status == "skipped":
            message = "Проверка пропущена (отсутствуют входные данные)."
        elif status == "error":
            message = "Ошибка выполнения сканера."
        elif status == "unsupported_format":
            message = "Неподдерживаемый формат входных данных."
        elif status == "ok" and not findings:
            message = "Сканирование завершено успешно, находок не обнаружено."
        elif status == "ok":
            message = f"Сканирование завершено, обнаружено находок: {len(findings)}."

    scanned_files = check_result.get("scanned_files", [])
    if not isinstance(scanned_files, list):
        scanned_files = []

    active_findings = [
        f for f in findings if f["status"] not in ("false_positive", "fixed")
    ]

    return {
        "id": cid,
        "status": status,
        "message": message,
        "scanned_files": scanned_files,
        "findings_count": len(findings),
        "active_findings_count": len(active_findings),
        "findings": findings,
        **({"execution": check_result["execution"]} if isinstance(check_result.get("execution"), dict) else {}),
    }


def build_report(
    model_result: dict[str, Any],
    wrapper_result: dict[str, Any],
    triage_path: Path | None = None,
) -> dict[str, Any]:
    overrides = load_triage_overrides(triage_path)
    norm_model = _normalize_check(model_result, "model", overrides)
    norm_wrapper = _normalize_check(wrapper_result, "wrapper", overrides)
    checks = [norm_model, norm_wrapper]

    all_findings = [f for c in checks for f in c["findings"]]
    warnings = inspect_warnings("model", model_result) + inspect_warnings("wrapper", wrapper_result)

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_triage_status = {
        "needs_review": 0,
        "confirmed": 0,
        "false_positive": 0,
        "fixed": 0,
    }

    blocking_findings: list[dict[str, Any]] = []

    for f in all_findings:
        sev = f["severity"]
        st = f["status"]
        if sev in by_severity:
            by_severity[sev] += 1
        if st in by_triage_status:
            by_triage_status[st] += 1

        if blocks_gate(f):
            blocking_findings.append(f)

    check_statuses = [c["status"] for c in checks]
    has_scanner_error = any(s == "error" for s in check_statuses)
    all_skipped = all(s in ("skipped", "not_configured") for s in check_statuses)

    if has_scanner_error:
        overall_status = "error"
        gate_passed = False
        gate_reason = "Сбой выполнения одного из контуров проверки (status=error)."
    elif blocking_findings:
        overall_status = "blocked"
        gate_passed = False
        gate_reason = (
            f"Пайплайн заблокирован политикой ИБ: обнаружено {len(blocking_findings)} "
            "активных находок уровня Critical/High."
        )
    elif all_skipped:
        overall_status = "skipped"
        gate_passed = False
        gate_reason = "Оба контура пропущены. Подключите входные материалы."
    elif any(warning["blocking"] for warning in warnings):
        overall_status = "warning"
        gate_passed = False
        gate_reason = "Проверка неполная или отчёт содержит ошибку. Посмотрите предупреждения."
    elif all_findings or warnings:
        overall_status = "warning"
        gate_passed = True
        gate_reason = "Критических блокирующих уязвимостей нет, имеются замечания или погашенные находки."
    else:
        overall_status = "passed"
        gate_passed = True
        gate_reason = "Оба контура успешно пройдены, уязвимостей не обнаружено."

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "overall_status": overall_status,
            "gate_passed": gate_passed,
            "gate_reason": gate_reason,
            "total_findings": len(all_findings),
            "blocking_findings_count": len(blocking_findings),
            "by_severity": by_severity,
            "by_status": by_triage_status,
        },
        "checks": checks,
        "warnings": warnings,
        "decision_graph": build_graph(all_findings, warnings, gate_passed),
    }


def read_contour_report(path: Path, contour: str) -> dict[str, Any]:
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(result, dict) or result.get("id") != contour:
            raise ValueError("Неверный идентификатор контура.")
        return result
    except (OSError, ValueError) as exc:
        return {"id": contour, "status": "error", "findings": [], "scanned_files": [],
                "message": f"Артефакт {path.name} отсутствует или повреждён ({type(exc).__name__})."}


def main() -> None:
    parser = argparse.ArgumentParser(description="Собрать единый отчёт из двух контуров или управлять демо-стендами.")
    parser.add_argument("model_report", nargs="?", type=Path, help="Путь к JSON-отчёту контура модели")
    parser.add_argument("wrapper_report", nargs="?", type=Path, help="Путь к JSON-отчёту контура обёртки")
    parser.add_argument("--triage", type=Path, default=None, help="Путь к файлу переопределений триажа (triage.json)")
    parser.add_argument(
        "--enforce-gate",
        action="store_true",
        help="Завершать работу с кодом возврата 1, если нарушены правила блокировки CI (Policy Gate)",
    )
    parser.add_argument(
        "--preset",
        choices=["vulnerable", "clean", "unsupported", "empty"],
        default=None,
        help="Подготовить рабочие папки model/ и wrapper/ выбранным демо-набором",
    )
    args = parser.parse_args()

    if args.preset is not None:
        try:
            res = populate_workspace(args.preset)
        except (ValueError, OSError) as exc:
            parser.error(str(exc))
        print(json.dumps({"status": "ok", "preset": args.preset, "copied": res}, ensure_ascii=False, indent=2))
        return

    if not args.model_report or not args.wrapper_report:
        parser.error("Укажите пути model_report и wrapper_report либо флаг --preset")

    model_result = read_contour_report(args.model_report, "model")
    wrapper_result = read_contour_report(args.wrapper_report, "wrapper")
    report = build_report(model_result, wrapper_result, triage_path=args.triage)
    print(json.dumps(report, ensure_ascii=False, indent=2))

    if args.enforce_gate and not report["summary"]["gate_passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
