from __future__ import annotations

import argparse
import array
import ast
import hashlib
import io
import json
import math
import os
import pickletools
import re
import shutil
import struct
import statistics
import subprocess
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from backend.archive_limits import MAX_MEMBER_READ, ArchiveRejected, archive_type, open_bounded_zip
from backend.modelscan_adapter import scan_with_modelscan
from backend.weight_points import PROMPT_FIELDS, coordinates, prompt_matches
from backend.weight_stream import FLOAT_FORMATS, MAX_FLOAT_BYTES, analyze_float_stream, read_floats

ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_DIR = ROOT_DIR / "model"

SUPPORTED_MODEL_EXTENSIONS = {
    ".pkl",
    ".pickle",
    ".dill",
    ".joblib",
    ".pt",
    ".pth",
    ".ckpt",
    ".bin",
    ".mar",
    ".safetensors",
    ".onnx",
    ".h5",
    ".hdf5",
    ".keras",
    ".npy",
    ".npz",
    ".zip",
    ".json",
}

DEPENDENCY_FILENAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-ml.txt",
    "pyproject.toml",
    "pipfile",
    "environment.yml",
    "environment.yaml",
    "conda.yaml",
}

IGNORED_FILENAMES = {
    "readme.md",
    ".gitkeep",
    ".gitignore",
    ".ds_store",
    "reference.json",
    "baseline.json",
    "sha256sums.txt",
}

# Безопасные примитивы реконструкции тензоров и структур данных в Pickle/PyTorch
SAFE_PICKLE_GLOBALS = {
    ("collections", "OrderedDict"),
    ("collections", "defaultdict"),
    ("torch._utils", "_rebuild_tensor"),
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_tensor_v3"),
    ("torch._utils", "_rebuild_parameter"),
    ("torch._utils", "_rebuild_sparse_tensor"),
    ("torch._utils", "_rebuild_meta_tensor_no_storage"),
    ("torch", "FloatStorage"),
    ("torch", "DoubleStorage"),
    ("torch", "HalfStorage"),
    ("torch", "BFloat16Storage"),
    ("torch", "LongStorage"),
    ("torch", "IntStorage"),
    ("torch", "ShortStorage"),
    ("torch", "CharStorage"),
    ("torch", "ByteStorage"),
    ("torch", "BoolStorage"),
    ("torch", "Size"),
    ("torch", "device"),
    ("torch", "dtype"),
    ("torch.storage", "_load_from_bytes"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("numpy._core.multiarray", "_reconstruct"),
    ("numpy._core.multiarray", "scalar"),
    ("numpy", "ndarray"),
    ("numpy", "dtype"),
    ("_codecs", "encode"),
    ("copy_reg", "_reconstructor"),
    ("copyreg", "_reconstructor"),
    ("__builtin__", "set"),
    ("builtins", "set"),
    ("builtins", "frozenset"),
    ("builtins", "complex"),
    ("builtins", "bytearray"),
    ("builtins", "slice"),
}

CRITICAL_PICKLE_MODULES = {
    "os",
    "posix",
    "nt",
    "subprocess",
    "commands",
    "pty",
    "popen2",
    "runpy",
    "marshal",
    "ctypes",
    "cffi",
    "webbrowser",
    "code",
    "codeop",
    "importlib",
    "imp",
    "sys",
}

CRITICAL_PICKLE_CALLABLES = {
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "compile"),
    ("builtins", "__import__"),
    ("__builtin__", "eval"),
    ("__builtin__", "exec"),
    ("__builtin__", "compile"),
    ("__builtin__", "__import__"),
    ("__builtin__", " execfile"),
    ("types", "FunctionType"),
    ("types", "CodeType"),
    ("operator", "attrgetter"),
    ("operator", "methodcaller"),
    ("functools", "partial"),
}

HIGH_RISK_PICKLE_MODULES = {
    "socket",
    "urllib",
    "urllib2",
    "urllib3",
    "http",
    "httplib",
    "requests",
    "ftplib",
    "smtplib",
    "telnetlib",
    "shutil",
    "tempfile",
    "pathlib",
    "glob",
    "pickle",
    "_pickle",
    "dill",
    "shelve",
}

HIGH_RISK_PICKLE_CALLABLES = {
    ("builtins", "open"),
    ("__builtin__", "open"),
    ("__builtin__", "file"),
    ("io", "open"),
    ("io", "FileIO"),
    ("torch.jit", "load"),
    ("torch.hub", "load"),
    ("torch.hub", "load_state_dict_from_url"),
}

# Встроенная офлайн-база уязвимостей (CVE / GHSA) для популярных ML и Python-пакетов
OFFLINE_VULN_DB: list[dict[str, Any]] = [
    {
        "package": "torch",
        "max_exclusive": (2, 6, 0),
        "cve": "CVE-2025-32434",
        "severity": "critical",
        "summary": "Удалённое выполнение кода (RCE) при загрузке модели через torch.load даже с weights_only=True в версиях PyTorch < 2.6.0.",
        "fixed_in": "2.6.0",
    },
    {
        "package": "torch",
        "max_exclusive": (2, 2, 2),
        "cve": "CVE-2024-31583",
        "severity": "high",
        "summary": "Use-after-free и повреждение памяти в интерпретаторе TorchScript / mobile bytecode (PyTorch < 2.2.2).",
        "fixed_in": "2.2.2",
    },
    {
        "package": "transformers",
        "max_exclusive": (4, 48, 0),
        "cve": "CVE-2024-11392",
        "severity": "critical",
        "summary": "Небезопасная десериализация в transformers (< 4.48.0), приводящая к выполнению произвольного кода при обработке весов/конфигураций.",
        "fixed_in": "4.48.0",
    },
    {
        "package": "transformers",
        "max_exclusive": (4, 38, 0),
        "cve": "CVE-2024-3568",
        "severity": "high",
        "summary": "Произвольное выполнение кода через десериализацию Pickle в TFPreTrainedModel.load_repo_checkpoint (transformers < 4.38.0).",
        "fixed_in": "4.38.0",
    },
    {
        "package": "onnx",
        "max_exclusive": (1, 16, 2),
        "cve": "CVE-2024-5187",
        "severity": "high",
        "summary": "Path Traversal (обход пути) при загрузке внешних тензоров в ONNX (< 1.16.2), позволяющий перезаписать или прочитать произвольные файлы.",
        "fixed_in": "1.16.2",
    },
    {
        "package": "onnx",
        "max_exclusive": (1, 16, 0),
        "cve": "CVE-2024-27318",
        "severity": "high",
        "summary": "Чтение произвольных файлов через external_data в ONNX-моделях (< 1.16.0).",
        "fixed_in": "1.16.0",
    },
    {
        "package": "keras",
        "max_exclusive": (3, 9, 0),
        "cve": "CVE-2025-1550",
        "severity": "critical",
        "summary": "Обход safe_mode=True в Keras (< 3.9.0) при загрузке архивов .keras, позволяющий выполнить произвольный код через config.json.",
        "fixed_in": "3.9.0",
    },
    {
        "package": "tensorflow",
        "max_exclusive": (2, 16, 1),
        "cve": "CVE-2024-3660",
        "severity": "critical",
        "summary": "Произвольное выполнение кода при загрузке моделей Keras/TensorFlow с Lambda-слоями (< 2.16.1).",
        "fixed_in": "2.16.1",
    },
    {
        "package": "numpy",
        "max_exclusive": (1, 22, 0),
        "cve": "CVE-2021-41495",
        "severity": "medium",
        "summary": "Разыменование NULL-указателя и некорректная валидация размерностей массивов в NumPy (< 1.22.0).",
        "fixed_in": "1.22.0",
    },
    {
        "package": "scipy",
        "max_exclusive": (1, 10, 0),
        "cve": "CVE-2023-25399",
        "severity": "medium",
        "summary": "Ошибки управления счётчиком ссылок в Py_FindObjects внутри SciPy (< 1.10.0).",
        "fixed_in": "1.10.0",
    },
    {
        "package": "scikit-learn",
        "max_exclusive": (1, 5, 0),
        "cve": "CVE-2024-5206",
        "severity": "medium",
        "summary": "Утечка чувствительных токенов в атрибуте stop_words_ в TfidfVectorizer/CountVectorizer (scikit-learn < 1.5.0).",
        "fixed_in": "1.5.0",
    },
    {
        "package": "pillow",
        "max_exclusive": (10, 3, 0),
        "cve": "CVE-2024-28219",
        "severity": "high",
        "summary": "Переполнение буфера в _imagingcms.c при обработке цветовых профилей изображений в Pillow (< 10.3.0).",
        "fixed_in": "10.3.0",
    },
    {
        "package": "pillow",
        "max_exclusive": (10, 2, 0),
        "cve": "CVE-2023-50447",
        "severity": "critical",
        "summary": "Произвольное выполнение кода через ImageMath.eval при обработке параметров окружения в Pillow (< 10.2.0).",
        "fixed_in": "10.2.0",
    },
    {
        "package": "pyyaml",
        "max_exclusive": (5, 4, 0),
        "cve": "CVE-2020-14343",
        "severity": "critical",
        "summary": "Выполнение произвольного кода при разборе YAML-файлов через FullLoader/load в PyYAML (< 5.4).",
        "fixed_in": "5.4.0",
    },
    {
        "package": "jinja2",
        "max_exclusive": (3, 1, 5),
        "cve": "CVE-2024-56326",
        "severity": "high",
        "summary": "Побег из песочницы (Sandbox Escape) через косвенный вызов str.format в шаблонах Jinja2 (< 3.1.5).",
        "fixed_in": "3.1.5",
    },
    {
        "package": "requests",
        "max_exclusive": (2, 32, 0),
        "cve": "CVE-2024-35195",
        "severity": "medium",
        "summary": "Игнорирование verify=False/сертификатов при повторном использовании сессии в Requests (< 2.32.0).",
        "fixed_in": "2.32.0",
    },
    {
        "package": "urllib3",
        "max_exclusive": (1, 26, 19),
        "cve": "CVE-2024-37891",
        "severity": "medium",
        "summary": "Утечка Proxy-Authorization при междоменных перенаправлениях в urllib3 (< 1.26.19).",
        "fixed_in": "1.26.19",
    },
    {
        "package": "urllib3",
        "min_inclusive": (2, 0, 0),
        "max_exclusive": (2, 2, 2),
        "cve": "CVE-2024-37891",
        "severity": "medium",
        "summary": "Утечка Proxy-Authorization при междоменных перенаправлениях в urllib3 (>= 2.0.0, < 2.2.2).",
        "fixed_in": "2.2.2",
    },
    {
        "package": "flask",
        "max_exclusive": (2, 3, 2),
        "cve": "CVE-2023-30861",
        "severity": "high",
        "summary": "Утечка сессионных cookie из-за некорректного заголовка Vary: Cookie при кэшировании в Flask (< 2.3.2).",
        "fixed_in": "2.3.2",
    },
    {
        "package": "werkzeug",
        "max_exclusive": (3, 0, 6),
        "cve": "CVE-2024-49767",
        "severity": "high",
        "summary": "Исчерпание ресурсов (DoS) при разборе multipart/form-data запросов в Werkzeug (< 3.0.6).",
        "fixed_in": "3.0.6",
    },
    {
        "package": "fastapi",
        "max_exclusive": (0, 109, 1),
        "cve": "CVE-2024-24762",
        "severity": "high",
        "summary": "ReDoS-уязвимость при парсинге заголовка Content-Type в FastAPI/Starlette (< 0.109.1).",
        "fixed_in": "0.109.1",
    },
    {
        "package": "starlette",
        "max_exclusive": (0, 40, 0),
        "cve": "CVE-2024-47874",
        "severity": "high",
        "summary": "Отказ в обслуживании (DoS) при обработке multipart-форм без лимита размера частей в Starlette (< 0.40.0).",
        "fixed_in": "0.40.0",
    },
    {
        "package": "gradio",
        "max_exclusive": (5, 0, 0),
        "cve": "CVE-2024-47167",
        "severity": "high",
        "summary": "SSRF и несанкционированный доступ к локальным файлам через проксирование компонентов в Gradio (< 5.0.0).",
        "fixed_in": "5.0.0",
    },
    {
        "package": "mlflow",
        "max_exclusive": (2, 16, 0),
        "cve": "CVE-2024-2928",
        "severity": "critical",
        "summary": "Локальное чтение произвольных файлов (LFI / Path Traversal) через артефакты экспериментов в MLflow (< 2.16.0).",
        "fixed_in": "2.16.0",
    },
    {
        "package": "langchain",
        "max_exclusive": (0, 2, 5),
        "cve": "CVE-2024-36480",
        "severity": "high",
        "summary": "Небезопасная десериализация и инъекция кода в цепочках инструментов LangChain (< 0.2.5).",
        "fixed_in": "0.2.5",
    },
    {
        "package": "aiohttp",
        "max_exclusive": (3, 10, 2),
        "cve": "CVE-2024-23334",
        "severity": "high",
        "summary": "Path Traversal при раздаче статических файлов с follow_symlinks в aiohttp (< 3.10.2).",
        "fixed_in": "3.10.2",
    },
    {
        "package": "joblib",
        "max_exclusive": (1, 2, 0),
        "cve": "CVE-2022-21797",
        "severity": "critical",
        "summary": "Произвольное выполнение кода через eval() в аргументе pre_dispatch класса Parallel в joblib (< 1.2.0).",
        "fixed_in": "1.2.0",
    },
    {
        "package": "tqdm",
        "max_exclusive": (4, 66, 3),
        "cve": "CVE-2024-34062",
        "severity": "medium",
        "summary": "Инъекция аргументов черезeval-подобный разбор CLI-параметров в tqdm (< 4.66.3).",
        "fixed_in": "4.66.3",
    },
    {
        "package": "ray",
        "max_exclusive": (2, 10, 0),
        "cve": "CVE-2023-48022",
        "severity": "critical",
        "summary": "Отсутствие аутентификации в Ray Jobs API позволяет выполнить произвольные команды на узлах кластера.",
        "fixed_in": "2.10.0",
    },
]


def _rel_path(path: Path, base_dir: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT_DIR.resolve()))
    except ValueError:
        try:
            return str(path.resolve().relative_to(base_dir.resolve()))
        except ValueError:
            return str(path)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_finding(
    rule_id: str,
    obj: str,
    evidence: str,
    severity: str,
    status: str = "needs_review",
    decision: str = "",
    category: str = "model_security",
    point: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not decision:
        if severity in ("critical", "high"):
            decision = "Требуется блокировка пайплайна и устранение уязвимости перед публикацией модели."
        else:
            decision = "Проверить происхождение артефакта и зафиксировать обоснование в карточке триажа."
    return {
        "id": rule_id,
        "contour": "model",
        "category": category,
        "object": obj,
        "evidence": evidence,
        "severity": severity,
        "status": status,
        "decision": decision,
        **({"point": point} if point is not None else {}),
    }


def _inspect_pickle_stream(
    data: bytes, source_label: str, findings: list[dict[str, Any]], depth: int = 0
) -> list[float]:
    """
    Статический разбор байткода Pickle через pickletools.genops() без исполнения кода.
    Возвращает также список числовых значений (float), встреченных в потоке, для анализа весов.
    """
    extracted_floats: list[float] = []
    if depth > 3:
        return extracted_floats

    stream = io.BytesIO(data)
    stack_strings: list[str] = []
    has_reduce_or_build = False
    dangerous_calls_seen: set[tuple[str, str, int]] = set()

    try:
        for opcode, arg, pos in pickletools.genops(stream):
            opname = opcode.name
            pos_val = pos if pos is not None else 0

            if opname in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"):
                if isinstance(arg, str):
                    stack_strings.append(arg)
                    if len(stack_strings) > 8:
                        stack_strings.pop(0)
            elif opname in ("BINFLOAT", "FLOAT"):
                try:
                    val = float(arg)
                    if math.isfinite(val):
                        extracted_floats.append(val)
                except (ValueError, TypeError):
                    pass
            elif opname in ("SHORT_BINBYTES", "BINBYTES", "BINBYTES8") and isinstance(arg, (bytes, bytearray)):
                # Проверяем, нет ли вложенного pickle или буфера float32
                if len(arg) >= 4 and arg[:2] in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
                    nested_floats = _inspect_pickle_stream(
                        bytes(arg), f"{source_label} -> nested_pickle@{pos_val}", findings, depth + 1
                    )
                    extracted_floats.extend(nested_floats)
                elif len(arg) >= 16 and len(arg) % 4 == 0 and len(extracted_floats) < 250000:
                    # Попытка безопасной распаковки буфера float32 (например, из numpy/torch сериализации)
                    count = min(len(arg) // 4, 50000)
                    try:
                        vals = struct.unpack(f"<{count}f", arg[: count * 4])
                        valid = [v for v in vals if math.isfinite(v) and abs(v) < 1e6]
                        if len(valid) == count and any(abs(v) > 1e-7 for v in valid):
                            extracted_floats.extend(valid)
                    except struct.error:
                        pass

            mod_name: str | None = None
            attr_name: str | None = None

            if opname in ("GLOBAL", "INST") and isinstance(arg, str):
                parts = arg.strip().split(" ", 1)
                if len(parts) == 2:
                    mod_name, attr_name = parts[0], parts[1]
                elif len(parts) == 1:
                    mod_name, attr_name = parts[0], "*"
            elif opname == "STACK_GLOBAL":
                if len(stack_strings) >= 2:
                    mod_name = stack_strings[-2]
                    attr_name = stack_strings[-1]
                    stack_strings = stack_strings[:-2]
            elif opname in ("EXT1", "EXT2", "EXT4"):
                findings.append(
                    _make_finding(
                        rule_id="MDL-PICKLE-EXT",
                        obj=f"{source_label} (offset {pos_val})",
                        evidence=f"Обнаружен опкод расширения copyreg {opname} (код {arg}), позволяющий подменить глобальный класс при десериализации.",
                        severity="high",
                        status="confirmed",
                        decision="Запретить загрузку Pickle с внешними кодами реестра copyreg; перевести модель в формат SafeTensors.",
                        category="unsafe_serialization",
                    )
                )

            if mod_name and attr_name:
                pair = (mod_name, attr_name)
                root_mod = mod_name.split(".")[0]
                dedup_key = (mod_name, attr_name, pos_val)
                if dedup_key in dangerous_calls_seen:
                    continue

                if pair in SAFE_PICKLE_GLOBALS or mod_name.startswith("torch.nn.modules"):
                    continue

                if root_mod in CRITICAL_PICKLE_MODULES or pair in CRITICAL_PICKLE_CALLABLES:
                    dangerous_calls_seen.add(dedup_key)
                    findings.append(
                        _make_finding(
                            rule_id="MDL-PICKLE-RCE",
                            obj=f"{source_label} (offset {pos_val})",
                            evidence=(
                                f"Опкод {opname} импортирует опасный системный вызов '{mod_name}.{attr_name}'. "
                                f"При вызове pickle.load() / torch.load() будет выполнен произвольный код."
                            ),
                            severity="critical",
                            status="confirmed",
                            decision=(
                                "КРИТИЧЕСКАЯ УГРОЗА (RCE): Заблокировать пайплайн. Не загружать файл через pickle/torch.load. "
                                "Пересобрать веса из доверенного источника в формат .safetensors."
                            ),
                            category="unsafe_serialization",
                        )
                    )
                elif root_mod in HIGH_RISK_PICKLE_MODULES or pair in HIGH_RISK_PICKLE_CALLABLES:
                    dangerous_calls_seen.add(dedup_key)
                    findings.append(
                        _make_finding(
                            rule_id="MDL-PICKLE-DANGEROUS-IO",
                            obj=f"{source_label} (offset {pos_val})",
                            evidence=(
                                f"Опкод {opname} обращается к файловому/сетевому модулю '{mod_name}.{attr_name}' "
                                f"на этапе десериализации модели."
                            ),
                            severity="high",
                            status="confirmed",
                            decision=(
                                "Заблокировать загрузку модели: сериализованный граф не должен выполнять файловые или сетевые операции. "
                                "Использовать torch.load(..., weights_only=True) или формат SafeTensors."
                            ),
                            category="unsafe_serialization",
                        )
                    )
                else:
                    dangerous_calls_seen.add(dedup_key)
                    findings.append(
                        _make_finding(
                            rule_id="MDL-PICKLE-CUSTOM-GLOBAL",
                            obj=f"{source_label} (offset {pos_val})",
                            evidence=(
                                f"Опкод {opname} ссылается на нестандартный символ '{mod_name}.{attr_name}', "
                                f"отсутствующий в белом списке безопасных примитивов тензоров."
                            ),
                            severity="medium",
                            status="needs_review",
                            decision=(
                                "Проверить происхождение класса/функции. Для чистых весов модели рекомендуется хранить только state_dict "
                                "в формате SafeTensors без сериализации произвольных Python-объектов."
                            ),
                            category="unsafe_serialization",
                        )
                    )

            if opname in ("REDUCE", "BUILD", "OBJ", "NEWOBJ", "NEWOBJ_EX"):
                has_reduce_or_build = True

    except Exception as exc:
        findings.append(
            _make_finding(
                rule_id="MDL-PICKLE-CORRUPT",
                obj=source_label,
                evidence=f"Поток байткода Pickle повреждён или обрезан при разборе: {exc}",
                severity="medium",
                status="needs_review",
                decision="Проверить целостность файла модели и контрольную сумму SHA-256.",
                category="format_integrity",
            )
        )

    return extracted_floats


def _record_nonfinite(source_label, tensor_name, shape, n, index, value, count, findings):
    kind = "NaN" if math.isnan(value) else ("+Inf" if value > 0 else "-Inf")
    findings.append(_make_finding(
        rule_id="MDL-WEIGHT-NONFINITE",
        obj=f"{source_label} :: тензор '{tensor_name}' (индекс {index})",
        evidence=f"Найдено {count} нечисловых или бесконечных значений из {n}. Первое: {kind}.",
        severity="high",
        category="weight_integrity",
        point={"tensor": tensor_name, "kind": "nonfinite", "index": index,
               "coordinates": coordinates(shape, index), "value": kind,
               "metrics": {"count": count, "sample_size": n}},
    ))


def _record_bias(source_label, tensor_name, shape, max_idx, max_val, mean_others, std_others, bias_z, findings):
    if max_val > 2.5 and bias_z > 5.0 and (max_val - mean_others) > 2.0:
        findings.append(
            _make_finding(
                rule_id="MDL-BACKDOOR-BIAS",
                obj=f"{source_label} :: тензор '{tensor_name}' (индекс класса {max_idx})",
                evidence=(
                    f"Аномальный сдвиг смещения (bias) для индекса {max_idx}: значение {max_val:.4f} "
                    f"при среднем остальных классов {mean_others:.4f} (std={std_others:.4f}, Z-score={bias_z:.1f}σ). "
                    f"Наблюдаемый признак характерен для целевой закладки (targeted class backdoor), повышающей априорный логит выбранного класса."
                ),
                severity="high",
                status="needs_review",
                decision=(
                    "Провести валидацию модели на эталонной выборке и проверить распределение предсказаний по классу "
                    f"#{max_idx}. При подтверждении переобучить выходной классификатор или выполнить fine-pruning."
                ),
                category="weight_backdoor",
                point={"tensor": tensor_name, "kind": "bias", "index": max_idx,
                       "coordinates": coordinates(shape, max_idx), "value": max_val,
                       "metrics": {"z_score": bias_z, "peer_mean": mean_others, "delta": max_val - mean_others},
                       "thresholds": {"z_score": 5.0, "value": 2.5, "delta": 2.0}},
            )
        )


def _record_row_norm(source_label, tensor_name, shape, max_row_idx, max_norm, median_norm, findings):
    norm_ratio = max_norm / max(median_norm, 1e-6)
    if norm_ratio > 4.5 and max_norm > 3.0:
        findings.append(
            _make_finding(
                rule_id="MDL-BACKDOOR-NEURON",
                obj=f"{source_label} :: тензор '{tensor_name}' (нейрон/канал #{max_row_idx}, shape={shape})",
                evidence=(
                    f"Обнаружена аномально большая норма в строке #{max_row_idx}: L2-норма строки = {max_norm:.4f}, "
                    f"что в {norm_ratio:.1f}x превышает медианную L2-норму слоя ({median_norm:.4f}). "
                    "Сравните строку с эталоном и проверьте поведение на предполагаемых триггерах."
                ),
                severity="high",
                status="needs_review",
                decision=(
                    f"Сравнить строку #{max_row_idx} слоя '{tensor_name}' с доверенными весами. "
                    "Решение об отклонении принять после проверки происхождения и поведения."
                ),
                category="weight_backdoor",
                point={"tensor": tensor_name, "kind": "row_norm", "index": max_row_idx,
                       "coordinates": [max_row_idx], "value": max_norm,
                       "metrics": {"row_norm": max_norm, "median_row_norm": median_norm, "ratio": norm_ratio},
                       "thresholds": {"ratio": 4.5, "row_norm": 3.0}},
            )
        )


def _record_weight_peak(source_label, tensor_name, shape, values, n, peak_index, peak_value, z_max, kurtosis, findings):
    if abs(peak_value) <= 5:
        return
    abs_vals = sorted(abs(value) for value in values)
    median_abs = abs_vals[len(abs_vals) // 2]
    p99_abs = abs_vals[min(len(abs_vals) - 1, int(len(abs_vals) * 0.99))]
    max_abs = abs(peak_value)
    ratio_to_p99 = max_abs / max(p99_abs, 1e-6)
    median = statistics.median(values)
    mad = statistics.median(abs(value - median) for value in values)
    robust_z = 0.6745 * abs(peak_value - median) / max(mad, 1e-6)
    triggers = [
        name for name, triggered in (
            ("classic_peak", z_max > 8.5 and max_abs > 5.0 and ratio_to_p99 > 4.0),
            ("heavy_tail", kurtosis is not None and kurtosis > 60.0 and max_abs > 8.0),
            ("robust_peak", n >= 32 and robust_z > 12.0 and max_abs > 5.0 and ratio_to_p99 > 4.0),
        ) if triggered
    ]
    if triggers:
        tail_evidence = f", эксцесс={kurtosis:.1f}" if kurtosis is not None else ""
        findings.append(
            _make_finding(
                rule_id="MDL-BACKDOOR-OUTLIER",
                obj=f"{source_label} :: тензор '{tensor_name}' (elements={n})",
                evidence=(
                    f"Экстремальный выброс весов: L_inf={max_abs:.4f} (медиана={median_abs:.4f}, 99-й перцентиль={p99_abs:.4f}), "
                    f"Z-score={z_max:.1f}σ, robust Z={robust_z:.1f}{tail_evidence}. "
                    "Резкий локальный пик требует сравнения с доверенными весами."
                ),
                severity="high",
                status="needs_review",
                decision=(
                    "Сравнить распределение весов с чистым чекпоинтом (reference.json) и применить ограничение амплитуды весов (weight clipping)."
                ),
                category="weight_backdoor",
                point={"tensor": tensor_name, "kind": "peak", "index": peak_index,
                       "coordinates": coordinates(shape, peak_index), "value": peak_value,
                       "metrics": {"abs_peak": max_abs, "z_score_max": z_max, "robust_z": robust_z, "mad": mad,
                                   "ratio_to_p99": ratio_to_p99, "sample_size": len(values), "values_inspected": n,
                                   **({"kurtosis": kurtosis} if kurtosis is not None else {})},
                       "thresholds": {"z_score_max": 8.5, "robust_z": 12.0, "kurtosis": 60.0,
                                      "ratio_to_p99": 4.0, "abs_peak": 8.0 if triggers == ["heavy_tail"] else 5.0},
                       "triggered_rules": triggers},
            )
        )


def _analyze_tensor_weights(
    tensors: dict[str, tuple[list[int], list[float]]],
    source_label: str,
    findings: list[dict[str, Any]],
) -> None:
    """
    Статистический детектор закладок (backdoors / trojans) в весах модели.
    Выявляет:
      1. Экстремальные выбросы весов ($L_\\infty$-аномалии, Z-score > 8.5, эксцесс > 45) — признак инъекции троянского патча или bit-flip атаки.
      2. Перекос смещения (bias) одного целевого класса — признак целевой закладки классификатора.
      3. Троянский нейрон-триггер (одна строка матрицы весов имеет $L_2$-норму в >4.5 раза выше медианы остальных нейронов слоя).
    """
    for tensor_name, (shape, values) in tensors.items():
        n = len(values)
        nonfinite = [index for index, value in enumerate(values) if not math.isfinite(value)]
        if nonfinite:
            index = nonfinite[0]
            _record_nonfinite(source_label, tensor_name, shape, n, index, values[index], len(nonfinite), findings)
            continue
        if n < 3:
            continue

        if max(abs(value) for value in values) > 1e150:
            findings.append(_make_finding(
                rule_id="MDL-WEIGHT-RANGE", obj=f"{source_label} :: {tensor_name}",
                evidence="Амплитуда весов превышает численно устойчивый диапазон анализа.",
                severity="medium", category="analysis_coverage",
                decision="Проверить масштаб весов и целостность исходного файла.",
            ))
            continue

        mean_val = sum(values) / n
        variance = sum((x - mean_val) ** 2 for x in values) / n
        std_val = math.sqrt(variance) if variance > 0 else 0.0

        peak_index = max(range(n), key=lambda index: abs(values[index]))

        # 1. Проверка вектора смещений (bias) на перекос целевого класса
        is_bias = len(shape) == 1 and "bias" in tensor_name.lower()
        if is_bias and n >= 3 and std_val > 1e-6:
            max_val = max(values)
            max_idx = values.index(max_val)
            others = [v for i, v in enumerate(values) if i != max_idx]
            mean_others = sum(others) / len(others)
            var_others = sum((v - mean_others) ** 2 for v in others) / len(others)
            std_others = math.sqrt(var_others) if var_others > 1e-9 else 1e-4
            bias_z = (max_val - mean_others) / std_others

            _record_bias(source_label, tensor_name, shape, max_idx, max_val, mean_others, std_others, bias_z, findings)

        # 2. Проверка матриц весов на троянский нейрон-триггер (аномальная L2-норма строки)
        if (len(shape) >= 2 and all(type(size) is int and size > 0 for size in shape)
                and shape[0] >= 4 and math.prod(shape) == n):
            rows = shape[0]
            cols = n // rows
            if cols >= 4 and rows * cols == n:
                row_norms: list[tuple[float, int]] = []
                for r in range(rows):
                    row_slice = values[r * cols : (r + 1) * cols]
                    r_norm = math.sqrt(sum(v * v for v in row_slice))
                    row_norms.append((r_norm, r))

                sorted_norms = sorted(norm for norm, _ in row_norms)
                median_norm = sorted_norms[rows // 2]
                max_norm, max_row_idx = max(row_norms, key=lambda item: item[0])

                _record_row_norm(source_label, tensor_name, shape, max_row_idx, max_norm, median_norm, findings)

        # 3. Проверка глобальных выбросов (L_inf / Z-score / эксцесс) в тензоре
        if n >= 16 and std_val > 1e-6:
            z_max = max(abs(x - mean_val) for x in values) / std_val
            kurtosis = (
                sum(((x - mean_val) / std_val) ** 4 for x in values) / n - 3.0
                if std_val > 1e-6
                else 0.0
            )
            _record_weight_peak(source_label, tensor_name, shape, values, n, peak_index, values[peak_index],
                                z_max, kurtosis, findings)


def _record_prompt_markers(
    data: bytes, source: str, location: str, findings: list[dict[str, Any]],
    shape: list[int] | None = None,
) -> None:
    for rule, offset in prompt_matches(data):
        findings.append(_make_finding(
            rule_id="MDL-PROMPT-MARKER",
            obj=f"{source} :: {location} ({rule}, byte {offset})",
            evidence=f"Правило {rule} сработало на смещении {offset} внутри поля или буфера.",
            severity="medium",
            category="prompt_indicator",
            decision="Проверить происхождение поля или байтового буфера и сравнить с доверенной версией.",
            point={"tensor": location, "kind": "prompt_marker", "index": offset,
                   "coordinates": coordinates(shape, offset) if shape is not None else None,
                   "value": rule, "metrics": {"bytes_inspected": len(data)}},
        ))


def _scan_pytorch_zip(archive, rel_name: str, findings: list[dict[str, Any]]) -> None:
    pkl_entries = [entry for entry in archive.entries if entry.filename.endswith(".pkl")]
    storages = [entry for entry in archive.entries
                if "/data/" in entry.filename and not entry.is_dir() and not entry.filename.endswith(".pkl")]
    if not pkl_entries:
        findings.append(_make_finding(
            "MDL-PT-STRUCTURE", rel_name, "ZIP-архив модели не содержит файла метаданных Pickle.",
            "low", category="format_integrity",
        ))
    for entry in pkl_entries:
        floats = _inspect_pickle_stream(archive.read(entry), f"{rel_name} -> {entry.filename}", findings)
        if len(floats) >= 4:
            _analyze_tensor_weights({entry.filename: ([len(floats)], floats)}, rel_name, findings)
    for entry in storages[:32]:
        if entry.file_size >= 12 and entry.file_size % 4 == 0:
            buf = archive.read(entry, prefix=400000)
            count = len(buf) // 4
            values = list(struct.unpack(f"<{count}f", buf))
            if all(math.isfinite(v) for v in values) and any(abs(v) > 1e-8 for v in values):
                _analyze_tensor_weights({entry.filename: ([count], values)}, rel_name, findings)


def _scan_large_tensor(stream, dtype, start, shape, source, name, count, findings):
    stats = analyze_float_stream(stream, dtype, start, shape)
    if stats.first_nonfinite is not None:
        index, value = stats.first_nonfinite
        _record_nonfinite(source, name, shape, count, index, value, stats.nonfinite_count, findings)
        return
    if stats.out_of_range:
        findings.append(_make_finding(
            "MDL-WEIGHT-RANGE", f"{source} :: {name}",
            "Амплитуда превышает численно устойчивый диапазон расчёта моментов.",
            "medium", category="analysis_coverage",
        ))
        return
    _record_row_norm(source, name, shape, stats.row_peak_index, stats.row_peak, stats.row_median, findings)
    std = math.sqrt(stats.variance)
    if std <= 1e-6:
        return
    if len(shape) == 1 and "bias" in name.lower():
        delta = stats.maximum - stats.mean
        peer_mean = stats.mean - delta / (count - 1)
        peer_m2 = max(0.0, count * stats.variance - delta**2 * count / (count - 1))
        peer_var = peer_m2 / (count - 1)
        peer_std = math.sqrt(peer_var) if peer_var > 1e-9 else 1e-4
        _record_bias(source, name, shape, stats.maximum_index, stats.maximum, peer_mean, peer_std,
                     (stats.maximum - peer_mean) / peer_std, findings)
    z_max = max(abs(stats.minimum - stats.mean), abs(stats.maximum - stats.mean)) / std
    _record_weight_peak(source, name, shape, stats.sample, count, stats.peak_index, stats.peak_value,
                        z_max, stats.kurtosis, findings)


def _scan_safetensors_file(path: Path, rel_name: str, findings: list[dict[str, Any]], coverage: dict) -> None:
    file_size = path.stat().st_size
    if file_size < 8:
        findings.append(
            _make_finding(
                rule_id="MDL-SAFETENSORS-CORRUPT",
                obj=rel_name,
                evidence=f"Размер файла .safetensors ({file_size} байт) меньше минимального 8-байтового заголовка.",
                severity="medium",
                status="confirmed",
                decision="Заменить повреждённый файл весов.",
                category="format_integrity",
            )
        )
        return

    with path.open("rb") as f:
        header_len_bytes = f.read(8)
        (header_len,) = struct.unpack("<Q", header_len_bytes)
        if header_len == 0 or header_len > 100 * 1024 * 1024 or 8 + header_len > file_size:
            findings.append(
                _make_finding(
                    rule_id="MDL-SAFETENSORS-HEADER",
                    obj=rel_name,
                    evidence=(
                        f"Некорректный размер заголовка SafeTensors: {header_len} байт при размере файла {file_size} байт "
                        f"(попытка переполнения буфера или обрезанный файл)."
                    ),
                    severity="high",
                    status="confirmed",
                    decision="Отклонить файл: заголовок SafeTensors выходит за границы файла.",
                    category="format_integrity",
                )
            )
            return

        header_raw = f.read(header_len)
        try:
            header = json.loads(header_raw.decode("utf-8"))
            if not isinstance(header, dict):
                raise ValueError("Ожидается объект JSON.")
        except Exception as exc:
            findings.append(
                _make_finding(
                    rule_id="MDL-SAFETENSORS-JSON",
                    obj=rel_name,
                    evidence=f"Заголовок SafeTensors не является валидным JSON: {exc}",
                    severity="high",
                    status="confirmed",
                    decision="Отклонить повреждённый файл модели.",
                    category="format_integrity",
                )
            )
            return

        data_start = 8 + header_len
        data_body_len = file_size - data_start
        metadata = header.get("__metadata__")
        if isinstance(metadata, dict):
            for k, v in metadata.items():
                val_str = str(v)
                if str(k).lower() in PROMPT_FIELDS and isinstance(v, str):
                    _record_prompt_markers(v[:65536].encode("utf-8"), rel_name, f"__metadata__.{k}", findings)
                if any(tok in val_str.lower() for tok in ("eval(", "exec(", "os.system", "subprocess", "http://", "https://")):
                    findings.append(
                        _make_finding(
                            rule_id="MDL-SAFETENSORS-META",
                            obj=f"{rel_name} :: __metadata__.{k}",
                            evidence=f"Подозрительное содержимое в метаданных SafeTensors: '{k}': '{val_str[:120]}'",
                            severity="medium",
                            status="needs_review",
                            decision="Очистить подозрительные поля __metadata__ перед публикацией модели.",
                            category="model_metadata",
                        )
                    )

        spans = []
        for key, info in header.items():
            if key == "__metadata__" or not isinstance(info, dict):
                continue
            offsets = info.get("data_offsets")
            dtype = info.get("dtype", "F32")
            shape = info.get("shape", [])
            if (
                not isinstance(offsets, list)
                or len(offsets) != 2
                or not all(type(x) is int for x in offsets)
            ):
                continue
            start_off, end_off = offsets
            if start_off < 0 or end_off < start_off or end_off > data_body_len:
                findings.append(
                    _make_finding(
                        rule_id="MDL-SAFETENSORS-BOUNDS",
                        obj=f"{rel_name} :: {key}",
                        evidence=(
                            f"Смещения тензора '{key}' [{start_off}, {end_off}] выходят за пределы секции данных ({data_body_len} байт)."
                        ),
                        severity="high",
                        status="confirmed",
                        decision="Заблокировать файл: нарушение границ буфера в заголовке SafeTensors.",
                        category="format_integrity",
                    )
                )
                continue
            if end_off > start_off:
                spans.append((start_off, end_off, key, dtype, shape))

        spans.sort()
        if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
            findings.append(_make_finding(
                "MDL-SAFETENSORS-OVERLAP", rel_name, "Буферы тензоров пересекаются.",
                "high", status="confirmed", category="format_integrity",
            ))
            return
        read_bytes = 0
        for start_off, end_off, key, dtype, shape in spans:
            byte_len = end_off - start_off
            dims = shape if isinstance(shape, list) else []
            if dtype in ("U8", "I8") and byte_len:
                f.seek(data_start + start_off)
                _record_prompt_markers(f.read(min(byte_len, 65536)), rel_name, key, findings, dims)
            float_format = FLOAT_FORMATS.get(dtype) if isinstance(dtype, str) else None
            if float_format and byte_len:
                _, width = float_format
                if (byte_len % width or not all(type(size) is int and size >= 0 for size in dims)
                        or math.prod(dims) * width != byte_len):
                    findings.append(_make_finding(
                        rule_id="MDL-SAFETENSORS-SHAPE", obj=f"{rel_name} :: {key}",
                        evidence="Размер буфера не соответствует форме или типу тензора.",
                        severity="high", status="confirmed", category="format_integrity",
                    ))
                    continue
                count = byte_len // width
                coverage["values_total"] += count
                coverage["tensors_total"] += 1
                if read_bytes + byte_len > MAX_FLOAT_BYTES:
                    findings.append(_make_finding(
                        rule_id="MDL-WEIGHT-SAMPLED", obj=f"{rel_name} :: {key}",
                        evidence=f"Тензор с {count} значениями пропущен после достижения лимита чтения SafeTensors.",
                        severity="low", category="analysis_coverage",
                        decision="Разбить модель на меньшие файлы для полного анализа.",
                    ))
                    continue
                start = data_start + start_off
                if count <= 100000:
                    f.seek(start)
                    vals = list(read_floats(f, dtype, count))
                    _analyze_tensor_weights({key: (dims, vals)}, rel_name, findings)
                else:
                    _scan_large_tensor(f, dtype, start, dims, rel_name, key, count, findings)
                read_bytes += byte_len
                coverage["values_inspected"] += count
                coverage["tensors_inspected"] += 1

_KERAS_MARKER = re.compile(rb'"class_name"\s{0,32}:\s{0,32}"Lambda"|__lambda__')


def _scan_keras_or_h5(path: Path, rel_name: str, findings: list[dict[str, Any]], archive=None) -> None:
    detected = False
    if archive is not None:
        for entry in archive.entries:
            if entry.filename.endswith(".json"):
                detected |= bool(_KERAS_MARKER.search(archive.read(entry)))
            elif entry.filename.endswith(".pkl"):
                _inspect_pickle_stream(archive.read(entry), f"{rel_name} -> {entry.filename}", findings)
    else:
        with path.open("rb") as stream:
            tail = b""
            for chunk in iter(lambda: stream.read(65536), b""):
                block = tail + chunk
                if _KERAS_MARKER.search(block):
                    detected = True
                    break
                tail = block[-96:]
    if detected:
        findings.append(
            _make_finding(
                rule_id="MDL-KERAS-LAMBDA",
                obj=rel_name,
                evidence="В конфигурации модели Keras/HDF5 обнаружен слой 'Lambda' с сериализованным Python-байткодом/выражением.",
                severity="critical",
                status="confirmed",
                decision=(
                    "КРИТИЧЕСКАЯ УГРОЗА (CVE-2024-3660 / CVE-2025-1550): Слой Lambda выполняет произвольный код при загрузке модели. "
                    "Заменить Lambda на стандартные слои Keras."
                ),
                category="unsafe_serialization",
            )
        )


def _scan_onnx_file(path: Path, rel_name: str, findings: list[dict[str, Any]]) -> None:
    raw = path.read_bytes()
    latin = raw.decode("latin-1", errors="ignore")

    # Поиск Path Traversal в external_data (CVE-2024-5187 / CVE-2024-27318)
    traversal_match = re.search(r"(\.\./|\.\.\\|/etc/passwd|/proc/self)", latin)
    if traversal_match:
        findings.append(
            _make_finding(
                rule_id="MDL-ONNX-TRAVERSAL",
                obj=rel_name,
                evidence=(
                    f"В бинарной структуре ONNX обнаружена ссылка на внешний путь с выходом из директории "
                    f"('{traversal_match.group(1)}') — признак эксплуатации CVE-2024-5187 / CVE-2024-27318."
                ),
                severity="critical",
                status="confirmed",
                decision="Заблокировать ONNX-модель: внешние пути к тензорам (external_data) не должны содержать '../' или абсолютные пути.",
                category="unsafe_serialization",
            )
        )


NPY_HEADER_LIMIT = 65536
NPY_PREVIEW = NPY_HEADER_LIMIT + 12 + 400000


def _scan_numpy_file(path: Path, rel_name: str, findings: list[dict[str, Any]], archive=None) -> None:
    if archive is None:
        with path.open("rb") as stream:
            data = stream.read(NPY_PREVIEW)
        _scan_npy_bytes(data, rel_name, findings, path.stat().st_size, path.read_bytes)
        return
    for entry in archive.entries:
        name = entry.filename
        label = f"{rel_name} -> {name}"
        if name.endswith(".npy"):
            data = archive.read(entry, prefix=NPY_PREVIEW)
            _scan_npy_bytes(data, label, findings, entry.file_size, lambda: archive.read(entry))
        elif name.endswith(".pkl"):
            _inspect_pickle_stream(archive.read(entry), label, findings)


def _scan_npy_bytes(data: bytes, label: str, findings: list[dict[str, Any]], total_size: int, read_full) -> None:
    if len(data) < 10 or data[:6] != b"\x93NUMPY":
        return
    major = data[6]
    offset = 10 if major == 1 else 12
    if len(data) < offset or major not in (1, 2, 3):
        raise ArchiveRejected("Неподдерживаемый или обрезанный заголовок NumPy.")
    header_len = int.from_bytes(data[8:offset], "little")
    if header_len > NPY_HEADER_LIMIT or offset + header_len > len(data):
        raise ArchiveRejected("Заголовок NumPy превышает лимит или обрезан.")
    header_str = data[offset : offset + header_len].decode("latin-1").strip()
    body_start = offset + header_len
    body = data[body_start:]

    if "'|O'" in header_str or '"|O"' in header_str or "has_object" in header_str:
        findings.append(
            _make_finding(
                rule_id="MDL-NUMPY-OBJECT",
                obj=label,
                evidence=f"Массив NumPy имеет тип dtype=object ({header_str}), что требует вызова pickle.load(allow_pickle=True).",
                severity="high",
                status="confirmed",
                decision="Запретить загрузку массивов с dtype=object (allow_pickle=False).",
                category="unsafe_serialization",
            )
        )
        if total_size > len(data):
            if total_size > MAX_MEMBER_READ:
                raise ArchiveRejected("Объектный массив NumPy превышает лимит статического разбора.")
            body = read_full()[body_start:]
        _inspect_pickle_stream(body, f"{label} (object payload)", findings)
        return

    try:
        header_dict = ast.literal_eval(header_str)
        descr = str(header_dict.get("descr", ""))
        shape = list(header_dict.get("shape", ()))
        if descr in ("<f4", "f4") and len(body) >= 12 and (total_size - body_start) % 4 == 0:
            count = min(len(body) // 4, 100000)
            vals = list(struct.unpack(f"<{count}f", body[: count * 4]))
            _analyze_tensor_weights({label: (shape or [count], vals)}, label, findings)
    except Exception:
        pass


def _scan_json_model_file(path: Path, rel_name: str, findings: list[dict[str, Any]]) -> None:
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append(
            _make_finding(
                rule_id="MDL-JSON-INVALID",
                obj=rel_name,
                evidence=f"Ошибка синтаксиса JSON в файле модели/конфигурации: {exc}",
                severity="low",
                status="needs_review",
                decision="Исправить структуру JSON-файла.",
                category="format_integrity",
            )
        )
        return

    if not isinstance(content, dict):
        return

    for key, value in content.items():
        if key.lower() in PROMPT_FIELDS and isinstance(value, str):
            _record_prompt_markers(value[:65536].encode("utf-8"), rel_name, key, findings)

    # 1. Проверка HuggingFace auto_map (выполнение произвольного кода при trust_remote_code=True)
    if "auto_map" in content:
        findings.append(
            _make_finding(
                rule_id="MDL-HF-AUTOMAP",
                obj=f"{rel_name} :: auto_map",
                evidence=(
                    f"В конфигурации модели задан хук 'auto_map': {json.dumps(content['auto_map'], ensure_ascii=False)}. "
                    f"При загрузке с trust_remote_code=True это приводит к выполнению внешнего Python-кода из репозитория модели."
                ),
                severity="high",
                status="confirmed",
                decision="Удалить секцию auto_map или принудительно зафиксировать trust_remote_code=False в коде обёртки.",
                category="unsafe_serialization",
            )
        )

    # 2. Если в JSON хранятся слои весов (например, weights/layers/tensors), проверяем их на закладки
    tensors: dict[str, tuple[list[int], list[float]]] = {}
    candidate_dicts = [content]
    for subkey in ("weights", "tensors", "layers", "state_dict", "parameters"):
        if isinstance(content.get(subkey), dict):
            candidate_dicts.append(content[subkey])

    for d in candidate_dicts:
        for k, v in d.items():
            if isinstance(v, list) and v:
                if all(isinstance(x, (int, float)) for x in v):
                    tensors[str(k)] = ([len(v)], [float(x) for x in v])
                elif all(isinstance(row, list) and row and all(isinstance(x, (int, float)) for x in row) for row in v):
                    flat = [float(x) for row in v for x in row]
                    tensors[str(k)] = ([len(v), len(v[0])], flat)

    if tensors:
        _analyze_tensor_weights(tensors, rel_name, findings)


def _check_reference_baseline(
    model_dir: Path, scanned_files: list[Path], findings: list[dict[str, Any]]
) -> None:
    ref_file = model_dir / "reference.json"
    if not ref_file.exists():
        ref_file = model_dir / "baseline.json"
    if not ref_file.exists():
        return

    try:
        ref_data = json.loads(ref_file.read_text(encoding="utf-8"))
    except Exception:
        return

    expected_hashes: dict[str, str] = ref_data.get("sha256", {}) if isinstance(ref_data, dict) else {}
    for file_path in scanned_files:
        expected = expected_hashes.get(file_path.name)
        if expected:
            actual = _sha256_file(file_path)
            if actual.lower() != expected.lower():
                findings.append(
                    _make_finding(
                        rule_id="MDL-REF-HASH-MISMATCH",
                        obj=_rel_path(file_path, model_dir),
                        evidence=(
                            f"Контрольная сумма SHA-256 файла ({actual[:16]}…) не совпадает с эталонным значением "
                            f"из {ref_file.name} ({expected[:16]}…). Веса модели были модифицированы после обучения."
                        ),
                        severity="critical",
                        status="confirmed",
                        decision="Заблокировать сборку: обнаружена несанкционированная подмена весов относительно эталона.",
                        category="weight_backdoor",
                    )
                )


_REQUIREMENT = re.compile(r"([a-zA-Z0-9](?:[a-zA-Z0-9_.-]*[a-zA-Z0-9])?)(?:\s*\[[^\]]+\])?(.*)")
_NUMERIC_PIN = re.compile(r"==\s*(v?[0-9]{1,12}(?:\.[0-9]{1,12})*)(?:\s+--hash=[a-z0-9]+:[a-f0-9]+)*", re.I)


def canonical_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def release_tuple(version: str) -> tuple[int, ...]:
    parts = [int(part) for part in version.lower().removeprefix("v").split(".")]
    while len(parts) > 3 and parts[-1] == 0:
        parts.pop()
    return tuple(parts + [0] * max(0, 3 - len(parts)))


def read_numeric_pin(line: str) -> tuple[str, str | None] | None:
    """Return a package and declared plain release if the manifest provides one."""
    line = re.split(r"(?:^|\s+)#", line, maxsplit=1)[0].strip()
    if not line:
        return None
    requirement = _REQUIREMENT.fullmatch(line)
    if not requirement:
        return ("", None)  # includes, options, URLs and other unsupported forms
    package, specifier = requirement.groups()
    pin = _NUMERIC_PIN.fullmatch(specifier.strip())
    return package, pin.group(1) if pin else None


def dependency_entries(path: Path) -> Iterator[tuple[int | str, str]]:
    text = path.read_text(encoding="utf-8-sig")
    if path.name.lower() in {"pyproject.toml", "pipfile"}:
        manifest = tomllib.loads(text)
        if path.name.lower() == "pyproject.toml":
            project = manifest.get("project", {})
            optional = project.get("optional-dependencies", {})
            groups = [("project.dependencies", project.get("dependencies", []))]
            groups.extend((f"project.optional-dependencies[{index}]", entries)
                          for index, entries in enumerate(optional.values(), 1))
            for section, entries in groups:
                for index, entry in enumerate(entries, 1):
                    yield f"{section}[{index}]", entry
            if ({"dependencies", "optional-dependencies"} & set(project.get("dynamic", []))
                    or "poetry" in manifest.get("tool", {})):
                yield "project", "-unsupported-toml-dependencies"
        else:
            for table in ("packages", "dev-packages"):
                for index, (package, value) in enumerate(manifest.get(table, {}).items(), 1):
                    location = f"{table}[{index}]"
                    if isinstance(value, str):
                        yield location, package + value
                    elif isinstance(value, dict) and not (value.keys() - {"version", "extras"}):
                        yield location, package + value.get("version", "")
                    else:
                        yield location, package
        return
    if path.suffix.lower() in {".yml", ".yaml"}:
        # Conda uses a different ecosystem; do not match its versions to PyPI advisories.
        yield "dependencies", "-unsupported-conda-manifest"
        return
    pending = ""
    start = 1
    for line_no, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = line_no
        line = line.rstrip()
        if line.endswith("\\"):
            pending += line[:-1]
            continue
        yield start, pending + line
        pending = ""
    if pending:
        yield start, "-incomplete-requirement"


def dependency_version_message(location: str, package: str) -> str:
    name = f" для {package}" if package else ""
    return f"{location}: точная версия{name} не определена. Передайте lockfile для целевой среды."


def _scan_dependencies(
    dep_files: list[Path], base_dir: Path, findings: list[dict[str, Any]], warnings: list[dict],
    dependencies: list[dict],
) -> int:
    checked_packages = 0
    pins_by_file: dict[Path, set[str]] = {}
    if base_dir.is_file():
        base_dir = base_dir.parent
    for dep_file in dep_files:
        rel_dep = _rel_path(dep_file, base_dir)
        for entry_location, entry in dependency_entries(dep_file):
            location = f"{rel_dep}:{entry_location}"
            pin = read_numeric_pin(entry) if isinstance(entry, str) else ("", None)
            if pin is None:
                continue
            pkg_raw, ver_str = pin
            if ver_str is None:
                warnings.append({
                    "code": "DEPENDENCY_VERSION_UNRESOLVED", "blocking": False,
                    "object": location, "package": pkg_raw,
                    "message": dependency_version_message(location, pkg_raw),
                })
                continue
            pkg_norm = canonical_package_name(pkg_raw)
            ver_tuple = release_tuple(ver_str)
            checked_packages += 1
            dependencies.append({"file": rel_dep, "name": pkg_norm, "version": ver_str})
            pins_by_file.setdefault(dep_file, set()).add(f"{pkg_norm}=={ver_str}")

            for adv in OFFLINE_VULN_DB:
                if (pkg_norm != canonical_package_name(adv["package"])
                        or not adv.get("min_inclusive", (0,)) <= ver_tuple < adv["max_exclusive"]):
                    continue
                findings.append(
                    _make_finding(
                        rule_id=f"MDL-DEP-{adv['cve']}",
                        obj=f"{location} ({pkg_raw}=={ver_str})",
                        evidence=f"В манифесте заявлен pin '{pkg_raw}=={ver_str}', попадающий в диапазон {adv['cve']}: {adv['summary']}",
                        severity=adv["severity"],
                        status="confirmed",
                        decision=f"Обновить зависимость '{pkg_raw}' в {rel_dep} до версии >= {adv['fixed_in']}.",
                        category="dependency_vulnerability",
                    )
                )

    # The optional network scanner receives only sanitized pins, never the input manifest.
    pip_audit_bin = shutil.which("pip-audit") if os.environ.get("MLSEC_PIP_AUDIT") == "1" else None
    if pip_audit_bin:
        for dep_file, pins in pins_by_file.items():
            if not dep_file.name.startswith("requirements"):
                continue
            try:
                with TemporaryDirectory() as temporary:
                    pin_file = Path(temporary) / "requirements.txt"
                    pin_file.write_text("\n".join(sorted(pins)) + "\n", encoding="utf-8")
                    proc = subprocess.run(
                        [
                            pip_audit_bin, "-r", str(pin_file), "--no-deps", "--disable-pip",
                            "-f", "json", "--progress-spinner", "off",
                        ],
                        capture_output=True, text=True, timeout=15, check=False,
                    )
                if proc.stdout.strip().startswith("{"):
                    audit_data = json.loads(proc.stdout)
                    existing_ids = {f["id"] for f in findings}
                    for dep in audit_data.get("dependencies", []):
                        for vuln in dep.get("vulns", []):
                            vuln_id = vuln.get("id", "VULN")
                            rule_id = f"MDL-DEP-{vuln_id}"
                            if rule_id not in existing_ids:
                                fix_versions = ", ".join(vuln.get("fix_versions", [])) or "актуальной"
                                findings.append(
                                    _make_finding(
                                        rule_id=rule_id,
                                        obj=f"{_rel_path(dep_file, base_dir)} ({dep.get('name')}=={dep.get('version')})",
                                        evidence=vuln.get("description") or f"Обнаружена уязвимость {vuln_id} через pip-audit.",
                                        severity="high",
                                        status="confirmed",
                                        decision=f"Обновить пакет {dep.get('name')} до версии {fix_versions}.",
                                        category="dependency_vulnerability",
                                    )
                                )
            except Exception:
                pass

    return checked_packages


def scan(
    target_path: Path | str | None = None,
    requirements_path: Path | str | None = None,
    simulate_error: bool = False,
    *,
    constraint_paths: tuple[Path, ...] = (),
) -> dict[str, Any]:
    """
    Контур проверки ML-модели:
      1. Формат артефакта и статический анализ сериализации без исполнения кода (Pickle/PyTorch/SafeTensors/Keras/ONNX/HF).
      2. Статистический поиск закладок (backdoors/trojans) в весах и сверка с эталоном.
      3. Проверка зависимостей по базе уязвимостей (CVE).
    """
    if simulate_error or os.environ.get("MLSEC_SIMULATE_MODEL_ERROR") == "1":
        return {
            "id": "model",
            "status": "error",
            "message": "Сбой инструмента анализа модели (имитация ошибки сканера / повреждения среды исполнения).",
            "scanned_files": [],
            "findings": [],
        }

    if target_path:
        model_dir = Path(target_path)
    elif os.environ.get("MLSEC_MODEL_PATH"):
        model_dir = Path(os.environ["MLSEC_MODEL_PATH"])
    else:
        from backend.report import resolve_default_contour_dir
        model_dir = resolve_default_contour_dir("model")

    try:
        if not model_dir.exists():
            return {
                "id": "model",
                "status": "skipped",
                "message": f"Входной путь '{model_dir}' не существует. Проверка контура модели пропущена.",
                "scanned_files": [],
                "findings": [],
            }

        all_files = (
            [model_dir]
            if model_dir.is_file()
            else sorted(p for p in model_dir.rglob("*") if p.is_file())
        )

        # Отделяем служебные файлы (README.md, .gitkeep, reference.json)
        candidate_files = [
            p for p in all_files if p.name.lower() not in IGNORED_FILENAMES
        ]

        # Дополнительно проверяем корневой requirements.txt, если он передан явно
        dep_files = [p for p in candidate_files if p.name.lower() in DEPENDENCY_FILENAMES]
        if requirements_path:
            req_p = Path(requirements_path)
            if req_p.exists() and req_p not in dep_files:
                dep_files.append(req_p)
        elif (ROOT_DIR / "requirements.txt").exists() and model_dir == DEFAULT_MODEL_DIR:
            root_req = ROOT_DIR / "requirements.txt"
            if root_req not in dep_files:
                dep_files.append(root_req)
        for path in constraint_paths:
            if path.is_file() and path not in dep_files:
                dep_files.append(path)

        artifact_files = [p for p in candidate_files if p not in dep_files]

        if not artifact_files and not dep_files:
            return {
                "id": "model",
                "status": "skipped",
                "message": (
                    f"В папке '{_rel_path(model_dir, ROOT_DIR)}' отсутствуют входные артефакты модели и файлы зависимостей "
                    "(найден только шаблонный README.md). Поместите веса модели или запустите демо-набор."
                ),
                "scanned_files": [],
                "findings": [],
            }

        findings: list[dict[str, Any]] = []
        scanned_rel_files: list[str] = []
        unsupported_files: list[str] = []
        warnings: list[dict] = []
        weight_coverage = dict(values_total=0, values_inspected=0, tensors_total=0, tensors_inspected=0)
        has_compressed_input = False

        for file_path in artifact_files:
            rel_name = _rel_path(file_path, model_dir)
            scanned_rel_files.append(rel_name)
            ext = file_path.suffix.lower()

            if ext not in SUPPORTED_MODEL_EXTENSIONS:
                if os.environ.get("MLSEC_MODELSCAN") == "1":
                    has_compressed_input |= archive_type(file_path) is not None
                unsupported_files.append(rel_name)
                findings.append(
                    _make_finding(
                        rule_id="MDL-FMT-UNSUPPORTED",
                        obj=rel_name,
                        evidence=(
                            f"Файл '{rel_name}' имеет неподдерживаемый формат ('{ext or 'без расширения'}'). "
                            f"Поддерживаемые форматы: {', '.join(sorted(SUPPORTED_MODEL_EXTENSIONS))}."
                        ),
                        severity="medium",
                        status="needs_review",
                        decision="Конвертировать модель в поддерживаемый безопасный формат (.safetensors или .onnx) либо исключить посторонний файл.",
                        category="unsupported_format",
                    )
                )
                continue

            try:
                container = archive_type(file_path)
                has_compressed_input |= container is not None
                if container == "compressed":
                    raise ArchiveRejected("Этот тип сжатого контейнера не поддерживается для проверки модели.")
                if container == "zip":
                    with open_bounded_zip(file_path) as archive:
                        if ext in (".keras", ".h5", ".hdf5"):
                            _scan_keras_or_h5(file_path, rel_name, findings, archive)
                        elif ext in (".npy", ".npz"):
                            _scan_numpy_file(file_path, rel_name, findings, archive)
                        elif ext in (".pkl", ".pickle", ".dill", ".joblib", ".pt", ".pth", ".ckpt", ".bin", ".mar", ".zip"):
                            _scan_pytorch_zip(archive, rel_name, findings)
                        else:
                            raise ArchiveRejected("ZIP-контейнер не соответствует заявленному формату модели.")
                elif ext == ".safetensors":
                    _scan_safetensors_file(file_path, rel_name, findings, weight_coverage)
                elif ext in (".h5", ".hdf5", ".keras"):
                    _scan_keras_or_h5(file_path, rel_name, findings)
                elif ext == ".onnx":
                    _scan_onnx_file(file_path, rel_name, findings)
                elif ext in (".npy", ".npz"):
                    _scan_numpy_file(file_path, rel_name, findings)
                elif ext == ".json":
                    _scan_json_model_file(file_path, rel_name, findings)
                elif ext == ".zip":
                    raise ArchiveRejected("Файл не содержит читаемого ZIP-контейнера.")
                else:
                    raw_bytes = file_path.read_bytes()
                    floats = _inspect_pickle_stream(raw_bytes, rel_name, findings)
                    if len(floats) >= 4:
                        _analyze_tensor_weights({rel_name: ([len(floats)], floats)}, rel_name, findings)
            except ArchiveRejected as exc:
                findings.append(_make_finding(
                    "MDL-ARCHIVE-REJECTED", rel_name, str(exc), "high",
                    status="confirmed", category="archive_safety",
                    decision="Отклонить контейнер и запросить модель в безопасном формате.",
                ))
                warnings.append({"code": "ARCHIVE_REJECTED", "message": f"{rel_name}. {exc}", "blocking": True})

        if model_dir.is_dir():
            _check_reference_baseline(model_dir, artifact_files, findings)

        checked_deps = 0
        dependencies: list[dict] = []
        if dep_files:
            for df in dep_files:
                scanned_rel_files.append(_rel_path(df, model_dir))
            checked_deps = _scan_dependencies(dep_files, model_dir, findings, warnings, dependencies)

        if os.environ.get("MLSEC_MODELSCAN") == "1" and has_compressed_input:
            warnings.append({
                "code": "MODELSCAN_ARCHIVE_SKIPPED", "blocking": False,
                "message": "Для сжатых входов используется встроенный сканер с ограничениями распаковки.",
            })
        elif os.environ.get("MLSEC_MODELSCAN") == "1" and artifact_files:
            extra_findings, modelscan_warnings = scan_with_modelscan(model_dir)
            findings.extend(extra_findings)
            warnings.extend(modelscan_warnings)

        if unsupported_files and len(unsupported_files) == len(artifact_files) and not dep_files:
            status = "unsupported_format"
            message = f"Все входные файлы контура модели имеют неподдерживаемый формат: {', '.join(unsupported_files)}"
        else:
            status = "ok"
            message = (
                f"Проверено артефактов модели: {len(artifact_files)}, "
                f"пакетов зависимостей: {checked_deps}. Найдено проблем: {len(findings)}."
            )

        return {
            "id": "model",
            "status": status,
            "message": message,
            "scanned_files": scanned_rel_files,
            "findings": findings,
            "warnings": warnings,
            "weight_coverage": weight_coverage,
            "dependencies": dependencies,
        }

    except Exception as exc:
        return {
            "id": "model",
            "status": "error",
            "message": f"Внутренняя ошибка контура модели: {type(exc).__name__}: {exc}",
            "scanned_files": [],
            "findings": [],
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Сканер безопасности ML-модели (веса, сериализация, зависимости).")
    parser.add_argument("--path", type=Path, default=None, help="Путь к папке или файлу модели (по умолчанию model/)")
    parser.add_argument("--requirements", type=Path, default=None, help="Путь к файлу зависимостей")
    parser.add_argument("--simulate-error", action="store_true", help="Имитировать сбой сканера для проверки отчёта")
    args = parser.parse_args()

    result = scan(
        target_path=args.path,
        requirements_path=args.requirements,
        simulate_error=args.simulate_error,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
