"""Scan one SFS scope. Contest inputs are data, never imported or executed."""
import argparse
import hashlib
import json
import os
import pickletools
import re
import sqlite3
import sys
from pathlib import Path

from backend import scan_ci
from backend.scanners import model, wrapper
from backend.sfs_dependencies import extra_dependencies
from backend.sfs_rules import cache_fixture_findings, docs_credential_findings, finding, model_fixture_findings, source_findings

SCOPES = ("model", "api", "cache", "executor", "llm")
PUBLIC_WEIGHT_SHA256 = "5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c"
PUBLIC_WEIGHT_REFERENCE = "https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct/blob/main/model.safetensors"
MODEL_EXTRAS = ("requirements.txt", "docker-constraints.txt", "Dockerfile")
RULES_WITH_SANITIZED_EVIDENCE = {
    "WRP-CRYPTO-WEAK-HASH": "MD5 используется для вычисления ключа записи кэша.",
    "WRP-SQLI-DYNAMIC": "Данные задачи интерполируются в SQL-строку вместо параметра запроса.",
    "WRP-CMD-SUBPROCESS-SHELL": "Динамическая команда передаётся subprocess с shell=True.",
    "MDL-KERAS-LAMBDA": "В HDF5 метаданные model_config содержат слой Keras Lambda и сериализованную функцию.",
    "MDL-ARCHIVE-REJECTED": "Контейнер отклонён проверкой безопасности распаковки. Причина указана в предупреждениях.",
}


def api_docs(root: Path) -> tuple[str, ...]:
    directory = root / "docs"
    if directory.is_symlink():
        raise ValueError("Символическая ссылка во входах: docs")
    if not directory.is_dir():
        return ()
    return tuple(sorted(entry.relative_to(root).as_posix()
                        for entry in directory.iterdir()
                        if entry.name.lower() == "readme.md" and (entry.is_file() or entry.is_symlink())))


def collect_inputs(scope: str, root: Path) -> dict[str, str]:
    names = ("model", *MODEL_EXTRAS) if scope == "model" else (f"src/{scope}",)
    if scope == "cache":
        names += ("docs/cache.db", "seed_cache.py")
    elif scope == "api":
        names += api_docs(root)
    digests = {}
    for name in names:
        path = root / name
        if any(parent.is_symlink() for parent in (path, *path.parents) if parent.is_relative_to(root)):
            raise ValueError(f"Символическая ссылка во входах: {name}")
        entries = sorted(path.rglob("*")) if path.is_dir() else [path]
        for entry in entries:
            rel = entry.relative_to(root).as_posix()
            if entry.is_symlink():
                raise ValueError(f"Символическая ссылка во входах: {rel}")
            if entry.is_file():
                with entry.open("rb") as stream:
                    digests[rel] = hashlib.file_digest(stream, "sha256").hexdigest()
    return digests


def scan_key(scope: str, inputs: dict[str, str]) -> str:
    base = Path(__file__).resolve().parent
    files = ("sfs_scan.py", "sfs_rules.py", "scan_ci.py")
    files += (("sfs_dependencies.py", *scan_ci.MODULES["model"])
              if scope == "model" else ("scanners/wrapper.py",))
    engine = [(name, hashlib.sha256((base / name).read_bytes()).hexdigest()) for name in files]
    return hashlib.sha256(json.dumps([scope, sys.version, inputs, engine], sort_keys=True).encode()).hexdigest()


def relative_object(value: str, root: Path, scope_dir: Path) -> str:
    prefix = scope_dir.relative_to(root).as_posix()
    value = value.removeprefix(f"{root}/")
    project = Path(__file__).resolve().parents[1]
    if root.is_relative_to(project) and root != project:
        value = value.removeprefix(root.relative_to(project).as_posix() + "/")
    local_prefix = scope_dir.as_posix() + "/"
    value = value.removeprefix(local_prefix)
    # A checkout may keep the export inside the scanner repository.
    if "/" + prefix + "/" in value:
        return prefix + "/" + value.split("/" + prefix + "/", 1)[1]
    if value.startswith(prefix + "/") or any(
        value == name or value.startswith(name + ":") or value.startswith(name + " (")
        for name in MODEL_EXTRAS
    ):
        return value
    return f"{prefix}/{value}"


def redact_base(raw: dict, root: Path, scope_dir: Path) -> dict:
    item = dict(raw)
    item["object"] = relative_object(raw["object"], root, scope_dir)
    rule = item["id"]
    evidence = RULES_WITH_SANITIZED_EVIDENCE.get(rule)
    if rule.startswith("MDL-PICKLE-"):
        operator = re.search(r"'((?:builtins\.eval|subprocess\.Popen|webbrowser\.open|shutil\.rmtree))'", raw["evidence"])
        suffix = f" для {operator.group(1)}" if operator else ""
        evidence = f"Статический разбор Pickle обнаружил опасный оператор{suffix}. Смещение указано в объекте."
    elif rule.startswith("MDL-DEP-"):
        match = re.search(r"\(([a-zA-Z0-9_.-]+==[vV]?[0-9.]+)\)", raw["object"])
        evidence = f"{match.group(1) if match else 'Зависимость из манифеста'} попадает в диапазон {rule.removeprefix('MDL-DEP-')}."
    elif rule.endswith("FMT-UNSUPPORTED"):
        evidence = "Для этого формата в выбранном контуре отсутствует анализатор."
    elif rule.startswith("MDL-BACKDOOR-") or rule == "MDL-WEIGHT-NONFINITE":
        evidence = "Статический сигнал. Числовые метрики и координаты доступны в point."
    item["evidence"] = evidence or "Сработало статическое правило. Подробности проверяются по указанному файлу и правилу."
    item["decision"] = "Сверить место с оригиналом и устранить выявленный механизм."
    item["status"] = "needs_review"
    if "cwe" not in item:
        if rule.startswith("MDL-PICKLE") or rule == "MDL-KERAS-LAMBDA":
            item["cwe"] = "CWE-502"
        elif rule == "WRP-SQLI-DYNAMIC":
            item["cwe"] = "CWE-89"
        elif rule == "WRP-CMD-SUBPROCESS-SHELL":
            item["cwe"] = "CWE-78"
        elif rule == "WRP-CRYPTO-WEAK-HASH":
            item["cwe"] = "CWE-328"
    return item


def model_extras(root: Path) -> list[dict]:
    target = root / "model"
    items = model_fixture_findings(target, root) + extra_dependencies(root)
    for path in sorted(target.glob("*tokenizer_config.json")):
        text = path.read_text(encoding="utf-8")
        config = json.loads(text)
        template = config.get("chat_template", "")
        if isinstance(template, str) and re.search(r"\b(?:ignore\s+(?:all\s+)?previous\s+instructions|YOU ARE HACKED)\b", template, re.I):
            line = next(i for i, text_line in enumerate(text.splitlines(), 1) if '"chat_template"' in text_line)
            hidden_network = all(word in template.lower() for word in ("head request", "telemetry", "hash"))
            evidence = "В chat_template вложена инструкция, перехватывающая системный контекст."
            if hidden_network:
                evidence += " Текст требует скрытого HEAD-запроса и передачи хеша разговора."
            items.append(finding("SYSTEM-PROMPT-INJECTION", f"model/{path.name}:{line}", evidence,
                                 "Восстановить доверенный шаблон и сверить его хеш с проверенной ревизией.",
                                 "high", 74, "model"))

    for path in sorted(target.glob("*.joblib")):
        if path.stat().st_size > 1024 * 1024:
            continue
        data = path.read_bytes()
        try:
            first_end = list(pickletools.genops(data))[-1][2] + 1
        except (ValueError, IndexError):
            continue
        for marker in re.finditer(rb"\x80[\x02-\x05]", data[first_end:]):
            offset = first_end + marker.start()
            try:
                ops = {op.name for op, _, _ in pickletools.genops(data[offset:])}
            except ValueError:
                continue
            if "REDUCE" in ops and ({"GLOBAL", "STACK_GLOBAL"} & ops):
                items.append(finding("JOBLIB-TRAILING-PICKLE", f"model/{path.name} (offset {offset})",
                                     "После STOP первого Pickle-потока находится второй поток с GLOBAL/STACK_GLOBAL и REDUCE.",
                                     "Карантинировать контейнер. При аудите разбирать все потоки без десериализации.", "high", 502, "model"))
                break
    return items


def scan_scope(scope: str, root: Path) -> dict:
    base = root / ("model" if scope == "model" else f"src/{scope}")
    if not base.is_dir():
        return error_result(scope, f"Каталог {base.relative_to(root)} отсутствует. Проверьте SFS_INPUT_DIR.")
    if scope == "model":
        raw = model.scan(base, requirements_path=root / "requirements.txt",
                         constraint_paths=(root / "docker-constraints.txt",))
        extra = model_extras(root)
    else:
        raw = wrapper.scan(base)
        extra = [item for path in sorted(base.rglob("*.py")) for item in source_findings(path, root)]
        if scope == "api":
            for name in api_docs(root):
                doc = root / name
                if doc.is_symlink():
                    raise ValueError("Символическая ссылка в документации API")
                extra.extend(docs_credential_findings(doc, base / "server.py", root))
        if scope == "cache":
            extra.extend(cache_fixture_findings(root))
            seed = root / "seed_cache.py"
            if seed.is_file():
                extra.extend(source_findings(seed, root))

    findings = []
    sampled = 0
    for item in raw["findings"]:
        safe = redact_base(item, root, base)
        if item.get("category") == "analysis_coverage":
            sampled += 1
        elif safe["object"] in {"model/merges.txt", "model/_fixtures/legacy_weights.py"} and item["id"] == "MDL-FMT-UNSUPPORTED":
            continue  # Tokenizer data and the separately AST-scanned Python fixture.
        elif item["id"] == "WRP-SECRET-001" and any(
            candidate["object"] == safe["object"] and candidate["id"] == "SFS-HARDCODED-CREDENTIAL"
            for candidate in extra
        ):
            continue
        else:
            findings.append(safe)

    warnings = []
    if sampled:
        warnings.append({"code": "SAMPLED_WEIGHTS", "blocking": False,
                         "message": f"Для {sampled} тензоров сработал лимит чтения или численного диапазона."})
    for warning in raw.get("warnings", []):
        if warning.get("code") == "DEPENDENCY_VERSION_UNRESOLVED":
            location = relative_object(warning["object"], root, base)
            warnings.append({"code": warning["code"], "blocking": False,
                             "message": model.dependency_version_message(location, warning["package"])})
        elif warning.get("code") == "ARCHIVE_REJECTED":
            warnings.append(warning)
    if any(warning.get("blocking") and warning.get("code") != "ARCHIVE_REJECTED"
           for warning in raw.get("warnings", [])):
        warnings.append({"code": "ANALYZER_ERROR", "blocking": True,
                         "message": "Дополнительный анализатор не завершил проверку."})

    return {"id": scope, "status": raw["status"], "message": f"Проверка {scope}: {raw['status']}.",
            "warnings": warnings, "findings": findings + extra,
            **({"weight_coverage": raw["weight_coverage"]} if "weight_coverage" in raw else {}),
            **({"dependencies": [
                {**entry, "file": relative_object(entry["file"], root, base)}
                for entry in raw["dependencies"]
            ]} if "dependencies" in raw else {}),
            "scanned_files": [relative_object(path, root, base) for path in raw["scanned_files"]]}


def error_result(scope: str, message: str) -> dict:
    return {"id": scope, "status": "error", "message": message, "findings": [], "scanned_files": []}


def run(scope: str, root: Path, cache: Path) -> dict:
    root = root.absolute()
    mode = "bypass"
    try:
        inputs = collect_inputs(scope, root)
        fingerprint = scan_key(scope, inputs)
        slot = cache / f"{scope}.json"
        use_cache = (os.environ.get("MLSEC_DISABLE_CACHE") != "1"
                     and not any(os.environ.get(name) == "1" for name in ("MLSEC_MODELSCAN", "MLSEC_PIP_AUDIT")))
        mode = "miss" if use_cache else "bypass"
        if use_cache:
            snapshot = scan_ci.read_snapshot(slot, fingerprint, scope)
            if snapshot is not None:
                return {**snapshot, "execution": {"cache": "hit", "fingerprint": fingerprint}}

        result = scan_scope(scope, root)
        if collect_inputs(scope, root) != inputs:
            return error_result(scope, "Входы изменились во время сканирования.")
        if scope == "model" and (actual := inputs.get("model/model.safetensors")):
            result["provenance"] = {"file": "model/model.safetensors", "sha256": actual,
                                    "reference": PUBLIC_WEIGHT_REFERENCE,
                                    "matches_reference": actual == PUBLIC_WEIGHT_SHA256}
            if actual != PUBLIC_WEIGHT_SHA256:
                result["findings"].append(finding(
                    "WEIGHTS-DRIFT", "model/model.safetensors",
                    "SHA-256 весов расходится с опубликованным эталоном SmolLM2-135M-Instruct.",
                    "Проверить источник и получить утверждённый эталон для этой версии весов.",
                    "high", 345, "model",
                ))
        for item in result["findings"]:
            path = next((name for name in inputs if item["object"] == name or any(
                item["object"].startswith(name + sep) for sep in (":", " ", " -> ")
            )), "")
            fields = [scope, item["id"], item["object"], item["evidence"], inputs.get(path, fingerprint)]
            item["key"] = hashlib.sha256(json.dumps(fields, ensure_ascii=True).encode()).hexdigest()
        if use_cache and result["status"] == "ok" and not any(w["blocking"] for w in result["warnings"]):
            try:
                scan_ci.write_snapshot(slot, fingerprint, result)
            except OSError:
                mode = "bypass"
        return {**result, "execution": {"cache": mode, "fingerprint": fingerprint}}
    except (OSError, ValueError, sqlite3.Error) as exc:
        return {**error_result(scope, f"Не удалось прочитать или проверить входы ({type(exc).__name__})."),
                "execution": {"cache": mode}}


def main():
    parser = argparse.ArgumentParser(description="Проверить один контур конкурса SFS.")
    parser.add_argument("scope", choices=SCOPES)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path(".sfs-cache"))
    args = parser.parse_args()
    for variable in ("MLSEC_MODELSCAN", "MLSEC_PIP_AUDIT", "MLSEC_BANDIT"):
        os.environ[variable] = "0"  # Official profile is offline and deterministic.
    report = run(args.scope, args.input, args.cache)
    print(json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2))
    print(f"{args.scope}: {report['status']}, cache={report.get('execution', {}).get('cache', 'bypass')}", file=sys.stderr)


if __name__ == "__main__":
    main()
