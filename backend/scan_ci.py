"""A separate content-addressed snapshot for each scanner."""
import argparse
import hashlib
import importlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile

ROOT = Path(__file__).resolve().parents[1]
MODULES = {
    "model": ("scanners/model.py", "weight_points.py", "weight_stream.py", "archive_limits.py", "modelscan_adapter.py"),
    "wrapper": ("scanners/wrapper.py",),
}


def fingerprint(contour: str, target: Path, tool_id: str = "") -> str:
    def file_digest(path: Path) -> str:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    if target.is_symlink():
        raise ValueError("Символические ссылки во входных данных CI не поддерживаются.")
    entries = sorted(target.rglob("*")) if target.is_dir() else [target]
    if any(entry.is_symlink() for entry in entries):
        raise ValueError("Символические ссылки во входных данных CI не поддерживаются.")
    files = [(str(entry.relative_to(target)), file_digest(entry)) for entry in entries if entry.is_file()]
    backend = ROOT / "backend"
    engine = [(name, file_digest(backend / name)) for name in ("scan_ci.py", *MODULES[contour])]
    if contour == "model" and target == ROOT / "model":
        root_requirements = ROOT / "requirements.txt"
        if root_requirements.is_file():
            engine.append(("requirements.txt", file_digest(root_requirements)))
    target_id = str(target.relative_to(ROOT)) if target.is_relative_to(ROOT) else str(target)
    payload = (contour, target_id, target.is_dir(), target.is_file(), files, engine, sys.version, tool_id)
    return hashlib.sha256(json.dumps(payload, ensure_ascii=True).encode()).hexdigest()


def snapshot_digest(result: dict) -> str:
    payload = json.dumps(result, sort_keys=True, allow_nan=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def read_snapshot(path: Path, key: str, contour: str) -> dict | None:
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
        result = snapshot["result"]
        if (snapshot["key"] == key and snapshot["digest"] == snapshot_digest(result)
                and result["id"] == contour
                and result["status"] in {"ok", "unsupported_format"}
                and isinstance(result["findings"], list)
                and isinstance(result["scanned_files"], list)):
            return result
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def write_snapshot(path: Path, key: str, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump({"key": key, "digest": snapshot_digest(result), "result": result},
                      stream, ensure_ascii=False, allow_nan=False)
            stream.close()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def modelscan_image(contour: str) -> str:
    if contour != "model" or os.environ.get("MLSEC_MODELSCAN") != "1":
        return ""
    image = os.environ.get("CI_JOB_IMAGE", "")
    if (image == os.environ.get("MLSEC_MODEL_IMAGE")
            and re.search(r"@sha256:[0-9a-f]{64}$", image)
            and shutil.which("modelscan")):
        return image
    return ""


def run(contour: str, target: Path, cache_dir: Path) -> dict:
    target = target.absolute()
    image = modelscan_image(contour)
    state = "bypass"
    try:
        if cache_dir.absolute().is_relative_to(target):
            raise ValueError("Кэш должен лежать вне каталога входных данных.")
        start_key = fingerprint(contour, target, image)
    except (OSError, ValueError) as exc:
        return {"id": contour, "status": "error", "findings": [], "scanned_files": [],
                "message": str(exc), "execution": {"cache": state}}

    external = (
        os.environ.get("MLSEC_PIP_AUDIT") == "1" or (os.environ.get("MLSEC_MODELSCAN") == "1" and not image)
        if contour == "model" else os.environ.get("MLSEC_BANDIT") != "0" and bool(shutil.which("bandit"))
    )
    bypass = (external or os.environ.get("MLSEC_DISABLE_CACHE") == "1"
              or os.environ.get(f"MLSEC_SIMULATE_{contour.upper()}_ERROR") == "1")
    snapshot = cache_dir / f"{contour}.json"
    if not bypass:
        state = "miss"
        previous = read_snapshot(snapshot, start_key, contour)
        if previous is not None:
            return {**previous, "execution": {"cache": "hit", "fingerprint": start_key}}

    scanner = importlib.import_module(f"backend.scanners.{contour}")
    result = scanner.scan(target_path=target)
    try:
        if fingerprint(contour, target, image) != start_key:
            return {"id": contour, "status": "error", "findings": [], "scanned_files": [],
                    "message": "Входные данные изменились во время сканирования.",
                    "execution": {"cache": "bypass"}}
    except (OSError, ValueError):
        return {"id": contour, "status": "error", "findings": [], "scanned_files": [],
                "message": "Не удалось перепроверить входные данные после сканирования.",
                "execution": {"cache": "bypass"}}
    if (not bypass and result["status"] in {"ok", "unsupported_format"}
            and not any(warning["blocking"] for warning in result.get("warnings", []))):
        try:
            write_snapshot(snapshot, start_key, result)
        except (OSError, ValueError):
            state = "bypass"
    return {**result, "execution": {"cache": state, "fingerprint": start_key}}


def main() -> None:
    parser = argparse.ArgumentParser(description="Запустить один контур с независимым кэшем CI.")
    parser.add_argument("contour", choices=MODULES)
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, default=Path(".mlsec-cache"))
    args = parser.parse_args()
    result = run(args.contour, args.path, args.cache_dir)
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
    print(f"{args.contour}: {result['execution']['cache']}", file=sys.stderr)


if __name__ == "__main__":
    main()
