import json
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory


def scan_with_modelscan(path: Path) -> tuple[list[dict], list[dict]]:
    executable = shutil.which("modelscan")
    if executable is None:
        return [], [{"code": "MODELSCAN_UNAVAILABLE", "message": "ModelScan включён, но не найден в PATH.", "blocking": True}]

    try:
        with TemporaryDirectory() as temp:
            report_path = Path(temp) / "modelscan.json"
            result = subprocess.run(
                [executable, "-p", str(path), "-r", "json", "-o", str(report_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45, check=False,
            )
            if result.returncode == 3:
                return [], [{"code": "MODELSCAN_UNSUPPORTED", "message": "ModelScan не поддерживает эти входы. Использованы встроенные проверки.", "blocking": False}]
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(payload.get("issues"), list):
            raise ValueError("ModelScan report is missing issues")

        findings = []
        for issue in payload["issues"]:
            source = str(issue["source"])
            operator = f'{issue["module"]}.{issue["operator"]}'
            findings.append({
                "id": "MDL-MODELSCAN-OPERATOR", "contour": "model",
                "object": f"{source} :: {operator}", "severity": issue["severity"].lower(),
                "evidence": f"ModelScan обнаружил потенциально небезопасный оператор {operator}.",
                "category": "unsafe_serialization", "status": "needs_review",
                "decision": "Сверить оператор и контейнер с доверенным источником модели.",
            })
        warnings = []
        if result.returncode not in (0, 1) or payload.get("errors"):
            warnings.append({"code": "MODELSCAN_ERROR", "message": f"ModelScan завершился с ошибкой или неполным отчётом (код {result.returncode}).", "blocking": True})
        return findings, warnings
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.TimeoutExpired):
        return [], [{"code": "MODELSCAN_ERROR", "message": "ModelScan не вернул корректный JSON-отчёт или превысил лимит времени.", "blocking": True}]
