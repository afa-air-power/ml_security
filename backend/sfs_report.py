"""Contest triage and strict gate. Verdicts are explicit and evidence-bound."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.decision_graph import build_graph
from backend.report import read_contour_report
from backend.scan_warnings import SEVERITIES, inspect_warnings
from backend.sfs_scan import SCOPES

STATUSES = ("true_positive", "false_positive", "accepted_risk")
ATTACK_PATHS = (
    ("Доступ к документам", ("SFS-DOC-PATH-TRAVERSAL",),
     ("GET /doc", "Параметр name", "Путь к файлу", "Чтение вне каталога при доступных правах")),
    ("Задача, кэш и исполнитель", ("WRP-SQLI-DYNAMIC", "SFS-CACHE-TRIGGER-SEED", "SFS-HIDDEN-COMMAND"),
     ("Текст задачи", "SQL-условие", "Строка из SQLite", "Служебная ветка исполнителя")),
    ("Промпт и исходящий запрос", ("SFS-SYSTEM-PROMPT-INJECTION", "SFS-OUTPUT-TRIGGERS-EGRESS"),
     ("Чат-шаблон", "Генерация вывода", "Условие по маркеру", "HEAD на фиксированный адрес")),
)


def build_report(raw_checks: list[dict], decisions: dict, metadata: dict | None = None) -> dict:
    checks = []
    findings = []
    warnings = []
    verdicts = dict.fromkeys((*STATUSES, "unresolved"), 0)
    severities = dict.fromkeys(sorted(SEVERITIES), 0)

    for raw in raw_checks:
        scope = raw["id"]
        scope_warnings = inspect_warnings(scope, raw)
        scope_findings = []
        for raw_item in raw.get("findings", []) if isinstance(raw.get("findings"), list) else []:
            if not isinstance(raw_item, dict) or not all(isinstance(raw_item.get(field), str) for field in (
                "id", "object", "evidence", "severity", "key",
            )) or raw_item["severity"] not in SEVERITIES:
                scope_warnings.append({"code": "INVALID_FINDING_KEY", "message": "Некорректная запись находки.",
                                       "contour": scope, "blocking": True, "finding_key": None})
                continue
            item = dict(raw_item)
            item["scope"] = scope
            entry = decisions.get(item["key"], {})
            status = entry.get("status") if isinstance(entry, dict) else None
            comment = entry.get("comment") if isinstance(entry, dict) else None
            if status in STATUSES and isinstance(comment, str) and comment.strip():
                item["status"] = status
                item["comment"] = comment.strip()
            else:
                item["status"] = "unresolved"
                item["comment"] = ""
            verdicts[item["status"]] += 1
            severities[item["severity"]] += 1
            scope_findings.append(item)

        scope_findings.sort(key=lambda item: (item["object"], item["id"]))
        findings.extend(scope_findings)
        warnings.extend(scope_warnings)
        checks.append({**raw, "findings": scope_findings, "findings_count": len(scope_findings),
                       "active_findings_count": sum(item["status"] == "unresolved" for item in scope_findings)})

    invalid = any(warning["blocking"] for warning in warnings)
    gate = not invalid and verdicts["unresolved"] == 0
    if invalid:
        reason = "Неполная проверка или ошибка отчёта. Откройте предупреждения."
    elif not gate:
        reason = f"Находки без статуса и обоснования: {verdicts['unresolved']}."
    else:
        reason = "У каждой находки есть решение триажа. Подтверждённые уязвимости остаются в отчёте."

    ids = {item["id"] for item in findings}
    paths = [{"title": title, "rules": list(rules), "steps": list(steps)}
             for title, rules, steps in ATTACK_PATHS if set(rules) <= ids]
    provenance = {"analysis": metadata or {}, "weights": raw_checks[0].get("provenance", {})}
    return {
        "schema_version": 1, "profile": "sfs", "provenance": provenance,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"overall_status": "error" if invalid else "passed" if gate else "blocked",
                    "gate_passed": gate, "gate_reason": reason, "total_findings": len(findings),
                    "blocking_findings_count": verdicts["unresolved"], "by_severity": severities, "by_status": verdicts},
        "checks": checks, "warnings": warnings, "attack_paths": paths,
        "decision_graph": build_graph(findings, warnings, gate, is_blocking=lambda item: item["status"] == "unresolved"),
    }


def markdown(report: dict) -> str:
    summary = report["summary"]
    lines = ["# Триаж конкурсного стенда Swordfish Security", "",
             "Проверка выполнена локально статическими методами. Обёртка, сериализованные объекты и модель не запускались.",
             "", f"**Находок:** {summary['total_findings']}. **Без решения:** {summary['blocking_findings_count']}.",
             "", "Политика CI проверяет полноту триажа. Открытые true positive требуют исправления перед эксплуатацией.", "",
             "| Контур | Правило | Место | CWE | Уровень | Статус | Доказательство и комментарий |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for check in report["checks"]:
        for item in check["findings"]:
            cells = [check["id"], item["id"], item["object"], item.get("cwe", "—"),
                     item["severity"], item["status"], f"{item['evidence']} {item['comment']}"]
            lines.append("| " + " | ".join(str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells) + " |")
    weights = report["provenance"]["weights"]
    if weights:
        lines.extend(["", "## Целостность весов", "",
                      f"SHA-256 файла `{weights['file']}` {'совпадает' if weights['matches_reference'] else 'расходится'} с опубликованным эталоном.",
                      f"`{weights['sha256']}` · [Метаданные Hugging Face]({weights['reference']})"])
    lines.extend(["", "## Покрытие", ""])
    for warning in report["warnings"]:
        lines.append(f"- **{warning['contour']}**. {warning['message']}")
    lines.extend(["", "## Связанные пути риска", ""])
    for path in report["attack_paths"]:
        lines.append(f"- **{path['title']}**. " + " → ".join(path["steps"]) + ".")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Объединить пять отчётов SFS и проверить решения триажа.")
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--triage", type=Path, default=Path("triage-sfs.json"))
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()

    checks = [read_contour_report(args.reports / f"{scope}.json", scope) for scope in SCOPES]
    metadata = {}
    try:
        registry = json.loads(args.triage.read_text(encoding="utf-8"))
        decisions = registry["decisions"]
        if not isinstance(decisions, dict):
            raise ValueError("decisions must be an object")
        metadata = registry.get("provenance", {})
    except (OSError, ValueError, KeyError, TypeError):
        decisions = {}
        checks[0].setdefault("warnings", []).append({
            "code": "TRIAGE_REGISTRY_ERROR", "blocking": True,
            "message": "Реестр триажа отсутствует или повреждён.",
        })
    report = build_report(checks, decisions, metadata)
    print(json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2))
    if args.markdown is not None:
        args.markdown.write_text(markdown(report), encoding="utf-8")
    if not report["summary"]["gate_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
