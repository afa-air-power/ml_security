"""Validate scan coverage and preserve tool warnings before report normalization."""

SEVERITIES = {"critical", "high", "medium", "low"}
CHECK_STATUSES = {"ok", "error", "skipped", "unsupported_format", "not_configured"}
INCOMPLETE_FINDINGS = {"WRP-SYNTAX-ERROR", "MDL-FMT-UNSUPPORTED", "WRP-FMT-UNSUPPORTED"}


def inspect_warnings(contour: str, result: dict) -> list[dict]:
    warnings = []

    def add(code: str, message: str, blocking: bool, finding_key: str | None = None) -> None:
        warnings.append({"code": code, "contour": contour, "message": message,
                         "blocking": blocking, "finding_key": finding_key})

    status = result.get("status")
    if not isinstance(status, str) or status not in CHECK_STATUSES:
        add("INVALID_CHECK_STATUS", "Отчёт содержит неизвестный статус сканера.", True)
    elif status != "ok":
        add(f"CHECK_{status.upper()}", str(result.get("message") or status), True)

    raw_warnings = result.get("warnings", [])
    if not isinstance(raw_warnings, list):
        add("INVALID_WARNING_LIST", "Поле warnings должно быть списком.", True)
    else:
        for item in raw_warnings:
            if (isinstance(item, dict) and isinstance(item.get("code"), str)
                    and isinstance(item.get("message"), str) and type(item.get("blocking")) is bool):
                add(item["code"], item["message"], item["blocking"])
            else:
                add("INVALID_WARNING", "Сканер вернул предупреждение без обязательных полей.", True)

    findings = result.get("findings")
    if not isinstance(findings, list):
        add("INVALID_FINDING_LIST", "Отчёт сканера не содержит корректный список находок.", True)
        return warnings

    for index, item in enumerate(findings):
        if not isinstance(item, dict) or not all(
            isinstance(item.get(field), str) and item[field].strip()
            for field in ("id", "object", "evidence", "severity")
        ) or item["severity"].lower() not in SEVERITIES:
            add("INVALID_FINDING", f"Находка №{index + 1} не содержит обязательных полей.", True)
            continue
        key = f'{item["id"]}::{item["object"]}'
        if item["id"] in INCOMPLETE_FINDINGS:
            add("PARTIAL_COVERAGE", item["evidence"], True, key)
        elif item.get("category") == "analysis_coverage":
            add("SAMPLED_INPUT", item["evidence"], False, key)

    return warnings
