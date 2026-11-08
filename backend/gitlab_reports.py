"""Export Swordfish findings in GitLab's native security report formats."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

SCHEMA_VERSION = "15.0.7"
SCANNER = {"id": "swordfish-sfs", "name": "Swordfish SFS",
           "version": "1.1.0", "vendor": {"name": "Swordfish SFS"}}
FILENAMES = {"sast": "gl-sast-report.json", "dependency_scanning": "gl-dependency-scanning-report.json"}
SOURCE_LINE = re.compile(r"^(.+?):([1-9][0-9]{0,8})(?= |$)")
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([vV]?[0-9]+(?:\.[0-9]+)*)(?=\)|\. |\s|$)")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
CWE = re.compile(r"CWE-([0-9]+)")


def source_prefix(input_root: Path | None, checkout: Path) -> str:
    if input_root is None:
        return ""
    root = input_root.resolve()
    checkout = checkout.resolve()
    if root == checkout or not root.is_relative_to(checkout):
        return ""
    return root.relative_to(checkout).as_posix()


def _project_path(value: str, prefix: str) -> str:
    path = PurePosixPath(value)
    if not path.parts or path.is_absolute() or ".." in path.parts or "\\" in value or any(ord(c) < 32 for c in value):
        raise ValueError("GitLab location must be a project-relative path.")
    return (PurePosixPath(prefix) / path).as_posix()


def _location(item: dict, paths: list[str], prefix: str) -> tuple[str, int | None]:
    obj = item["object"]
    for path in paths:
        if obj == path or any(obj.startswith(path + part) for part in (":", " (", " :: ", " -> ")):
            line = SOURCE_LINE.match(obj)
            return _project_path(path, prefix), int(line[2]) if line and line[1] == path else None
    line = SOURCE_LINE.match(obj)
    if line:
        return _project_path(line[1], prefix), int(line[2])
    path = re.split(r" :: | -> | \(", obj, maxsplit=1)[0]
    return _project_path(path, prefix), None


def _digest(data) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def _gitlab_vulnerability(item: dict, path: str, line: int | None):
    rule = item["id"]
    cve = CVE.search(rule)
    pin = PIN.search(item["object"]) or PIN.match(item["evidence"])
    is_dependency = cve is not None and pin is not None and "-DEP-" in rule
    rule_id = rule if line is not None or is_dependency else f"{rule}-{_digest(item['object'])[:16]}"
    identifiers = [{"type": "sfs_rule", "name": rule, "value": rule_id}]
    if cve:
        identifier = {"type": "cve", "name": cve[0], "value": cve[0],
                      "url": f"https://www.cve.org/CVERecord?id={cve[0]}"}
        if is_dependency:
            identifiers.insert(0, identifier)
        else:
            identifiers.append(identifier)
    if cwe := CWE.fullmatch(item.get("cwe") or ""):
        identifiers.append({"type": "cwe", "name": cwe[0], "value": cwe[1],
                            "url": f"https://cwe.mitre.org/data/definitions/{cwe[1]}.html"})

    kind = "dependency_scanning" if is_dependency else "sast"
    if is_dependency:
        dependency = {"package": {"name": pin[1].lower()}, "version": pin[2]}
        location = {"file": path, "dependency": dependency}
    else:
        location = {"file": path, "start_line": line or 1, "end_line": line or 1}
    details = {"sfs_object": {"type": "text", "name": "Место по данным SFS", "value": item["object"]},
               "sfs_triage": {"type": "text", "name": "Решение триажа SFS", "value": item["status"]}}
    if item.get("comment"):
        details["sfs_comment"] = {"type": "text", "name": "Обоснование триажа", "value": item["comment"]}
    finding = {
        "id": _digest([kind, identifiers[0]["value"], location]),
        "name": rule, "description": item["evidence"], "severity": item["severity"].capitalize(),
        "identifiers": identifiers, "location": location, "details": details,
    }
    if item.get("decision"):
        finding["solution"] = item["decision"]
    if (item.get("reference") or "").startswith("https://"):
        finding["links"] = [{"url": item["reference"]}]
    return kind, finding


def build_gitlab_reports(report: dict, started: datetime, prefix: str = "") -> dict:
    findings = {kind: {} for kind in FILENAMES}
    dependency_files: dict[str, dict[tuple[str, str], dict]] = {}
    for check in report["checks"]:
        paths = sorted(check.get("scanned_files", []), key=len, reverse=True)
        for item in check.get("dependencies", []):
            path = _project_path(item["file"], prefix)
            dep = {"package": {"name": item["name"]}, "version": item["version"]}
            dependency_files.setdefault(path, {})[item["name"], item["version"]] = dep
        for item in check["findings"]:
            if item["status"] == "false_positive":
                continue
            path, line = _location(item, paths, prefix)
            kind, finding = _gitlab_vulnerability(item, path, line)
            findings[kind][finding["id"]] = finding
            if kind == "dependency_scanning":
                dep = finding["location"]["dependency"]
                dependency_files.setdefault(path, {})[dep["package"]["name"], dep["version"]] = dep

    end = datetime.fromisoformat(report["generated_at"])
    start = min(started, end)
    result = {}
    for kind, items in findings.items():
        relevant = report["checks"] if kind == "sast" else [c for c in report["checks"] if c["id"] == "model"]
        scopes = {check["id"] for check in relevant}
        scan_warnings = [w for w in report["warnings"] if w["contour"] in scopes and w["code"] != "TRIAGE_REGISTRY_ERROR"]
        complete = bool(relevant) and all(c["status"] == "ok" for c in relevant)
        complete = complete and not any(w["blocking"] for w in scan_warnings)
        result[kind] = {
            "version": SCHEMA_VERSION,
            "scan": {
                "type": kind, "analyzer": SCANNER, "scanner": SCANNER,
                "status": "success" if complete else "failure",
                "start_time": start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
                "end_time": end.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
                "messages": [{"level": "fatal" if w["blocking"] else "warn",
                              "value": f"{w['code']}. {w['message']}"}
                             for w in scan_warnings],
            },
            "vulnerabilities": list(items.values()),
        }
    result["dependency_scanning"]["dependency_files"] = [
        {"path": path, "package_manager": "pip", "dependencies": list(packages.values())}
        for path, packages in sorted(dependency_files.items())
    ]
    return result


def write_gitlab_reports(directory: Path, report: dict, started: datetime, prefix: str) -> None:
    reports = build_gitlab_reports(report, started, prefix)
    directory.mkdir(parents=True, exist_ok=True)
    for kind, data in reports.items():
        (directory / FILENAMES[kind]).write_text(
            json.dumps(data, ensure_ascii=False, allow_nan=False, indent=2) + "\n", encoding="utf-8",
        )
