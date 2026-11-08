"""Compare external scanner JSON with the contest report without exporting raw evidence."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from backend.scanners.model import canonical_package_name, dependency_entries, read_numeric_pin, release_tuple

TOOLS = ("bandit", "semgrep", "gitleaks", "modelscan", "pip-audit")
BANDIT_LINKS = {
    "B104": {"SFS-WILDCARD-BIND"},
    "B105": {"SFS-HARDCODED-CREDENTIAL", "SFS-AUTH-BYPASS"},
    "B324": {"WRP-CRYPTO-WEAK-HASH"},
    "B602": {"WRP-CMD-SUBPROCESS-SHELL"},
    "B607": {"SFS-SUBPROCESS-PATH-SEARCH"},
    "B608": {"WRP-SQLI-DYNAMIC"},
}
ADVISORY_ID = re.compile(r"(?:CVE-\d{4}-\d{4,}|PYSEC-\d{4}-\d+|GHSA-[\da-z]{4}-[\da-z]{4}-[\da-z]{4}|BIT-[\da-z-]+)")
TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,200}")


def _rows(value):
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError("Invalid scanner result list")
    return value


def _token(value):
    if not isinstance(value, str) or not TOKEN.fullmatch(value):
        raise ValueError("Invalid rule ID")
    return value


def _file(root, value, *, model=False):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid scanner path")
    raw = Path(value)
    target = raw if raw.is_absolute() else root / ("model" if model else "") / raw
    if model and not raw.is_absolute() and raw.parts and raw.parts[0] == "model":
        target = root / raw
    resolved = target.resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError("Scanner file is outside the input or missing")
    return resolved.relative_to(root).as_posix()


def _line(value):
    if type(value) is not int or value <= 0:
        raise ValueError("Invalid source line")
    return value


def pin_entries(root):
    for manifest in ("requirements.txt", "docker-constraints.txt"):
        path = root / manifest
        if path.is_symlink():
            raise ValueError("Symlink in input manifests")
        if not path.is_file():
            continue
        for line, entry in dependency_entries(path):
            pin = read_numeric_pin(entry)
            if pin and pin[1] is not None:
                package, version = pin
                yield canonical_package_name(package), version, f"{manifest}:{line}"


def _audit_dependencies(root, data):
    pins = {}
    for package, version, location in pin_entries(root):
        pins.setdefault((package, release_tuple(version)), []).append(location)
    groups = {}
    raw = 0
    skipped = 0
    for dependency in _rows(data["dependencies"]):
        if "skip_reason" in dependency:
            skipped += 1
            continue
        package = canonical_package_name(_token(dependency["name"]))
        version = _token(dependency["version"])
        if not re.fullmatch(r"[vV]?[0-9]{1,12}(?:\.[0-9]{1,12})*", version):
            raise ValueError("pip-audit version is not a numeric pin")
        if (package, release_tuple(version)) not in pins:
            raise ValueError("pip-audit package or version does not match the input manifests")
        entries = groups.setdefault((package, version), [])
        for item in _rows(dependency["vulns"]):
            raw += 1
            aliases = item.get("aliases", [])
            fixes = item.get("fix_versions", [])
            if not isinstance(aliases, list) or not isinstance(fixes, list):
                raise ValueError("Invalid pip-audit advisory")
            ids = {value for value in [item["id"], *aliases]
                   if isinstance(value, str) and ADVISORY_ID.fullmatch(value)}
            if not ids:
                raise ValueError("Missing advisory ID")
            fix = {_token(value) for value in fixes}
            connected = [(other_ids, other_fix) for other_ids, other_fix in entries if ids & other_ids]
            for other_ids, other_fix in connected:
                entries.remove((other_ids, other_fix))
                ids.update(other_ids)
                fix.update(other_fix)
            entries.append((ids, fix))
    items = []
    for (package, version), entries in sorted(groups.items()):
        for ids, fixes in entries:
            primary = min(ids, key=lambda item: (not item.startswith("CVE-"), not item.startswith("GHSA-"), item))
            items.append({"rule": primary, "aliases": sorted(ids - {primary}), "package": package,
                          "version": version, "locations": pins[package, release_tuple(version)],
                          "listed_fixes": sorted(fixes)})
    return raw, skipped, sorted(items, key=lambda item: (item["package"], item["rule"]))


def normalize(tool, data, root):
    if tool == "pip-audit":
        raw, skipped, items = _audit_dependencies(root, data)
        return raw, skipped, items
    items = []
    if tool == "bandit":
        entries = _rows(data["results"])
        for item in entries:
            items.append({"rule": _token(item["test_id"]), "file": _file(root, item["filename"]),
                          "line": _line(item["line_number"]), "severity": _token(item["issue_severity"])})
    elif tool == "semgrep":
        entries = _rows(data["results"])
        for item in entries:
            # With --no-rewrite-rule-ids the report contains the original registry ID.
            items.append({"rule": _token(item["check_id"]), "file": _file(root, item["path"]),
                          "line": _line(item["start"]["line"])})
    elif tool == "gitleaks":
        entries = _rows(data)
        for item in entries:
            items.append({"rule": _token(item["RuleID"]), "file": _file(root, item["File"]),
                          "line": _line(item["StartLine"]), "last_line": _line(item["EndLine"])})
    elif tool == "modelscan":
        entries = _rows(data["issues"])
        for item in entries:
            module, operator = _token(item["module"]), _token(item["operator"])
            items.append({"rule": f"{module}.{operator}", "file": _file(root, item["source"], model=True),
                          "severity": _token(item["severity"])})
    else:
        raise ValueError("Unknown scanner")
    errors = len(_rows(data["errors"])) if tool in ("bandit", "semgrep", "modelscan") else 0
    return len(entries), errors, items


def _links(tool, item, findings):
    rule = item["rule"]
    result = []
    for candidate in findings:
        obj, rule_id = candidate["object"], candidate["id"]
        if tool == "pip-audit":
            matched = any(rule_id.endswith("-" + alias) for alias in (rule, *item["aliases"])) and any(
                obj == loc or obj.startswith(loc + " (") for loc in item["locations"]
            )
        elif tool == "modelscan":
            matched = (obj == item["file"] or obj.startswith(item["file"] + " (")) and (
                (rule == "Keras.Lambda" and rule_id == "MDL-KERAS-LAMBDA")
                or (rule_id.startswith("MDL-PICKLE-") and rule in candidate.get("evidence", ""))
            )
        else:
            ids = BANDIT_LINKS.get(rule, set()) if tool == "bandit" else (
                {"SFS-HARDCODED-CREDENTIAL", "SFS-DOC-CREDENTIAL-EXPOSURE"} if tool == "gitleaks" else
                {"WRP-CRYPTO-WEAK-HASH"} if rule.endswith(".insecure-hash-algorithm-md5") else
                {"WRP-CMD-SUBPROCESS-SHELL"} if rule.endswith(".subprocess-shell-true") else set()
            )
            path, _, line = obj.rpartition(":")
            matched = (rule_id in ids and path == item["file"] and line.isdecimal()
                       and item["line"] <= int(line) <= item.get("last_line", item["line"]))
        if matched:
            result.append({"rule": rule_id, "object": obj, "status": candidate["status"]})
    return result


def compare(root, report, external):
    root = root.resolve()
    findings = [item for check in report["checks"] for item in check["findings"]]
    results = {}
    for tool, payload in external.items():
        raw, errors, items = normalize(tool, payload, root)
        for item in items:
            item["links"] = _links(tool, item, findings)
        counts = Counter("linked" if item["links"] else "unreviewed" for item in items)
        results[tool] = {"raw_count": raw, "normalized_count": len(items), "errors_or_skips": errors,
                         "linked": counts["linked"], "unreviewed": counts["unreviewed"], "findings": items}
    return {"schema_version": 1, "tools": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--print-pins", action="store_true", help="Write only sanitized numeric pins for pip-audit")
    for tool in TOOLS:
        parser.add_argument("--" + tool, type=Path)
    args = parser.parse_args()
    try:
        external = {tool: json.loads(path.read_text(encoding="utf-8")) for tool in TOOLS
                    if (path := getattr(args, tool.replace("-", "_"))) is not None}
        if args.print_pins:
            if external or args.report is not None:
                raise ValueError("--print-pins is a separate operation")
            print("\n".join(sorted({f"{p}=={v}" for p, v, _ in pin_entries(args.input)})))
            return
        if not external:
            raise ValueError("Provide at least one scanner report")
        if args.report is None:
            raise ValueError("Provide the contest report")
        report = json.loads(args.report.read_text(encoding="utf-8"))
        print(json.dumps(compare(args.input, report, external), ensure_ascii=False, indent=2))
    except (OSError, TypeError, ValueError, KeyError):
        parser.error("Cannot read or validate reports; check JSON, paths and pinned versions")


if __name__ == "__main__":
    main()
