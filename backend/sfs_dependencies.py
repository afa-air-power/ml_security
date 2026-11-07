"""Small pinned offline advisory set for the competition manifests."""
import re
from pathlib import Path

from backend.scanners.model import canonical_package_name, dependency_entries, read_numeric_pin, release_tuple
from backend.sfs_rules import finding

EXTRA_ADVISORIES = (
    ("requests", (2, 3, 0), (2, 31, 0), "2023-32681", "Утечка Proxy-Authorization при отдельных перенаправлениях.", 200),
    ("urllib3", (0, 0, 0), (1, 26, 17), "2023-43804", "Заголовок Cookie может уйти на другой origin при перенаправлении.", 200),
)


def extra_dependencies(root: Path) -> list[dict]:
    issues = []
    for name in ("requirements.txt", "docker-constraints.txt"):
        path = root / name
        if not path.is_file():
            continue
        for line_number, line in dependency_entries(path):
            pin = read_numeric_pin(line)
            if not pin or pin[1] is None:
                continue
            package, version = pin
            v = release_tuple(version)
            for pkg, lower, fixed, cve, evidence, cwe in EXTRA_ADVISORIES:
                if canonical_package_name(package) == pkg and lower <= v < fixed:
                    issues.append(finding(
                        f"DEP-CVE-{cve}", f"{name}:{line_number}", f"{package}=={version}. {evidence}",
                        "Обновить pin, проверить разрешённые транзитивные зависимости и собрать новый образ.",
                        "medium", cwe, "model",
                    ))
    dockerfile = root / "Dockerfile"
    if dockerfile.is_file():
        for i, line in enumerate(dockerfile.read_text(encoding="utf-8").splitlines(), 1):
            if re.match(r"^\s*(?:RUN\s+)?pip\s+install\b", line, re.I) and re.search(
                r"""(['"])requests\s*>=\s*2\.31(?:\.0)?\s*,\s*<\s*2\.32(?:\.0)?\1""", line, re.I,
            ):
                issues.append(finding(
                    "DEP-DOCKER-CVE-2024-35195", f"Dockerfile:{i}",
                    "Второй pip install ограничивает requests диапазоном ниже исправления 2.32.0. Уязвимость зависит от verify=False в Session.",
                    "Убрать двухфазное разрешение и использовать единый lock с исправленной версией.", "medium", 295, "model",
                ))
    return issues
