"""Small pinned offline advisory set for the competition manifests."""
import re
from pathlib import Path

from backend.scanners.model import canonical_package_name, dependency_entries, read_numeric_pin, release_tuple
from backend.sfs_rules import finding

EXTRA_ADVISORIES = (
    ("requests", (2, 3, 0), (2, 31, 0), "2023-32681", "Утечка Proxy-Authorization при отдельных перенаправлениях.", 200),
    ("urllib3", (0, 0, 0), (1, 26, 17), "2023-43804", "Заголовок Cookie может уйти на другой origin при перенаправлении.", 200),
)

# Reviewed after the pip-audit comparison. Keep upstream references and the
# conditions of exploitation; the check only proves that a declared pin matches.
REVIEWED_ADVISORIES = (
    ("requests", (0,), (2, 20, 0), "2018-18074", "Authorization сохраняется при HTTPS→HTTP перенаправлении на том же хосте.",
     319, "medium", "https://www.cve.org/CVERecord?id=CVE-2018-18074"),
    ("requests", (0,), (2, 32, 4), "2024-47081", "Специальный URL может раскрыть данные из .netrc.",
     200, "medium", "https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7"),
    ("requests", (0,), (2, 33, 0), "2026-25645", "Предсказуемый временный файл при прямом вызове extract_zipped_paths.",
     377, "medium", "https://github.com/psf/requests/security/advisories/GHSA-gc5v-m9x4-r6x2"),
    ("urllib3", (0,), (1, 26, 18), "2023-45803", "Тело запроса может сохраниться после ответа 303 и смены метода на GET.",
     200, "medium", "https://github.com/urllib3/urllib3/security/advisories/GHSA-g4mx-q9vg-27p4"),
    ("urllib3", (2, 0, 0), (2, 0, 7), "2023-45803", "Тело запроса может сохраниться после ответа 303 и смены метода на GET.",
     200, "medium", "https://github.com/urllib3/urllib3/security/advisories/GHSA-g4mx-q9vg-27p4"),
    ("transformers", (0,), (4, 48, 0), "2024-11393", "Небезопасная десериализация при конвертации MaskFormer.",
     502, "high", "https://www.zerodayinitiative.com/advisories/ZDI-24-1514/"),
    ("transformers", (0,), (4, 48, 0), "2024-11394", "Небезопасная десериализация при конвертации модели Trax.",
     502, "high", "https://www.zerodayinitiative.com/advisories/ZDI-24-1515/"),
    ("torch", (0,), (2, 10, 0), "2026-24747", "Повреждение памяти при загрузке специально созданного checkpoint с weights_only=True.",
     502, "high", "https://github.com/pytorch/pytorch/security/advisories/GHSA-63cw-57p8-fm3p"),
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
            for pkg, lower, fixed, cve, evidence, cwe, severity, reference in REVIEWED_ADVISORIES:
                if canonical_package_name(package) == pkg and lower <= v < fixed:
                    issue = finding(
                        f"DEP-CVE-{cve}", f"{name}:{line_number}", f"{package}=={version}. {evidence}",
                        f"Обновить зависимость до исправленной версии (от {'.'.join(map(str, fixed))} для этой ветки) и проверить lockfile.",
                        severity, cwe, "model",
                    )
                    issues.append({**issue, "reference": reference})
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
