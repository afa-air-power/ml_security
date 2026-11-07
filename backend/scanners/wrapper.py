from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
from enum import Enum, auto
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_WRAPPER_DIR = ROOT_DIR / "wrapper"

SUPPORTED_CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".sh",
    ".bash",
    ".yaml",
    ".yml",
    ".json",
    ".dockerfile",
}

IGNORED_FILENAMES = {
    "readme.md",
    ".gitkeep",
    ".gitignore",
    ".ds_store",
    "requirements.txt",
}


def _rel_path(path: Path, base_dir: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT_DIR.resolve()))
    except ValueError:
        try:
            return str(path.resolve().relative_to(base_dir.resolve()))
        except ValueError:
            return str(path)


def _make_finding(
    rule_id: str,
    obj: str,
    evidence: str,
    severity: str,
    status: str = "confirmed",
    decision: str = "",
    category: str = "sast",
) -> dict[str, Any]:
    if not decision:
        if severity in ("critical", "high"):
            decision = "Устранить уязвимость в коде обёртки перед деплоем сервиса инференса."
        else:
            decision = "Проверить контекст вызова и добавить валидацию входных данных."
    return {
        "id": rule_id,
        "contour": "wrapper",
        "category": category,
        "object": obj,
        "evidence": evidence,
        "severity": severity,
        "status": status,
        "decision": decision,
    }


def _get_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _get_call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _get_kwarg(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_constant_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_constant_false(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_dynamic_expr(node: ast.AST | None) -> bool:
    """Проверяет, формируется ли аргумент динамически (f-строка, конкатенация, переменная, вызов)."""
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return False
    return True


class _SQLValue(Enum):
    FIXED = auto()
    UNKNOWN = auto()
    INTERPOLATED = auto()


class PythonSecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, rel_file: str, lines: list[str]) -> None:
        self.rel_file = rel_file
        self.lines = lines
        self.findings: list[dict[str, Any]] = []
        self.aliases: dict[str, str] = {}
        self._sql_values: dict[str, _SQLValue] = {}

    def _sql_value(self, node: ast.AST | None) -> _SQLValue:
        match node:
            case ast.Constant():
                return _SQLValue.FIXED
            case ast.Name(id=name):
                return self._sql_values.get(name, _SQLValue.UNKNOWN)
            case ast.NamedExpr(value=value):
                return self._sql_value(value)
            case ast.Tuple(elts=values):
                if all(self._sql_value(value) is _SQLValue.FIXED for value in values):
                    return _SQLValue.FIXED
            case ast.JoinedStr(values=parts):
                return self._sql_interpolation(parts)
            case ast.FormattedValue(value=value, format_spec=spec):
                return self._sql_interpolation([value, *([spec] if spec is not None else [])])
            case ast.BinOp(left=left, op=ast.Add() | ast.Mod(), right=right):
                return self._sql_interpolation([left, right])
            case ast.Call(func=ast.Attribute(value=template, attr="format" | "format_map"),
                          args=args, keywords=keywords):
                return self._sql_interpolation([template, *args, *(kw.value for kw in keywords)])
            case ast.IfExp(body=body, orelse=other):
                return self._merge_sql_values(self._sql_value(body), self._sql_value(other))
        return _SQLValue.UNKNOWN

    def _sql_interpolation(self, values: list[ast.AST]) -> _SQLValue:
        return (_SQLValue.FIXED if all(self._sql_value(value) is _SQLValue.FIXED for value in values)
                else _SQLValue.INTERPOLATED)

    @staticmethod
    def _merge_sql_values(left: _SQLValue, right: _SQLValue) -> _SQLValue:
        if _SQLValue.INTERPOLATED in (left, right):
            return _SQLValue.INTERPOLATED
        return left if left is right else _SQLValue.UNKNOWN

    def _bind_sql_value(self, target: ast.AST, value: _SQLValue) -> None:
        if isinstance(target, ast.Name):
            self._sql_values[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_sql_value(element, _SQLValue.UNKNOWN)
        elif isinstance(target, ast.Starred):
            self._bind_sql_value(target.value, _SQLValue.UNKNOWN)

    def _visit_sql_scope(self, node: ast.AST) -> None:
        outer, self._sql_values = self._sql_values, {}
        try:
            self.generic_visit(node)
        finally:
            self._sql_values = outer

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = visit_Lambda = _visit_sql_scope

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        before = self._sql_values.copy()
        for stmt in node.body:
            self.visit(stmt)
        body, self._sql_values = self._sql_values, before
        for stmt in node.orelse:
            self.visit(stmt)
        other = self._sql_values
        self._sql_values = {
            name: self._merge_sql_values(body.get(name, _SQLValue.UNKNOWN),
                                         other.get(name, _SQLValue.UNKNOWN))
            for name in body.keys() | other.keys()
        }

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is not None:
            self._bind_sql_value(node.target, self._sql_value(node.value))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node)
        value = (_SQLValue.UNKNOWN if not isinstance(node.op, (ast.Add, ast.Mod))
                 else self._sql_interpolation([node.target, node.value]))
        self._bind_sql_value(node.target, value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.generic_visit(node)
        self._bind_sql_value(node.target, self._sql_value(node.value))

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def _loc(self, lineno: int) -> str:
        return f"{self.rel_file}:{lineno}"

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            asname = alias.asname or alias.name
            self.aliases[asname] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            asname = alias.asname or alias.name
            self.aliases[asname] = f"{mod}.{alias.name}" if mod else alias.name
        self.generic_visit(node)

    def _resolve_call_name(self, raw_name: str) -> str:
        if not raw_name:
            return ""
        parts = raw_name.split(".")
        first = parts[0]
        if first in self.aliases:
            resolved_first = self.aliases[first]
            return ".".join([resolved_first] + parts[1:])
        return raw_name

    def visit_Assign(self, node: ast.Assign) -> None:
        # Проверка захардкоженных секретов / API-ключей / токенов в присваиваниях
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value.strip()
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_lower = target.id.lower()
                    if any(
                        sec in var_lower
                        for sec in ("secret", "password", "passwd", "api_key", "apikey", "token", "private_key", "access_key")
                    ):
                        if len(val) >= 8 and not val.startswith(("$", "{", "YOUR_", "<", "env")):
                            masked = val[:4] + "..." + val[-2:] if len(val) > 8 else "***"
                            self.findings.append(
                                _make_finding(
                                    rule_id="WRP-SECRET-001",
                                    obj=self._loc(node.lineno),
                                    evidence=(
                                        f"В переменной '{target.id}' захардкожен секрет/токен ('{masked}'): "
                                        f"`{self._snippet(node.lineno)}`"
                                    ),
                                    severity="high",
                                    status="confirmed",
                                    decision="Вынести секреты и ключи API в переменные окружения (os.environ) или защищённое хранилище секретов CI/CD.",
                                    category="hardcoded_secret",
                                )
                            )
        self.generic_visit(node)
        value = self._sql_value(node.value)
        for target in node.targets:
            self._bind_sql_value(target, value)

    def visit_Call(self, node: ast.Call) -> None:
        raw_name = _get_call_name(node.func)
        call_name = self._resolve_call_name(raw_name)
        lineno = getattr(node, "lineno", 1)
        snippet = self._snippet(lineno)

        # 1. Прямое выполнение кода: eval / exec / compile
        if call_name in ("eval", "exec", "builtins.eval", "builtins.exec"):
            self.findings.append(
                _make_finding(
                    rule_id="WRP-RCE-EVAL",
                    obj=self._loc(lineno),
                    evidence=f"Использование опасного примитива '{call_name}()' позволяет выполнить произвольный Python-код: `{snippet}`",
                    severity="critical",
                    status="confirmed",
                    decision="Заменить eval()/exec() на безопасный парсинг (ast.literal_eval, json.loads) или строгий белый список операций.",
                    category="code_execution",
                )
            )

        # 2. Небезопасная десериализация Pickle / Dill / Marshal / Shelve / Joblib
        elif call_name in (
            "pickle.load",
            "pickle.loads",
            "_pickle.load",
            "_pickle.loads",
            "dill.load",
            "dill.loads",
            "marshal.load",
            "marshal.loads",
            "shelve.open",
            "joblib.load",
            "cloudpickle.load",
            "cloudpickle.loads",
        ):
            self.findings.append(
                _make_finding(
                    rule_id="WRP-DESER-PICKLE",
                    obj=self._loc(lineno),
                    evidence=(
                        f"Небезопасная десериализация через '{call_name}()': `{snippet}`. "
                        "Загрузка недоверенных данных или весов в формате Pickle приводит к RCE."
                    ),
                    severity="critical",
                    status="confirmed",
                    decision="Отказаться от pickle/joblib для загрузки моделей и входных запросов; использовать SafeTensors, ONNX или JSON.",
                    category="unsafe_deserialization",
                )
            )

        # 3. PyTorch torch.load без weights_only=True
        elif call_name == "torch.load" or raw_name.endswith(".torch.load"):
            weights_only_kw = _get_kwarg(node, "weights_only")
            if weights_only_kw is None or _is_constant_false(weights_only_kw):
                state_desc = "weights_only=False" if _is_constant_false(weights_only_kw) else "без параметра weights_only=True"
                self.findings.append(
                    _make_finding(
                        rule_id="WRP-ML-TORCHLOAD",
                        obj=self._loc(lineno),
                        evidence=(
                            f"Вызов 'torch.load()' {state_desc}: `{snippet}`. "
                            "По умолчанию используемый внутри Pickle-унпиклер выполняет произвольные команды из архива модели."
                        ),
                        severity="critical",
                        status="confirmed",
                        decision="Передать явно weights_only=True в torch.load(..., weights_only=True) и обновить PyTorch до >= 2.6.0, либо перейти на safetensors.torch.load_file().",
                        category="ml_supply_chain",
                    )
                )

        # 4. PyYAML yaml.load без SafeLoader
        elif call_name in ("yaml.load", "yaml.unsafe_load", "yaml.full_load"):
            loader_kw = _get_kwarg(node, "Loader")
            loader_name = _get_call_name(loader_kw) if loader_kw else ""
            if call_name == "yaml.unsafe_load" or "SafeLoader" not in loader_name:
                self.findings.append(
                    _make_finding(
                        rule_id="WRP-DESER-YAML",
                        obj=self._loc(lineno),
                        evidence=f"Небезопасный разбор YAML через '{call_name}()' без SafeLoader: `{snippet}`",
                        severity="high",
                        status="confirmed",
                        decision="Заменить вызов на yaml.safe_load() или передать Loader=yaml.SafeLoader.",
                        category="unsafe_deserialization",
                    )
                )

        # 5. HuggingFace trust_remote_code=True
        elif raw_name.endswith("from_pretrained") or call_name.endswith("from_pretrained"):
            trc_kw = _get_kwarg(node, "trust_remote_code")
            if _is_constant_true(trc_kw):
                self.findings.append(
                    _make_finding(
                        rule_id="WRP-ML-TRUST-REMOTE",
                        obj=self._loc(lineno),
                        evidence=(
                            f"Загрузка модели через '{raw_name}(..., trust_remote_code=True)': `{snippet}`. "
                            "Разрешает автоматическое скачивание и исполнение произвольных Python-скриптов из репозитория модели."
                        ),
                        severity="high",
                        status="confirmed",
                        decision="Установить trust_remote_code=False и зафиксировать проверенный commit-hash (revision) модели.",
                        category="ml_supply_chain",
                    )
                )

        # 6. Инъекция команд ОС (Command Injection)
        elif call_name in ("os.system", "os.popen", "posix.system", "commands.getoutput", "commands.getstatusoutput"):
            self.findings.append(
                _make_finding(
                    rule_id="WRP-CMD-OS-SYSTEM",
                    obj=self._loc(lineno),
                    evidence=f"Выполнение командной оболочки через '{call_name}()': `{snippet}`. Позволяет провести Command Injection при попадании внешних данных.",
                    severity="critical",
                    status="confirmed",
                    decision="Заменить os.system/os.popen на subprocess.run([...], shell=False) с передачей аргументов списком без оболочки.",
                    category="command_injection",
                )
            )
        elif call_name in (
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
        ):
            shell_kw = _get_kwarg(node, "shell")
            if _is_constant_true(shell_kw):
                self.findings.append(
                    _make_finding(
                        rule_id="WRP-CMD-SUBPROCESS-SHELL",
                        obj=self._loc(lineno),
                        evidence=f"Вызов '{call_name}(..., shell=True)': `{snippet}`. Запуск через shell уязвим к внедрению метасимволов (; | && ` $()).",
                        severity="high",
                        status="confirmed",
                        decision="Установить shell=False и передавать команду и её аргументы в виде списка строк.",
                        category="command_injection",
                    )
                )

        # 7. SQL-инъекция при динамическом формировании запроса
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany", "executescript"):
            query = node.args[0] if node.args else next(
                (kw.value for kw in node.keywords if kw.arg in ("operation", "query", "sql", "sql_script")), None
            )
            if self._sql_value(query) is _SQLValue.INTERPOLATED:
                self.findings.append(
                    _make_finding(
                        rule_id="WRP-SQLI-DYNAMIC",
                        obj=self._loc(lineno),
                        evidence=f"Динамическая сборка SQL-запроса через интерполяцию строк в '{raw_name}()': `{snippet}`",
                        severity="high",
                        status="needs_review",
                        decision="Передавать значения отдельно через параметры запроса; для идентификаторов использовать закрытый список.",
                        category="sql_injection",
                    )
                )

        # 8. SSRF / Загрузка внешних весов или URL по пользовательскому параметру
        elif call_name in (
            "requests.get",
            "requests.post",
            "requests.request",
            "urllib.request.urlopen",
            "urllib.request.urlretrieve",
            "httpx.get",
            "httpx.post",
        ):
            verify_kw = _get_kwarg(node, "verify")
            if _is_constant_false(verify_kw):
                self.findings.append(
                    _make_finding(
                        rule_id="WRP-NET-TLS-DISABLED",
                        obj=self._loc(lineno),
                        evidence=f"Отключена проверка TLS-сертификата (verify=False) в '{call_name}()': `{snippet}`",
                        severity="medium",
                        status="confirmed",
                        decision="Включить проверку сертификатов (verify=True) для защиты от перехвата (MITM) при скачивании весов/данных.",
                        category="network_security",
                    )
                )
            if node.args and _is_dynamic_expr(node.args[0]):
                arg_dump = ast.unparse(node.args[0]) if hasattr(ast, "unparse") else ""
                if any(tok in arg_dump.lower() for tok in ("url", "request", "user", "input", "param", "target", "webhook")):
                    self.findings.append(
                        _make_finding(
                            rule_id="WRP-SSRF-URL",
                            obj=self._loc(lineno),
                            evidence=(
                                f"Сетевой запрос '{call_name}()' использует динамический URL из внешнего параметра ('{arg_dump}'): `{snippet}`"
                            ),
                            severity="medium",
                            status="needs_review",
                            decision="Валидировать схему (https) и хост по белому списку доменов; заблокировать обращения к 127.0.0.1, 169.254.169.254 и внутренним подсетям.",
                            category="ssrf",
                        )
                    )

        # 9. Path Traversal при открытии файлов по внешнему имени
        elif call_name in ("open", "builtins.open", "io.open", "flask.send_file", "fastapi.responses.FileResponse"):
            if node.args and _is_dynamic_expr(node.args[0]):
                arg_dump = ast.unparse(node.args[0]) if hasattr(ast, "unparse") else ""
                if any(tok in arg_dump.lower() for tok in ("filename", "file_path", "user", "request", "query", "param", "path")):
                    if "basename" not in arg_dump and "resolve" not in arg_dump:
                        self.findings.append(
                            _make_finding(
                                rule_id="WRP-PATH-TRAVERSAL",
                                obj=self._loc(lineno),
                                evidence=(
                                    f"Открытие файла '{call_name}()' по невалидированному пути '{arg_dump}': `{snippet}`. "
                                    "Позволяет выйти за пределы рабочей директории через '../'."
                                ),
                                severity="high",
                                status="needs_review",
                                decision="Нормализовать путь через Path(base_dir, Path(user_name).name).resolve() и проверять .is_relative_to(base_dir).",
                                category="path_traversal",
                            )
                        )

        # 10. Запуск веб-сервера с debug=True
        elif raw_name.endswith(".run"):
            debug_kw = _get_kwarg(node, "debug")
            if _is_constant_true(debug_kw):
                self.findings.append(
                    _make_finding(
                        rule_id="WRP-WEB-DEBUG",
                        obj=self._loc(lineno),
                        evidence=f"Запуск веб-приложения с включённым отладчиком (debug=True): `{snippet}`. Открывает интерактивную консоль выполнения кода (Werkzeug Debugger).",
                        severity="high",
                        status="confirmed",
                        decision="Отключить debug=True в конфигурации запуска (debug=False).",
                        category="web_configuration",
                    )
                )

        # 11. Слабое хэширование (MD5 / SHA1) для проверки безопасности/паролей
        elif call_name in ("hashlib.md5", "hashlib.sha1"):
            self.findings.append(
                _make_finding(
                    rule_id="WRP-CRYPTO-WEAK-HASH",
                    obj=self._loc(lineno),
                    evidence=f"Использование криптографически слабого алгоритма '{call_name}()': `{snippet}`",
                    severity="low",
                    status="needs_review",
                    decision="Для проверки целостности весов ML-модели и токенов использовать hashlib.sha256().",
                    category="cryptography",
                )
            )

        self.generic_visit(node)


REGEX_RULES: list[dict[str, Any]] = [
    {
        "id": "WRP-SECRET-TOKEN",
        "pattern": re.compile(
            r"(hf_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{25,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
        ),
        "severity": "critical",
        "category": "hardcoded_secret",
        "desc": "В исходном коде обнаружен открытый токен доступа (HuggingFace / OpenAI / AWS / GitHub / Private Key)",
        "decision": "Немедленно отозвать скомпрометированный ключ, удалить его из истории Git и передавать через защищённые переменные CI/CD.",
    },
    {
        "id": "WRP-JS-XSS-EVAL",
        "extensions": {".js", ".ts"},
        "pattern": re.compile(r"\b(eval\s*\(|new\s+Function\s*\(| \.innerHTML\s*=|child_process\.exec\s*\()"),
        "severity": "high",
        "category": "code_execution",
        "desc": "Небезопасное выполнение кода или вставка неэкранированного HTML/команды в JS/TS-обёртке",
        "decision": "Использовать textContent вместо innerHTML и отказаться от eval/exec.",
    },
    {
        "id": "WRP-SH-CURL-PIPE",
        "extensions": {".sh", ".bash", ".dockerfile"},
        "pattern": re.compile(r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|python|python3)\b"),
        "severity": "high",
        "category": "supply_chain",
        "desc": "Загрузка и немедленное исполнение внешнего скрипта по сети (curl | bash) без проверки контрольной суммы",
        "decision": "Скачивать артефакты фиксированной версии, проверять SHA-256 и только после этого запускать.",
    },
]


def _scan_python_file(path: Path, rel_name: str, findings: list[dict[str, Any]]) -> None:
    source = path.read_text(encoding="utf-8", errors="replace")
    lines = source.splitlines()

    try:
        tree = ast.parse(source, filename=rel_name)
        visitor = PythonSecurityASTVisitor(rel_name, lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except SyntaxError as exc:
        findings.append(
            _make_finding(
                rule_id="WRP-SYNTAX-ERROR",
                obj=f"{rel_name}:{exc.lineno or 1}",
                evidence=f"Синтаксическая ошибка в Python-коде обёртки: {exc.msg}",
                severity="medium",
                status="confirmed",
                decision="Исправить синтаксическую ошибку в исходном файле обёртки.",
                category="code_quality",
            )
        )

    _scan_generic_patterns(rel_name, path.suffix.lower(), lines, findings)


def _scan_generic_patterns(
    rel_name: str, ext: str, lines: list[str], findings: list[dict[str, Any]]
) -> None:
    existing_locs = {(f["id"], f["object"]) for f in findings}
    for lineno, line in enumerate(lines, start=1):
        for rule in REGEX_RULES:
            allowed_exts = rule.get("extensions")
            if allowed_exts and ext not in allowed_exts:
                continue
            match = rule["pattern"].search(line)
            if match:
                loc = f"{rel_name}:{lineno}"
                if (rule["id"], loc) in existing_locs:
                    continue
                existing_locs.add((rule["id"], loc))
                matched_text = match.group(0)
                if len(matched_text) > 12 and "KEY" not in matched_text:
                    matched_text = matched_text[:6] + "..." + matched_text[-3:]
                findings.append(
                    _make_finding(
                        rule_id=rule["id"],
                        obj=loc,
                        evidence=f"{rule['desc']} ('{matched_text}'): `{line.strip()[:120]}`",
                        severity=rule["severity"],
                        status="confirmed",
                        decision=rule["decision"],
                        category=rule["category"],
                    )
                )


def _run_external_bandit(wrapper_dir: Path, findings: list[dict[str, Any]]) -> None:
    """Добавляет сигналы Bandit без исходных строк и с дедупликацией по правилу."""
    bandit_bin = shutil.which("bandit") if os.environ.get("MLSEC_BANDIT") != "0" else None
    if not bandit_bin:
        return
    try:
        proc = subprocess.run(
            [bandit_bin, "-r", str(wrapper_dir), "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if not proc.stdout.strip().startswith("{"):
            return
        data = json.loads(proc.stdout)
        covered = {(f["object"], f["id"]) for f in findings}
        sev_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        equivalents = {
            "B105": "WRP-SECRET-001", "B324": "WRP-CRYPTO-WEAK-HASH",
            "B602": "WRP-CMD-SUBPROCESS-SHELL", "B608": "WRP-SQLI-DYNAMIC",
        }

        for item in data.get("results", []):
            fname = Path(item.get("filename", ""))
            if not fname.resolve().is_relative_to(wrapper_dir.resolve()):
                continue
            rel = _rel_path(fname, wrapper_dir)
            lineno = item.get("line_number", 1)
            loc = f"{rel}:{lineno}"
            test_id = item.get("test_id", "")
            if not isinstance(test_id, str) or not re.fullmatch(r"B[0-9]{3}", test_id):
                continue
            rule = f"WRP-BANDIT-{test_id}"
            if (loc, equivalents.get(test_id)) in covered or (loc, rule) in covered:
                continue
            covered.add((loc, rule))
            sev = sev_map.get(str(item.get("issue_severity", "MEDIUM")).upper(), "medium")
            findings.append(
                _make_finding(
                    rule_id=rule,
                    obj=loc,
                    evidence=f"Bandit обнаружил конструкцию по правилу {test_id}. Исходная строка исключена.",
                    severity=sev,
                    status="needs_review",
                    decision="Проверить срабатывание правила Bandit и устранить небезопасную конструкцию.",
                    category="sast_bandit",
                )
            )
    except Exception:
        pass


def scan(
    target_path: Path | str | None = None,
    simulate_error: bool = False,
) -> dict[str, Any]:
    """
    Контур статического анализа кода-обёртки (SAST):
      - Выполняет AST-анализ Python-исходников и проверку шаблонов безопасности для скриптов запуска.
      - Работает строго по целевым исходникам обёртки.
      - Явно различает чистый прогон, находки, пропуск (нет файлов) и ошибку инструмента.
    """
    if simulate_error or os.environ.get("MLSEC_SIMULATE_WRAPPER_ERROR") == "1":
        return {
            "id": "wrapper",
            "status": "error",
            "message": "Сбой статического анализатора обёртки (имитация ошибки SAST-инструмента).",
            "scanned_files": [],
            "findings": [],
        }

    if target_path:
        wrapper_dir = Path(target_path)
    elif os.environ.get("MLSEC_WRAPPER_PATH"):
        wrapper_dir = Path(os.environ["MLSEC_WRAPPER_PATH"])
    else:
        from backend.report import resolve_default_contour_dir
        wrapper_dir = resolve_default_contour_dir("wrapper")

    try:
        if not wrapper_dir.exists():
            return {
                "id": "wrapper",
                "status": "skipped",
                "message": f"Целевая директория обёртки '{wrapper_dir}' не найдена. Проверка пропущена.",
                "scanned_files": [],
                "findings": [],
            }

        all_files = (
            [wrapper_dir]
            if wrapper_dir.is_file()
            else sorted(p for p in wrapper_dir.rglob("*") if p.is_file())
        )

        candidate_files = [
            p
            for p in all_files
            if p.name.lower() not in IGNORED_FILENAMES and "__pycache__" not in p.parts
        ]

        if not candidate_files:
            return {
                "id": "wrapper",
                "status": "skipped",
                "message": (
                    f"В папке '{_rel_path(wrapper_dir, ROOT_DIR)}' нет исходных файлов кода-обёртки "
                    "(найден только README.md). Поместите код обёртки в wrapper/ или загрузите демо-набор."
                ),
                "scanned_files": [],
                "findings": [],
            }

        findings: list[dict[str, Any]] = []
        scanned_rel_files: list[str] = []
        unsupported_files: list[str] = []

        for file_path in candidate_files:
            rel_name = _rel_path(file_path, wrapper_dir)
            scanned_rel_files.append(rel_name)
            ext = file_path.suffix.lower()
            if file_path.name.lower() == "dockerfile":
                ext = ".dockerfile"

            if ext not in SUPPORTED_CODE_EXTENSIONS:
                unsupported_files.append(rel_name)
                findings.append(
                    _make_finding(
                        rule_id="WRP-FMT-UNSUPPORTED",
                        obj=rel_name,
                        evidence=(
                            f"Файл '{rel_name}' имеет неподдерживаемое расширение '{ext or 'без расширения'}' для SAST-анализатора."
                        ),
                        severity="low",
                        status="needs_review",
                        decision="Проверить назначение файла в директории обёртки или подключить профильный анализатор.",
                        category="unsupported_format",
                    )
                )
                continue

            if ext == ".py":
                _scan_python_file(file_path, rel_name, findings)
            else:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
                _scan_generic_patterns(rel_name, ext, lines, findings)

        if wrapper_dir.is_dir():
            _run_external_bandit(wrapper_dir, findings)

        if unsupported_files and len(unsupported_files) == len(candidate_files):
            status = "unsupported_format"
            message = f"Все файлы в контуре обёртки имеют неподдерживаемый формат: {', '.join(unsupported_files)}"
        else:
            status = "ok"
            message = (
                f"Проверено файлов исходного кода: {len(candidate_files)}. "
                f"Обнаружено срабатываний SAST: {len(findings)}."
            )

        return {
            "id": "wrapper",
            "status": status,
            "message": message,
            "scanned_files": scanned_rel_files,
            "findings": findings,
        }

    except Exception as exc:
        return {
            "id": "wrapper",
            "status": "error",
            "message": f"Внутренняя ошибка SAST-анализатора обёртки: {type(exc).__name__}: {exc}",
            "scanned_files": [],
            "findings": [],
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="SAST-сканер безопасности кода-обёртки ML-модели.")
    parser.add_argument("--path", type=Path, default=None, help="Путь к исходникам обёртки (по умолчанию wrapper/)")
    parser.add_argument("--simulate-error", action="store_true", help="Имитировать сбой сканера для проверки отчёта")
    args = parser.parse_args()

    result = scan(target_path=args.path, simulate_error=args.simulate_error)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
