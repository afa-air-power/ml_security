"""Offline, source-based rules for the SFS competition fixture."""
import ast
import re
import sqlite3
from pathlib import Path, PurePosixPath


def finding(rule, location, evidence, decision, severity, cwe, contour="wrapper"):
    return {
        "id": f"SFS-{rule}", "contour": contour, "object": location, "evidence": evidence,
        "decision": decision, "severity": severity, "status": "needs_review", "cwe": f"CWE-{cwe}",
    }


def _literal(node, names):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return names.get(node.id, "") if isinstance(node, ast.Name) else ""


def _operational_findings(tree, add):
    # Only use module-level literal bindings. Reassignment makes a name ambiguous.
    names = {}
    writes = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            writes[node.id] = writes.get(node.id, 0) + 1
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and writes[target.id] == 1:
                    names[target.id] = _literal(node.value, {})

    sqlite_aliases = {}
    process_aliases = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sqlite3":
                    sqlite_aliases[f"{alias.asname or alias.name}.connect"] = "connect"
                elif alias.name == "subprocess":
                    process_aliases[alias.asname or alias.name] = True
        if isinstance(node, ast.ImportFrom) and node.module == "sqlite3":
            for alias in node.names:
                if alias.name == "connect":
                    sqlite_aliases[alias.asname or alias.name] = "connect"

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if _literal(key, {}).lower() in {"host", "bind", "listen", "listen_address"} and _literal(value, names) in {"0.0.0.0", "::"}:
                    add("WILDCARD-BIND", value.lineno, "Сетевой адрес в конфигурации по умолчанию слушает на всех интерфейсах.",
                        "Ограничить интерфейс или явно настроить сетевые границы и проверить проброс порта.", "medium", 668)
        if not isinstance(node, ast.Call):
            continue
        func = ast.unparse(node.func)
        first = node.args[0] if node.args else None
        if func in sqlite_aliases:
            db_arg = first if first is not None else next((kw.value for kw in node.keywords if kw.arg == "database"), None)
            path = PurePosixPath(_literal(db_arg, names))
            if path.parent in {PurePosixPath("/tmp"), PurePosixPath("/var/tmp")}:
                add("SQLITE-SHARED-TEMP", node.lineno, "SQLite открывает предсказуемый файл непосредственно в общем временном каталоге.",
                    "Хранить базу в каталоге приложения с проверенными правами и владельцем.", "medium", 377)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in process_aliases:
            if node.func.attr in {"Popen", "run", "call", "check_call", "check_output"}:
                args = first if first is not None else next((kw.value for kw in node.keywords if kw.arg == "args"), None)
                shell = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
                override = any(kw.arg in ("executable", None) for kw in node.keywords)
                if isinstance(args, (ast.List, ast.Tuple)) and args.elts and not override and (shell is None or isinstance(shell, ast.Constant) and shell.value is False):
                    executable = _literal(args.elts[0], names)
                    if executable and "/" not in executable and "\\" not in executable:
                        add("SUBPROCESS-PATH-SEARCH", node.lineno, "Исполняемый файл задан без абсолютного пути и ищется в PATH.",
                            "Задать доверенный абсолютный путь и контролировать окружение процесса.", "low", 426)
        # Direct rfile.read(int(self.headers['Content-Length'])) with no bound in the expression.
        if re.fullmatch(r"\w+\.rfile\.read", func) and isinstance(first, ast.Call) and isinstance(first.func, ast.Name) and first.func.id == "int" and len(first.args) == 1:
            length = first.args[0]
            if isinstance(length, ast.Subscript) and isinstance(length.value, ast.Attribute) and length.value.attr == "headers" and _literal(length.slice, {}).lower() == "content-length":
                add("HTTP-BODY-UNBOUNDED", node.lineno, "Тело запроса читается целиком по длине из HTTP-заголовка без предела в выражении.",
                    "Проверять длину и ограничивать размер тела и время чтения до разбора JSON.", "medium", 400)


def source_findings(path: Path, root: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []  # The general SAST scanner reports coverage for this file.

    rel = path.relative_to(root).as_posix()
    issues = []

    def add(rule, line, evidence, decision, severity, cwe):
        issues.append(finding(rule, f"{rel}:{line}", evidence, decision, severity, cwe))

    _operational_findings(tree, add)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name) and re.search(r"(?:^|_)(?:token|secret|password|sign_key)(?:_|$)", target.id, re.I) and len(node.value.value) >= 8:
                    add("HARDCODED-CREDENTIAL", node.lineno, f"Строковый литерал в {target.id}. Значение скрыто.",
                        "Удалить секрет из исходников и истории, заменить значение и читать его из защищённой переменной.", "high", 798)
            if re.search(r"['\"]Authorization['\"]\s*:\s*['\"]Bearer ['\"]\s*\+[^\n]+\|\|\s*['\"][^'\"]+['\"]", node.value.value):
                match = next((i for i, line in enumerate(text.splitlines(), 1)
                              if "Authorization" in line and "||" in line), node.lineno)
                add("WEB-FALLBACK-TOKEN", match, "Клиентский HTML/JS содержит фиксированный запасной Bearer-токен.",
                    "Убрать резервное значение из HTML и требовать индивидуальную авторизацию.", "high", 798)

        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = list(ast.walk(node))
        for child in body:
            if isinstance(child, ast.If):
                guard = ast.unparse(child.test)
                guarded = list(ast.walk(ast.Module(body=child.body, type_ignores=[])))
                if node.name == "_authorized" and isinstance(child.test, ast.Compare) and any(
                    isinstance(n, ast.Constant) and isinstance(n.value, str)
                    for n in child.test.comparators
                ) and any(isinstance(n, ast.Return) and isinstance(n.value, ast.Constant) and n.value.value is True for n in guarded):
                    add("AUTH-BYPASS", child.lineno, "Сравнение с фиксированным токеном разрешает запрос до основной проверки.",
                        "Удалить исключение и проверять только токен из доверенной конфигурации.", "critical", 798)
                if node.name == "run_safe" and "cmd" in guard and any(
                    isinstance(n, ast.Call) and ast.unparse(n.func).startswith("subprocess.") for n in guarded
                ):
                    add("HIDDEN-COMMAND", child.lineno, "Особый маркер команды запускает отдельный системный вызов до allowlist.",
                        "Удалить скрытую ветку и маршрутизировать все операции через один валидатор.", "high", 912)
                if node.name == "suggest_command" and "HACKED_MARK" in guard and any(
                    isinstance(n, ast.Call) and ast.unparse(n.func) == "_telemetry" for n in guarded
                ):
                    add("OUTPUT-TRIGGERS-EGRESS", child.lineno,
                        "Маркер в выводе модели вызывает _telemetry. В этом модуле она отправляет HEAD на фиксированный внешний адрес.",
                        "Исключить сетевой побочный эффект из обработки вывода и ограничить исходящую сеть.", "medium", 200)
            if isinstance(child, ast.Compare) and isinstance(child.left, ast.Name) and any(
                isinstance(op, ast.In) for op in child.ops
            ) and any(isinstance(other, ast.Name) and other.id in {"cmd", "command"} for other in child.comparators):
                add("SUBSTRING-ALLOWLIST", child.lineno, "Разрешение по вхождению подстроки в команду. Первый аргумент и остальные аргументы отдельно не проверяются.",
                    "Проверять точное имя операции и схему аргументов. Использовать argv без shell.", "high" if node.name == "run_safe" else "medium", 184)
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr in {"read_text", "read_bytes"}:
                expression = child.func.value
                if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Div) and ast.unparse(expression.left) == "DOCS_DIR" and isinstance(expression.right, ast.Name):
                    add("DOC-PATH-TRAVERSAL", child.lineno, "Имя из query присоединяется к DOCS_DIR перед чтением. Проверка маршрута не ограничивает итоговый путь.",
                        "Разрешать конкретные имена документов или проверять resolve().is_relative_to() и тип файла.", "high", 22)
    return issues


def docs_credential_findings(doc: Path, server: Path, root: Path) -> list[dict]:
    if not doc.is_file() or not server.is_file():
        return []
    try:
        tree = ast.parse(server.read_text(encoding="utf-8"))
    except SyntaxError:
        return []
    tokens = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "API_TOKEN" for target in node.targets
        ):
            token = _literal(node.value, {})
            if len(token) >= 8:
                tokens.add(token)
    issues = []
    for line_no, text in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
        match = re.search(r"(?i)\bAuthorization:\s*Bearer\s+([A-Za-z0-9._~+/-]+=*)(?=[\s'\"]|$)", text)
        if match and match[1] in tokens:
            issues.append(finding(
                "DOC-CREDENTIAL-EXPOSURE", f"{doc.relative_to(root).as_posix()}:{line_no}",
                "Пример Authorization в документации повторяет зафиксированный ключ API. Значение скрыто.",
                "Удалить значение из документации и истории, ротировать ключ и использовать переменную окружения.",
                "high", 798,
            ))
    return issues


def model_fixture_findings(directory: Path, root: Path) -> list[dict]:
    result = []
    for path in sorted(directory.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            result.append(finding("FIXTURE-PARSE", path.relative_to(root).as_posix(),
                                  "Вспомогательный файл модели не разбирается как Python.",
                                  "Исправить файл или исключить его по правилам комплектации.", "low", 502, "model"))
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name not in {"__reduce__", "__reduce_ex__"}:
                continue
            for instruction in ast.walk(node):
                if not isinstance(instruction, ast.Return) or not isinstance(instruction.value, ast.Tuple) or not instruction.value.elts:
                    continue
                operator = ast.unparse(instruction.value.elts[0])
                if operator in {"eval", "exec", "Popen", "subprocess.Popen", "webbrowser.open", "shutil.rmtree"}:
                    result.append(finding(
                        "REDUCE-HOOK", f"{path.relative_to(root).as_posix()}:{instruction.lineno}",
                        f"Сериализационный hook возвращает вызываемый объект {operator}.",
                        "Удалить побочные эффекты из __reduce__ и хранить только данные безопасного формата.", "high", 502, "model",
                    ))
    return result


def cache_fixture_findings(root: Path) -> list[dict]:
    db = root / "docs/cache.db"
    if not db.is_file():
        return []
    uri = db.as_uri() + "?mode=ro&immutable=1"
    with sqlite3.connect(uri, uri=True) as connection:
        connection.execute("PRAGMA trusted_schema=OFF")
        count = connection.execute("SELECT count(*) FROM cache WHERE command = ?", ("echo PAYLOAD_EXECUTED",)).fetchone()[0]
    if not count:
        return []
    return [finding("CACHE-TRIGGER-SEED", "docs/cache.db",
                    f"В таблице cache найдено записей со служебным маркером исполнителя: {count}. База прочитана в режиме read-only.",
                    "Удалить запись из поставки. Связать HMAC с запросом и командой, использовать отдельный ключ.", "high", 912)]
