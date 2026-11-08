from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from backend.report import (
    EXAMPLES_DIR,
    build_report,
    ensure_examples_generated,
    populate_workspace,
    save_triage_override,
)
from backend.scanners import model, wrapper

ROOT_DIR = Path(__file__).resolve().parents[1]
FRONTEND = ROOT_DIR / "frontend"
STATIC_FILES = {
    "/": ("index.html", "text/html"),
    "/app.js": ("app.js", "text/javascript"),
    "/styles.css": ("styles.css", "text/css"),
}


def generate_report_for_preset(preset: str) -> dict:
    ensure_examples_generated()

    if preset == "sfs":
        return json.loads((ROOT_DIR / "docs/sfs-report.json").read_text(encoding="utf-8"))

    if preset == "artifact":
        artifact_path = ROOT_DIR / "report.json"
        if artifact_path.exists():
            return json.loads(artifact_path.read_text(encoding="utf-8"))

    if preset == "vulnerable":
        base = EXAMPLES_DIR / "vulnerable"
        return build_report(
            model.scan(target_path=base / "model"),
            wrapper.scan(target_path=base / "wrapper"),
        )
    if preset == "clean":
        base = EXAMPLES_DIR / "clean"
        return build_report(
            model.scan(target_path=base / "model"),
            wrapper.scan(target_path=base / "wrapper"),
        )
    if preset == "unsupported":
        base = EXAMPLES_DIR / "unsupported"
        return build_report(
            model.scan(target_path=base / "model"),
            wrapper.scan(target_path=base / "wrapper"),
        )
    if preset == "error":
        return build_report(
            model.scan(simulate_error=True),
            wrapper.scan(simulate_error=True),
        )
    if preset == "skipped":
        empty_dir = EXAMPLES_DIR / "_empty_probe"
        return build_report(
            model.scan(target_path=empty_dir),
            wrapper.scan(target_path=empty_dir),
        )

    return build_report(model.scan(), wrapper.scan())


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/health":
            self.send_json({"status": "ok"})
        elif path == "/api/report":
            preset = (query.get("preset") or ["workspace"])[0]
            self.send_json(generate_report_for_preset(preset))
        elif path in STATIC_FILES:
            name, content_type = STATIC_FILES[path]
            self.send_body((FRONTEND / name).read_bytes(), content_type)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        if self.headers.get_content_type() != "application/json":
            self.send_json({"error": "Ожидается application/json"}, status_code=415)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("Недопустимый размер запроса")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Ожидается объект")
        except (ValueError, RecursionError):
            self.send_json({"error": "Некорректный JSON"}, status_code=400)
            return

        if path == "/api/triage":
            finding_key = str(payload.get("key", "")).strip()
            status = str(payload.get("status", "needs_review")).strip()
            decision = str(payload.get("decision", "")).strip()
            severity = payload.get("severity")
            if not finding_key:
                self.send_json({"error": "Не указан ключ находки (key)"}, status_code=400)
                return
            entry = save_triage_override(
                finding_key=finding_key,
                status=status,
                decision=decision,
                severity=str(severity) if severity else None,
            )
            self.send_json({"status": "saved", "override": entry})
        elif path == "/api/workspace":
            preset = str(payload.get("preset", "vulnerable")).strip()
            try:
                copied = populate_workspace(preset)
                self.send_json({"status": "ok", "preset": preset, "copied": copied})
            except Exception as exc:
                self.send_json({"error": str(exc)}, status_code=400)
        else:
            self.send_error(404)

    def send_json(self, data: dict, status_code: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_body(body, "application/json", status_code=status_code)

    def send_body(self, body: bytes, content_type: str, status_code: int = 200) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Локальный интерфейс ML Security.")
    parser.add_argument("--port", default=8000, type=int)
    args = parser.parse_args()

    ensure_examples_generated()

    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
        print(f"ML Security: http://127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
