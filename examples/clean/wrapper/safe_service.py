"""Безопасная реализация сервиса инференса."""
import json
import os
import sqlite3
import subprocess
from pathlib import Path

API_TOKEN = os.environ.get("ML_SERVICE_TOKEN", "")

def parse_request(raw_body: str) -> dict:
    data = json.loads(raw_body)
    if not isinstance(data, dict):
        raise ValueError("Ожидается JSON-объект")
    return data

def resize_image_safe(image_name: str, base_dir: Path) -> Path:
    safe_path = (base_dir / Path(image_name).name).resolve()
    if not safe_path.is_relative_to(base_dir.resolve()):
        raise PermissionError("Выход за пределы директории запрещён")
    subprocess.run(["convert", str(safe_path), "-resize", "224x224", "out.png"], shell=False, check=False)
    return safe_path

def record_audit(conn: sqlite3.Connection, user_id: str, pred: float) -> None:
    cur = conn.cursor()
    cur.execute("INSERT INTO predictions (user_id, score) VALUES (?, ?)", (user_id, pred))
