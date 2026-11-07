"""Демонстрационный сервис-обёртка ML-модели с дефектами безопасности."""
import sqlite3
import subprocess
import torch
import yaml
from transformers import AutoModel

HF_API_TOKEN = "hf_DemoSecretTokenForMosHubHackathon2026AbCdEf"

def load_legacy_pipeline(model_path: str, config_yaml: str):
    state = torch.load(model_path)
    cfg = yaml.load(config_yaml)
    backbone = AutoModel.from_pretrained("org/custom-bert", trust_remote_code=True)
    return state, cfg, backbone

def preprocess_user_input(user_expr: str, image_path: str):
    scale = eval(user_expr)
    subprocess.run(f"convert {image_path} -resize {scale}% out.png", shell=True)
    return scale

def log_prediction(conn: sqlite3.Connection, user_id: str, label: str):
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO audit_logs VALUES ('{user_id}', '{label}')")
