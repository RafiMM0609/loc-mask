"""Configuration loader for PII-Shield."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8787
    log_level: str = "info"


@dataclass
class MaskingConfig:
    detect_secrets: bool = True
    detect_pii: bool = True
    detect_person_and_ip: bool = False
    placeholder_prefix: str = "<<PII:"
    placeholder_suffix: str = ">>"
    score_threshold: float = 0.45


@dataclass
class CustomPatternConfig:
    name: str
    pattern: str
    score: float = 0.9


@dataclass
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    masking: MaskingConfig = field(default_factory=MaskingConfig)
    allowlist_values: set[str] = field(default_factory=set)
    custom_patterns: list[CustomPatternConfig] = field(default_factory=list)


DEFAULT_ALLOWLIST = {
    "changeme",
    "password",
    "password123",
    "12345678",
    "1234567890",
    "your_api_key_here",
    "your-api-key-here",
    "sk-test-placeholder",
    "example@example.com",
    "test@example.com",
    "user@example.com",
    "admin@example.com",
    "null",
    "none",
    "true",
    "false",
    "undefined",
}


def load_config(config_path: Path | str | None = None) -> AppConfig:
    """Load configuration from YAML file with safe defaults."""
    env_path = os.environ.get("PII_SHIELD_CONFIG")
    path = Path(config_path or env_path or DEFAULT_CONFIG_PATH)

    raw: dict[str, Any] = {}
    if path.exists():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            raw = loaded

    srv_raw = raw.get("server", {}) or {}
    mask_raw = raw.get("masking", {}) or {}
    allow_raw = raw.get("allowlist", {}) or {}
    custom_raw = raw.get("custom_patterns", []) or []

    allow_values = {str(v).strip().lower() for v in (allow_raw.get("values") or DEFAULT_ALLOWLIST)}

    custom_patterns = [
        CustomPatternConfig(
            name=str(item["name"]).upper(),
            pattern=str(item["pattern"]),
            score=float(item.get("score", 0.9)),
        )
        for item in custom_raw
        if isinstance(item, dict) and item.get("name") and item.get("pattern")
    ]

    host = str(srv_raw.get("host", "127.0.0.1"))
    if host == "0.0.0.0":
        host = "127.0.0.1"

    return AppConfig(
        server=ServerConfig(
            host=host,
            port=int(srv_raw.get("port", 8787)),
            log_level=str(srv_raw.get("log_level", "info")),
        ),
        masking=MaskingConfig(
            detect_secrets=bool(mask_raw.get("detect_secrets", True)),
            detect_pii=bool(mask_raw.get("detect_pii", True)),
            detect_person_and_ip=bool(mask_raw.get("detect_person_and_ip", False)),
            placeholder_prefix=str(mask_raw.get("placeholder_prefix", "<<PII:")),
            placeholder_suffix=str(mask_raw.get("placeholder_suffix", ">>")),
            score_threshold=float(mask_raw.get("score_threshold", 0.45)),
        ),
        allowlist_values=allow_values,
        custom_patterns=custom_patterns,
    )
