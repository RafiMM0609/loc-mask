"""Tests for MaskingEngine, custom recognizers, allowlist, and 2-way vault."""

from __future__ import annotations

import pytest

from pii_shield.config import load_config
from pii_shield.engine import MaskingEngine


@pytest.fixture(scope="module")
def engine() -> MaskingEngine:
    return MaskingEngine(load_config())


@pytest.mark.parametrize(
    "sample,expected_type",
    [
        ("sk-proj-abcdefghijklmnopqrstuvwxyz123456", "OPENAI_API_KEY"),
        ("sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456", "ANTHROPIC_API_KEY"),
        ("AIzaSy" + "DaGmWKa4JsXZ-HjGw7ISLn_3nam123456", "GOOGLE_API_KEY"),
        ("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"),
        ("ghp_1234567890abcdefghijklmnopqrstuvwxyz", "GITHUB_TOKEN"),
        ("glpat-1234567890abcdefghij", "GITLAB_TOKEN"),
        ("xoxb-" + "123456789012-1234567890123-" + "abcdefghijklmnopqrstuvwx", "SLACK_TOKEN"),
        ("sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz1234", "STRIPE_KEY"),
        ("123456789:" + "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "TELEGRAM_TOKEN"),
        ("SB-Mid-server-" + "AbCdEfGhIjKlMnOpQrSt1234", "MIDTRANS_KEY"),
        ("xnd_development_AbCdEfGhIjKlMnOpQrStUvWxYz1234", "XENDIT_KEY"),
        ("hf_abcdefghijklmnopqrstuvwxyz12345678", "PACKAGE_TOKEN"),
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "JWT_TOKEN",
        ),
        ("Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9_token12345", "BEARER_TOKEN"),
        ("postgres://dbadmin:SuperSecretPass99@db.internal:5432/prod_db", "DB_URI"),
        ("password = 'RealProdPassword!99'", "SECRET_ASSIGNMENT"),
        ("DB_PASSWORD=RealDatabaseSecret99", "SECRET_ASSIGNMENT"),
        ("SMTP_SECRET=MailGatewaySecret88", "SECRET_ASSIGNMENT"),
        ("SMTP_HOST=smtp.gmail.com", "SECRET_ASSIGNMENT"),
        ("3273011508950001", "ID_NIK"),
        ("081234567890", "ID_PHONE"),
        ("+62 812-3456-7890", "ID_PHONE"),
        ("budi.santoso@company.co.id", "EMAIL_ADDRESS"),
        ("4532015112830366", "CREDIT_CARD"),
    ],
)
def test_detects_sensitive_entities(
    engine: MaskingEngine, sample: str, expected_type: str
) -> None:
    res = engine.mask_text(f"Data: {sample}", session_id="t-detect")
    assert expected_type in res.entity_types
    assert sample not in res.text
    assert "<<PII:" in res.text

    restored, count = engine.unmask_text(res.text, session_id="t-detect")
    assert count >= 1
    assert restored == f"Data: {sample}"


def test_private_key_block_masked_and_restored(engine: MaskingEngine) -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOgIBAAJBALk8EXAMPLEKEYMATERIAL1234567890\n"
        "-----END RSA PRIVATE KEY-----"
    )
    text = f"Key:\n{pem}\nEnd"
    res = engine.mask_text(text, session_id="t-pem")
    assert "PRIVATE_KEY" in res.entity_types
    assert "EXAMPLEKEYMATERIAL" not in res.text
    restored, _ = engine.unmask_text(res.text, session_id="t-pem")
    assert restored == text


def test_zero_false_positives_on_normal_code_and_allowlist(engine: MaskingEngine) -> None:
    code = (
        "import os\n"
        "api_key = os.getenv('OPENAI_API_KEY')\n"
        "password = 'changeme'\n"
        "host = '192.168.1.10'\n"
        "local = 'http://localhost:8787'\n"
        "contact = 'example@example.com'\n"
        "developer = 'Budi Santoso'\n"
    )
    res = engine.mask_text(code, session_id="t-clean")
    assert res.count == 0
    assert res.text == code


def test_deterministic_placeholder_and_no_double_masking(engine: MaskingEngine) -> None:
    secret = "sk-proj-deterministic1234567890abcdef"
    res1 = engine.mask_text(f"A={secret} and B={secret}", session_id="t-det")
    tokens = [w for w in res1.text.split() if "<<PII:" in w]
    assert len(tokens) == 2
    assert tokens[0].split("=")[1] == tokens[1].split("=")[1]

    # Masking an already masked string must leave placeholders untouched.
    res2 = engine.mask_text(res1.text, session_id="t-det")
    assert res2.count == 0
    assert res2.text == res1.text


def test_nested_payload_mask_and_unmask_skips_structural_keys(engine: MaskingEngine) -> None:
    payload = {
        "model": "gpt-6.1-sol",
        "id": "sk-proj-not-a-secret-structural-id-1234567890",
        "instructions": "Use postgres://admin:SecretPass123@prod.db:5432/app",
        "input": [
            {
                "role": "user",
                "content": "My NIK is 3273011508950001 and email is dev@perusahaan.id",
            }
        ],
    }
    masked, types = engine.mask_payload(payload, session_id="t-json")
    assert masked["model"] == "gpt-6.1-sol"
    assert masked["id"] == payload["id"]
    assert "SecretPass123" not in masked["instructions"]
    assert "3273011508950001" not in masked["input"][0]["content"]
    assert "dev@perusahaan.id" not in masked["input"][0]["content"]
    assert {"DB_URI", "ID_NIK", "EMAIL_ADDRESS"}.issubset(set(types))

    unmasked, restored_count = engine.unmask_payload(masked, session_id="t-json")
    assert restored_count >= 3
    assert unmasked == payload
