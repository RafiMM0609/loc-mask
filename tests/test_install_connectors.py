"""Migration checks for automatic Codex masking and preserving user settings."""

from __future__ import annotations

import json
import tomllib

import pytest

from connectors import install_connectors as installer


@pytest.fixture
def codex_paths(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    hooks = tmp_path / "hooks.json"
    monkeypatch.setattr(installer, "CODEX_CONFIG", config)
    monkeypatch.setattr(installer, "CODEX_HOOKS", hooks)
    return config, hooks


def _proxy_block() -> str:
    return (
        f"{installer.CODEX_PROVIDER_START}\n"
        '[model_providers.pii-shield]\n'
        'base_url = "http://127.0.0.1:8787/chatgpt-backend/codex"\n'
        f"{installer.CODEX_PROVIDER_END}\n"
    )


@pytest.mark.parametrize("existing_config", [None, 'model_provider = "custom"\n'])
def test_codex_fresh_install_is_idempotent(codex_paths, existing_config) -> None:
    config, hooks = codex_paths
    if existing_config is not None:
        config.write_bytes(existing_config.encode())

    installer.apply_codex(dry_run=True)
    assert not hooks.exists()
    assert not installer._codex_checkpoint().exists()
    installer.apply_codex(dry_run=False)
    assert installer._is_codex_hooks_active(hooks)
    backup = installer._codex_checkpoint().read_bytes()
    installed = hooks.read_bytes()
    installer.apply_codex(dry_run=False)
    assert hooks.read_bytes() == installed
    assert installer._codex_checkpoint().read_bytes() == backup

    installer.rollback_codex()
    assert not hooks.exists()
    assert installer._read_optional(config) == existing_config


@pytest.mark.parametrize("previous_provider", [None, "custom"])
def test_codex_migration_and_scoped_rollback(codex_paths, previous_provider) -> None:
    config, hooks = codex_paths
    settings = 'model = "test-model"\n[model_providers.custom]\nname = "Custom"\n'
    restored_selector = f'model_provider = "{previous_provider}"\n' if previous_provider else ""
    pre_proxy = restored_selector + settings
    config.with_name("config.toml.bak.before-proxy").write_text(pre_proxy, encoding="utf-8")
    before = 'model_provider = "pii-shield"\n' + settings + _proxy_block() + "[windows]\nsandbox = 'elevated'\n"
    config.write_bytes(before.replace("\n", "\r\n").encode())
    third_party = {"type": "command", "command": "other-hook"}
    old = {"hooks": {
        "UserPromptSubmit": [{"hooks": [
            third_party, {"command": "python /ps/connectors/codex/codex_proxy_start.py"},
        ]}],
        "PreToolUse": [{"hooks": [{"command": "python /ps/connectors/codex/codex_tool_guard.py"}]}],
        "PostToolUse": [{"hooks": [{"command": "python /ps/connectors/codex/codex_output_guard.py"}]}],
    }}
    hooks.write_text(json.dumps(old), encoding="utf-8")
    config_bytes, hooks_bytes = config.read_bytes(), hooks.read_bytes()

    installer.apply_codex(dry_run=True)
    assert config.read_bytes() == config_bytes
    assert hooks.read_bytes() == hooks_bytes

    installer.apply_codex(dry_run=False)
    merged = json.loads(hooks.read_text(encoding="utf-8"))["hooks"]
    assert third_party in merged["UserPromptSubmit"][0]["hooks"]
    assert "PreToolUse" not in merged
    assert "codex_shell_output_guard.py" in str(merged["PostToolUse"])
    assert "codex_proxy_start.py" not in str(merged)
    assert installer._is_codex_hooks_active(hooks)
    after = config.read_bytes().decode()
    assert "\r\n" in after
    parsed = tomllib.loads(after)
    assert parsed.get("model_provider") == previous_provider
    assert "pii-shield" not in parsed["model_providers"]
    assert parsed["windows"]["sandbox"] == "elevated"

    installer.rollback_codex(dry_run=True)
    assert config.read_bytes().decode() == after
    installer.rollback_codex()
    assert config.read_bytes() == config_bytes
    assert hooks.read_bytes() == hooks_bytes


def test_codex_ambiguous_migration_leaves_files_intact(codex_paths) -> None:
    config, hooks = codex_paths
    settings = 'model = "test-model"\n'
    before = 'model_provider = "pii-shield"\n' + settings + _proxy_block()
    config.write_text(before, encoding="utf-8")
    for name in ("openai", "custom"):
        config.with_name(f"config.toml.bak.{name}").write_text(
            f'model_provider = "{name}"\n' + settings, encoding="utf-8"
        )

    for dry_run in (True, False):
        with pytest.raises(ValueError, match="tidak dapat dipastikan"):
            installer.apply_codex(dry_run=dry_run)
    assert config.read_text(encoding="utf-8") == before
    assert not hooks.exists()
    assert not installer._codex_checkpoint().exists()


def test_codex_rollback_preserves_config_edits(codex_paths) -> None:
    config, hooks = codex_paths
    config.write_text('model_provider = "pii-shield"\n' + _proxy_block(), encoding="utf-8")
    installer.apply_codex(dry_run=False)
    config.write_text('model = "new-model"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="berubah"):
        installer.rollback_codex()
    assert config.read_text(encoding="utf-8") == 'model = "new-model"\n'
    assert installer._is_codex_hooks_active(hooks)


def test_show_status_handles_permission_error_gracefully(tmp_path, monkeypatch, capsys) -> None:
    restricted = tmp_path / "restricted_hooks.json"
    restricted.write_text("{}", encoding="utf-8")
    orig_read_text = type(restricted).read_text

    def _mock_read_text(self, *args, **kwargs):
        if self == restricted:
            raise PermissionError("Access denied")
        return orig_read_text(self, *args, **kwargs)

    monkeypatch.setattr(type(restricted), "read_text", _mock_read_text)
    monkeypatch.setattr(installer, "_antigravity_hook_targets", lambda: [restricted])
    monkeypatch.setattr(installer, "CODEX_HOOKS", tmp_path / "no-codex-hooks.json")
    monkeypatch.setattr(installer, "CODEX_CONFIG", tmp_path / "no-codex-config.toml")
    monkeypatch.setattr(installer, "PI_EXT_TARGET", tmp_path / "no-pi.ts")

    assert installer._is_antigravity_active(restricted) is False
    assert installer.show_status() == 0
    out = capsys.readouterr().out
    assert "RESTRICTED" in out


def test_apply_antigravity_is_idempotent_with_backups(tmp_path, monkeypatch) -> None:
    hooks = tmp_path / "hooks.json"
    hooks.write_text('{"other-hook": {"enabled": true}}\n', encoding="utf-8")
    monkeypatch.setattr(installer, "_antigravity_hook_targets", lambda: [hooks])

    installer.apply_antigravity(dry_run=False)
    backups_after_first = sorted(tmp_path.glob("hooks.json.bak.*"))
    assert len(backups_after_first) == 1
    installed = json.loads(hooks.read_text(encoding="utf-8"))
    assert "pii-shield-guard" in installed
    assert "other-hook" in installed

    installer.apply_antigravity(dry_run=False)
    assert sorted(tmp_path.glob("hooks.json.bak.*")) == backups_after_first
