"""Safe installer and rollback helper for PII-Shield connectors.

By default runs in --status mode without modifying any live agent configuration.
When --apply is invoked explicitly, creates timestamped .bak backups first.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
import tomllib
from datetime import datetime
from pathlib import Path

HOME = Path.home()
SHIELD_ROOT = Path(__file__).resolve().parent.parent

ANTIGRAVITY_HOOKS = HOME / ".gemini" / "config" / "hooks.json"
T3_ANTIGRAVITY_DIR = HOME / ".t3" / "userdata" / "providers" / "antigravity"
CODEX_DIR = Path(os.environ.get("CODEX_HOME") or HOME / ".codex").expanduser()
CODEX_CONFIG = CODEX_DIR / "config.toml"
CODEX_HOOKS = CODEX_DIR / "hooks.json"
CODEX_HOOKS_EXAMPLE = SHIELD_ROOT / "connectors" / "codex" / "hooks.example.json"
CODEX_GUARDS = ("codex_hook_guard.py", "codex_shell_output_guard.py")
RETIRED_CODEX_GUARDS = ("codex_proxy_start.py", "codex_tool_guard.py", "codex_output_guard.py")
PI_EXT_DIR = HOME / ".pi" / "agent" / "extensions"
PI_EXT_TARGET = PI_EXT_DIR / "pii-shield.ts"
PI_EXT_SOURCE = SHIELD_ROOT / "connectors" / "pi" / "pii-shield.ts"
ANTIGRAVITY_EXAMPLE = SHIELD_ROOT / "connectors" / "antigravity" / "hooks.example.json"

CODEX_MARKER_START = "# >>> PII-SHIELD START >>>"
CODEX_MARKER_END = "# <<< PII-SHIELD END <<<"
CODEX_PROVIDER_START = "# >>> PII-SHIELD PROVIDER >>>"
CODEX_PROVIDER_END = "# <<< PII-SHIELD PROVIDER <<<"


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    bak = path.with_name(f"{path.name}.bak.{stamp}")
    shutil.copy2(path, bak)
    return bak


def _latest_backup(path: Path) -> Path | None:
    candidates = sorted(path.parent.glob(f"{path.name}.bak.*"), reverse=True)
    return candidates[0] if candidates else None


def _antigravity_hook_targets() -> list[Path]:
    targets = [ANTIGRAVITY_HOOKS]
    try:
        if T3_ANTIGRAVITY_DIR.exists():
            for provider_dir in sorted(T3_ANTIGRAVITY_DIR.iterdir()):
                if provider_dir.is_dir():
                    targets.append(provider_dir / "config" / "hooks.json")
    except OSError:
        pass
    return targets


def _antigravity_hook_state(path: Path) -> str:
    try:
        if not path.exists():
            return "NOT INSTALLED"
        ag_data = json.loads(path.read_text(encoding="utf-8"))
        return "ACTIVE" if "pii-shield-guard" in ag_data else "NOT INSTALLED"
    except PermissionError:
        return "RESTRICTED (permission denied)"
    except (OSError, json.JSONDecodeError):
        return "NOT INSTALLED"


def _is_antigravity_active(path: Path) -> bool:
    return _antigravity_hook_state(path) == "ACTIVE"


def _is_codex_hooks_active(path: Path) -> bool:
    try:
        installed = _read_codex_hooks(path.read_text(encoding="utf-8"))["hooks"]
        for event, entries in _codex_hook_entries().items():
            expected = entries[0]
            if not any(
                entry.get("matcher", "") == expected.get("matcher", "")
                and expected["hooks"][0] in entry["hooks"]
                for entry in installed.get(event, [])
            ):
                return False
        return True
    except (OSError, ValueError, KeyError):
        return False


def show_status() -> int:
    for target in _antigravity_hook_targets():
        label = "Antigravity" if target == ANTIGRAVITY_HOOKS else "Antigravity (T3)"
        state = _antigravity_hook_state(target)
        print(f"{label:<16} ({target}): {state}")

    codex_installed = _is_codex_hooks_active(CODEX_HOOKS)
    try:
        pi_installed = PI_EXT_TARGET.exists()
    except OSError:
        pi_installed = False

    print(f"{'Codex CLI':<16} ({CODEX_HOOKS}): {'INSTALLED (trust via /hooks)' if codex_installed else 'NOT INSTALLED'}")
    try:
        config = CODEX_CONFIG.read_text(encoding="utf-8")
        if CODEX_MARKER_START in config or CODEX_PROVIDER_START in config:
            print(f"{'Codex (legacy)':<16} ({CODEX_CONFIG}): LEGACY PROXY BLOCK PRESENT")
    except OSError:
        pass
    print(f"{'Pi dev CLI':<16} ({PI_EXT_TARGET}): {'ACTIVE' if pi_installed else 'NOT INSTALLED'}")
    return 0


def _resolve_venv_python() -> Path:
    for candidate in (
        SHIELD_ROOT / ".venv" / "Scripts" / "python.exe",
        SHIELD_ROOT / ".venv" / "bin" / "python",
    ):
        if candidate.exists():
            return candidate
    return Path(sys.executable)


def _load_hooks_entry(example_path: Path) -> dict:
    raw = example_path.read_text(encoding="utf-8")
    python_exe = _resolve_venv_python().as_posix()
    shield_root = SHIELD_ROOT.as_posix()
    resolved = (
        raw.replace("~/pii-shield/.venv/bin/python", python_exe)
        .replace("~/pii-shield/.venv/Scripts/python.exe", python_exe)
        .replace("~/pii-shield", shield_root)
    )
    return json.loads(resolved)


def apply_antigravity(dry_run: bool) -> None:
    desired_entry = _load_hooks_entry(ANTIGRAVITY_EXAMPLE)
    for target in _antigravity_hook_targets():
        existing = {}
        original_text = ""
        if target.exists():
            original_text = target.read_text(encoding="utf-8")
            existing = json.loads(original_text)
        existing.update(desired_entry)
        hook_text = json.dumps(existing, indent=2) + "\n"

        if dry_run:
            print(f"[DRY-RUN] Akan mengupdate {target} dengan key 'pii-shield-guard'")
            continue

        if target.exists() and original_text == hook_text:
            print(f"[OK] Antigravity hook sudah terbaru di {target}")
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        bak = _backup(target)
        target.write_text(hook_text, encoding="utf-8")
        print(f"[OK] Antigravity hook terpasang di {target}" + (f" (backup: {bak})" if bak else ""))


def _codex_hook_entries() -> dict:
    entries = json.loads(CODEX_HOOKS_EXAMPLE.read_text(encoding="utf-8"))["hooks"]
    for groups in entries.values():
        for entry in groups:
            for hook in entry["hooks"]:
                script = Path(hook["command"].rsplit(" ", 1)[-1]).name
                args = (str(_resolve_venv_python()), str(CODEX_HOOKS_EXAMPLE.parent / script))
                if os.name == "nt":
                    hook["command"] = "& " + " ".join("'" + arg.replace("'", "''") + "'" for arg in args)
                else:
                    hook["command"] = shlex.join(args)
    return entries


def _read_codex_hooks(text: str | None) -> dict:
    data = json.loads(text) if text is not None else {}
    if not isinstance(data, dict) or not isinstance(data.get("hooks", {}), dict):
        raise ValueError("hooks.json Codex tidak valid.")
    for entries in data.get("hooks", {}).values():
        if not isinstance(entries, list) or any(
            not isinstance(entry, dict)
            or not isinstance(entry.get("hooks"), list)
            or any(not isinstance(hook, dict) for hook in entry["hooks"])
            for entry in entries
        ):
            raise ValueError("Grup hook di hooks.json Codex tidak valid.")
    return data


def _is_owned_codex_hook(hook: dict) -> bool:
    endings = tuple(f"/connectors/codex/{name}" for name in (*CODEX_GUARDS, *RETIRED_CODEX_GUARDS))
    for field in ("command", "commandWindows"):
        command = hook.get(field)
        if isinstance(command, str):
            normalized = command.replace("\\", "/").rstrip().rstrip("\"'")
            if normalized.endswith(endings):
                return True
    return False


def _merge_codex_hooks(original: str | None, desired: dict) -> str | None:
    data = _read_codex_hooks(original)
    events = dict(data.get("hooks", {}))
    for event in dict.fromkeys((*events, *desired)):
        entries = []
        for entry in events.get(event, []):
            kept = [hook for hook in entry["hooks"] if not _is_owned_codex_hook(hook)]
            if kept or not entry["hooks"]:
                entries.append({**entry, "hooks": kept})
        entries.extend(desired.get(event, []))
        if entries:
            events[event] = entries
        else:
            events.pop(event, None)
    if events == data.get("hooks", {}):
        return original
    data["hooks"] = events
    return json.dumps(data, indent=2) + "\n"


def _remove_proxy_blocks(text: str) -> str:
    for start, end in (
        (CODEX_MARKER_START, CODEX_MARKER_END),
        (CODEX_PROVIDER_START, CODEX_PROVIDER_END),
    ):
        if start not in text and end not in text:
            continue
        if text.count(start) != 1 or text.count(end) != 1 or text.index(start) > text.index(end):
            raise ValueError("Marker konfigurasi proxy Codex tidak lengkap atau ambigu.")
        first = text.index(start)
        last = text.index(end) + len(end)
        if (first and text[first - 1] != "\n") or (last < len(text) and text[last] != "\n"):
            raise ValueError("Marker konfigurasi proxy Codex harus berada pada baris tersendiri.")
        text = text[:first] + text[last:].removeprefix("\n")
    return text


def _settings_match(previous: dict, current: dict) -> bool:
    """Match backup settings while allowing new settings in the current file."""
    for key, value in previous.items():
        if key not in current:
            return False
        actual = current[key]
        if isinstance(value, dict) and isinstance(actual, dict):
            if not _settings_match(value, actual):
                return False
        elif value != actual:
            return False
    return True


def _previous_codex_provider(config: dict, path: Path) -> str | None:
    candidates = set()
    backups = list(path.parent.glob(f"{path.name}.bak.*"))
    for backup in backups:
        try:
            previous = tomllib.loads(_remove_proxy_blocks(backup.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
        provider = previous.pop("model_provider", None)
        if provider == "pii-shield" or (provider is not None and not isinstance(provider, str)):
            continue
        if _settings_match(previous, config):
            candidates.add(provider)
    if len(candidates) == 1:
        return candidates.pop()
    if not backups and not config:
        return None
    raise ValueError(
        "Provider Codex sebelum proxy PS tidak dapat dipastikan. "
        "Tentukan model_provider yang diinginkan di config.toml (atau hapus barisnya untuk default Codex), lalu ulangi."
    )


def _migrate_codex_config(original: str | None, path: Path) -> str | None:
    if original is None:
        return None
    cleaned = _remove_proxy_blocks(original)
    if cleaned == original:
        return original

    config = tomllib.loads(cleaned)
    owned_provider = CODEX_PROVIDER_START in original and "pii-shield" not in config.get("model_providers", {})
    if owned_provider and config.get("model_provider") == "pii-shield":
        del config["model_provider"]
        previous = _previous_codex_provider(config, path)
        replacement = "" if previous is None else f"model_provider = {json.dumps(previous, ensure_ascii=False)}\n"
        # The proxy installer writes this exact root selector at the start of the file.
        selector = 'model_provider = "pii-shield"\n'
        if not cleaned.startswith(selector):
            raise ValueError("Selector proxy PS sudah diedit. Tentukan model_provider di config.toml, lalu ulangi.")
        cleaned = replacement + cleaned[len(selector):]
    if owned_provider and any(
        isinstance(profile, dict) and profile.get("model_provider") == "pii-shield"
        for profile in config.get("profiles", {}).values()
    ):
        raise ValueError("Ubah profil Codex yang masih memilih provider pii-shield, lalu ulangi.")
    tomllib.loads(cleaned)
    return cleaned


def _read_optional(path: Path) -> str | None:
    try:
        with path.open(encoding="utf-8", newline="") as source:
            return source.read()
    except FileNotFoundError:
        return None


def _write_codex_file(path: Path, content: str | None) -> None:
    if content is None:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as staged:
        temporary = Path(staged.name)
        try:
            staged.write(content)
            staged.close()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def _codex_checkpoint() -> Path:
    return CODEX_HOOKS.with_name("pii-shield-codex.backup.json")


def _read_codex_checkpoint() -> dict:
    snapshot = _read_optional(_codex_checkpoint())
    data = json.loads(snapshot) if snapshot is not None else {}
    if not isinstance(data, dict) or any(
        name not in {"config", "hooks"}
        or not isinstance(pair, list)
        or len(pair) != 2
        or any(value is not None and not isinstance(value, str) for value in pair)
        for name, pair in data.items()
    ):
        raise ValueError("Backup instalasi Codex tidak valid.")
    return data


def _apply_codex_changes(changes: dict[str, list[str | None]], *, reverse: bool = False) -> None:
    paths = {"hooks": CODEX_HOOKS, "config": CODEX_CONFIG}
    source, target = (1, 0) if reverse else (0, 1)
    order = ("config", "hooks") if reverse else ("hooks", "config")
    current = {name: _read_optional(paths[name]) for name in changes}
    for name, pair in changes.items():
        if current[name] not in pair:
            raise ValueError(f"{paths[name]} berubah sejak pemasangan Codex. Backup disimpan di {_codex_checkpoint()}.")
    written = []
    try:
        for name in order:
            if name in changes and current[name] == changes[name][source]:
                _write_codex_file(paths[name], changes[name][target])
                written.append(name)
    except OSError:
        for name in reversed(written):
            _write_codex_file(paths[name], current[name])
        raise


def apply_codex(dry_run: bool) -> None:
    original_hooks = _read_optional(CODEX_HOOKS)
    original_config = _read_optional(CODEX_CONFIG)
    normalized = original_config.replace("\r\n", "\n") if original_config is not None else None
    migrated = _migrate_codex_config(normalized, CODEX_CONFIG)
    if migrated == normalized:
        migrated = original_config
    elif original_config and "\r\n" in original_config and migrated is not None:
        migrated = migrated.replace("\n", "\r\n")

    changes = {}
    for name, before, after in (
        ("hooks", original_hooks, _merge_codex_hooks(original_hooks, _codex_hook_entries())),
        ("config", original_config, migrated),
    ):
        if before != after:
            changes[name] = [before, after]

    if dry_run:
        if changes:
            for name in changes:
                action = "Pasang dua hook Codex" if name == "hooks" else "Migrasikan blok proxy PS"
                print(f"[DRY-RUN] {action} di {CODEX_HOOKS if name == 'hooks' else CODEX_CONFIG}")
        else:
            print("[DRY-RUN] Hook Codex sudah terbaru.")
        return

    if changes:
        # Keep the first snapshot for files that still match an earlier PS write.
        snapshot = _read_codex_checkpoint()
        for name, (before, after) in changes.items():
            previous = snapshot.get(name)
            snapshot[name] = [previous[0] if previous and before in previous else before, after]
        _write_codex_file(_codex_checkpoint(), json.dumps(snapshot, indent=2) + "\n")
        _apply_codex_changes(changes)
    print("[OK] Hook Codex terpasang. Buka sesi baru dan tinjau kepercayaan hook di /hooks.")


def rollback_codex(dry_run: bool = False) -> None:
    changes = _read_codex_checkpoint()
    if dry_run:
        print("[DRY-RUN] Pulihkan instalasi Codex dari backup." if changes else "[DRY-RUN] Backup instalasi Codex tidak ditemukan.")
    elif changes:
        _apply_codex_changes(changes, reverse=True)
        _codex_checkpoint().unlink()
        print("[OK] Instalasi Codex dipulihkan.")
    else:
        print("[OK] Backup instalasi Codex tidak ditemukan.")


def apply_pi(dry_run: bool) -> None:
    if dry_run:
        print(f"[DRY-RUN] Akan menyalin {PI_EXT_SOURCE} -> {PI_EXT_TARGET}")
        return

    PI_EXT_DIR.mkdir(parents=True, exist_ok=True)
    bak = _backup(PI_EXT_TARGET)
    shutil.copy2(PI_EXT_SOURCE, PI_EXT_TARGET)
    print(f"[OK] Pi extension terpasang di {PI_EXT_TARGET}" + (f" (backup: {bak})" if bak else ""))


def rollback_all() -> None:
    for target in _antigravity_hook_targets():
        if not target.exists():
            continue
        bak = _latest_backup(target)
        if bak:
            shutil.copy2(bak, target)
            print(f"[OK] Rollback Antigravity dari {bak}")
        else:
            data = json.loads(target.read_text(encoding="utf-8"))
            if "pii-shield-guard" in data:
                data.pop("pii-shield-guard", None)
                if data:
                    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                else:
                    target.unlink()
                print(f"[OK] Hapus pii-shield-guard dari {target}")

    rollback_codex()

    if PI_EXT_TARGET.exists():
        PI_EXT_TARGET.unlink()
        print(f"[OK] Hapus {PI_EXT_TARGET}")


def main() -> int:
    parser = argparse.ArgumentParser(description="PII-Shield connector installer")
    parser.add_argument("--status", action="store_true", help="Tampilkan status instalasi saat ini")
    parser.add_argument(
        "--apply",
        choices=["all", "antigravity", "codex", "pi"],
        help="Pasang connector ke konfigurasi live (dengan backup otomatis)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Simulasi tanpa mengubah file")
    parser.add_argument(
        "--rollback", nargs="?", const="all", choices=["all", "codex"],
        help="Pulihkan semua connector atau hanya Codex",
    )
    args = parser.parse_args()

    if args.rollback == "codex":
        rollback_codex(args.dry_run)
        return 0
    if args.rollback == "all":
        if args.dry_run:
            parser.error("--dry-run untuk rollback hanya tersedia dengan --rollback codex.")
        rollback_all()
        return 0
    if args.apply:
        if args.apply in ("all", "antigravity"):
            apply_antigravity(args.dry_run)
        if args.apply in ("all", "codex"):
            apply_codex(args.dry_run)
        if args.apply in ("all", "pi"):
            apply_pi(args.dry_run)
        return 0

    return show_status()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1) from None
