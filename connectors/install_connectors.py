"""Safe installer and rollback helper for PII-Shield connectors.

By default runs in --status mode without modifying any live agent configuration.
When --apply is invoked explicitly, creates timestamped .bak backups first.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

HOME = Path.home()
SHIELD_ROOT = Path(__file__).resolve().parent.parent

ANTIGRAVITY_HOOKS = HOME / ".gemini" / "config" / "hooks.json"
T3_ANTIGRAVITY_DIR = HOME / ".t3" / "userdata" / "providers" / "antigravity"
CODEX_CONFIG = HOME / ".codex" / "config.toml"
CODEX_HOOKS = HOME / ".codex" / "hooks.json"
CODEX_HOOKS_EXAMPLE = SHIELD_ROOT / "connectors" / "codex" / "hooks.example.json"
PI_EXT_DIR = HOME / ".pi" / "agent" / "extensions"
PI_EXT_TARGET = PI_EXT_DIR / "pii-shield.ts"
PI_EXT_SOURCE = SHIELD_ROOT / "connectors" / "pi" / "pii-shield.ts"
ANTIGRAVITY_EXAMPLE = SHIELD_ROOT / "connectors" / "antigravity" / "hooks.example.json"

CODEX_MARKER_START = "# >>> PII-SHIELD START >>>"
CODEX_MARKER_END = "# <<< PII-SHIELD END <<<"


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
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
    if not path.exists():
        return False
    try:
        raw = path.read_text(encoding="utf-8")
        return "codex_hook_guard.py" in raw and "codex_tool_guard.py" in raw
    except OSError:
        return False


def show_status() -> int:
    for target in _antigravity_hook_targets():
        label = "Antigravity" if target == ANTIGRAVITY_HOOKS else "Antigravity (T3)"
        state = _antigravity_hook_state(target)
        print(f"{label:<16} ({target}): {state}")

    codex_installed = _is_codex_hooks_active(CODEX_HOOKS)
    pi_installed = PI_EXT_TARGET.exists()

    print(f"{'Codex CLI':<16} ({CODEX_HOOKS}): {'ACTIVE' if codex_installed else 'NOT INSTALLED'}")
    if CODEX_CONFIG.exists() and CODEX_MARKER_START in CODEX_CONFIG.read_text(encoding="utf-8"):
        print(f"{'Codex (legacy)':<16} ({CODEX_CONFIG}): LEGACY PROXY BLOCK PRESENT")
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


def _load_codex_hooks_entry() -> dict:
    raw = CODEX_HOOKS_EXAMPLE.read_text(encoding="utf-8")
    python_exe = _resolve_venv_python().as_posix()
    shield_root = SHIELD_ROOT.as_posix()
    resolved = (
        raw.replace("~/pii-shield/.venv/bin/python", python_exe)
        .replace("~/pii-shield/.venv/Scripts/python.exe", python_exe)
        .replace("~/pii-shield", shield_root)
    )
    return json.loads(resolved)


def _strip_legacy_codex_block(dry_run: bool) -> None:
    if not CODEX_CONFIG.exists():
        return
    text = CODEX_CONFIG.read_text(encoding="utf-8")
    if CODEX_MARKER_START not in text or CODEX_MARKER_END not in text:
        return
    if dry_run:
        print(f"[DRY-RUN] Akan menghapus blok legacy chatgpt_base_url dari {CODEX_CONFIG}")
        return
    bak = _backup(CODEX_CONFIG)
    start = text.index(CODEX_MARKER_START)
    end = text.index(CODEX_MARKER_END) + len(CODEX_MARKER_END)
    cleaned = (text[:start] + text[end:]).lstrip("\r\n")
    CODEX_CONFIG.write_text(cleaned, encoding="utf-8")
    print(f"[OK] Hapus blok legacy PII-Shield dari {CODEX_CONFIG}" + (f" (backup: {bak})" if bak else ""))


def apply_codex(dry_run: bool) -> None:
    _strip_legacy_codex_block(dry_run)

    desired = _load_codex_hooks_entry()
    existing: dict = {}
    if CODEX_HOOKS.exists():
        try:
            existing = json.loads(CODEX_HOOKS.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = {}

    hooks_root = existing.get("hooks")
    if not isinstance(hooks_root, dict):
        hooks_root = {}

    for event_name, desired_entries in desired.get("hooks", {}).items():
        current_list = hooks_root.get(event_name)
        if not isinstance(current_list, list):
            current_list = []
        # Replace any previous pii-shield hook entries for this event
        filtered = [
            entry
            for entry in current_list
            if "codex_hook_guard.py" not in json.dumps(entry)
            and "codex_tool_guard.py" not in json.dumps(entry)
        ]
        hooks_root[event_name] = filtered + desired_entries

    existing["hooks"] = hooks_root

    if dry_run:
        print(f"[DRY-RUN] Akan memasang Codex hooks (UserPromptSubmit + PreToolUse) di {CODEX_HOOKS}")
        return

    CODEX_HOOKS.parent.mkdir(parents=True, exist_ok=True)
    bak = _backup(CODEX_HOOKS)
    CODEX_HOOKS.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    print(f"[OK] Codex hooks terpasang di {CODEX_HOOKS}" + (f" (backup: {bak})" if bak else ""))


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

    if CODEX_HOOKS.exists():
        bak = _latest_backup(CODEX_HOOKS)
        if bak:
            shutil.copy2(bak, CODEX_HOOKS)
            print(f"[OK] Rollback Codex hooks dari {bak}")
        else:
            CODEX_HOOKS.unlink()
            print(f"[OK] Hapus {CODEX_HOOKS}")

    if CODEX_CONFIG.exists():
        text = CODEX_CONFIG.read_text(encoding="utf-8")
        if CODEX_MARKER_START in text and CODEX_MARKER_END in text:
            start = text.index(CODEX_MARKER_START)
            end = text.index(CODEX_MARKER_END) + len(CODEX_MARKER_END)
            cleaned = (text[:start] + text[end:]).lstrip("\r\n")
            CODEX_CONFIG.write_text(cleaned, encoding="utf-8")
            print(f"[OK] Hapus blok legacy PII-Shield dari {CODEX_CONFIG}")

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
    parser.add_argument("--rollback", action="store_true", help="Kembalikan config ke kondisi semula")
    args = parser.parse_args()

    if args.rollback:
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
    raise SystemExit(main())
