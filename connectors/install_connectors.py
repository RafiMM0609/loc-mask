"""Safe installer and rollback helper for PII-Shield connectors.

By default runs in --status mode without modifying any live agent configuration.
When --apply is invoked explicitly, creates timestamped .bak backups first.
"""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime
from pathlib import Path

HOME = Path.home()
SHIELD_ROOT = Path(__file__).resolve().parent.parent

ANTIGRAVITY_HOOKS = HOME / ".gemini" / "config" / "hooks.json"
T3_ANTIGRAVITY_DIR = HOME / ".t3" / "userdata" / "providers" / "antigravity"
CODEX_CONFIG = HOME / ".codex" / "config.toml"
PI_EXT_DIR = HOME / ".pi" / "agent" / "extensions"
PI_EXT_TARGET = PI_EXT_DIR / "pii-shield.ts"
PI_EXT_SOURCE = SHIELD_ROOT / "connectors" / "pi" / "pii-shield.ts"
ANTIGRAVITY_EXAMPLE = SHIELD_ROOT / "connectors" / "antigravity" / "hooks.example.json"

CODEX_MARKER_START = "# >>> PII-SHIELD START >>>"
CODEX_MARKER_END = "# <<< PII-SHIELD END <<<"
CODEX_BLOCK = (
    f"{CODEX_MARKER_START}\n"
    'chatgpt_base_url = "http://127.0.0.1:8787/chatgpt-backend/"\n'
    f"{CODEX_MARKER_END}\n"
)


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
    if T3_ANTIGRAVITY_DIR.exists():
        for provider_dir in sorted(T3_ANTIGRAVITY_DIR.iterdir()):
            if provider_dir.is_dir():
                targets.append(provider_dir / "config" / "hooks.json")
    return targets


def _is_antigravity_active(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        ag_data = json.loads(path.read_text(encoding="utf-8"))
        return "pii-shield-guard" in ag_data
    except json.JSONDecodeError:
        return False


def show_status() -> int:
    for target in _antigravity_hook_targets():
        label = "Antigravity" if target == ANTIGRAVITY_HOOKS else "Antigravity (T3)"
        state = "ACTIVE" if _is_antigravity_active(target) else "NOT INSTALLED"
        print(f"{label:<16} ({target}): {state}")

    codex_installed = False
    if CODEX_CONFIG.exists():
        codex_installed = CODEX_MARKER_START in CODEX_CONFIG.read_text(encoding="utf-8")

    pi_installed = PI_EXT_TARGET.exists()

    print(f"{'Codex CLI':<16} ({CODEX_CONFIG}): {'ACTIVE' if codex_installed else 'NOT INSTALLED'}")
    print(f"{'Pi dev CLI':<16} ({PI_EXT_TARGET}): {'ACTIVE' if pi_installed else 'NOT INSTALLED'}")
    return 0


def apply_antigravity(dry_run: bool) -> None:
    desired_entry = json.loads(ANTIGRAVITY_EXAMPLE.read_text(encoding="utf-8"))
    for target in _antigravity_hook_targets():
        existing = {}
        if target.exists():
            existing = json.loads(target.read_text(encoding="utf-8"))
        existing.update(desired_entry)

        if dry_run:
            print(f"[DRY-RUN] Akan mengupdate {target} dengan key 'pii-shield-guard'")
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        bak = _backup(target)
        target.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
        print(f"[OK] Antigravity hook terpasang di {target}" + (f" (backup: {bak})" if bak else ""))


def apply_codex(dry_run: bool) -> None:
    content = CODEX_CONFIG.read_text(encoding="utf-8") if CODEX_CONFIG.exists() else ""
    if CODEX_MARKER_START in content:
        print(f"[SKIP] Codex config sudah memiliki blok PII-Shield di {CODEX_CONFIG}")
        return

    updated = CODEX_BLOCK + "\n" + content if content else CODEX_BLOCK
    if dry_run:
        print(f"[DRY-RUN] Akan menambahkan chatgpt_base_url ke bagian atas {CODEX_CONFIG}")
        return

    CODEX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    bak = _backup(CODEX_CONFIG)
    CODEX_CONFIG.write_text(updated, encoding="utf-8")
    print(f"[OK] Codex proxy terpasang di {CODEX_CONFIG}" + (f" (backup: {bak})" if bak else ""))


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

    if CODEX_CONFIG.exists():
        bak = _latest_backup(CODEX_CONFIG)
        if bak:
            shutil.copy2(bak, CODEX_CONFIG)
            print(f"[OK] Rollback Codex dari {bak}")
        else:
            text = CODEX_CONFIG.read_text(encoding="utf-8")
            if CODEX_MARKER_START in text:
                start = text.index(CODEX_MARKER_START)
                end = text.index(CODEX_MARKER_END) + len(CODEX_MARKER_END)
                cleaned = (text[:start] + text[end:]).lstrip("\r\n")
                CODEX_CONFIG.write_text(cleaned, encoding="utf-8")
                print(f"[OK] Hapus blok PII-Shield dari {CODEX_CONFIG}")

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
