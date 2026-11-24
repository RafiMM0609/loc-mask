"""Thread-safe in-memory 2-way vault and streaming unmask decoder."""

from __future__ import annotations

import re
import threading
from collections import defaultdict


class VaultStore:
    """In-memory bidirectional mapping between raw secrets/PII and <<PII:TYPE_N>> placeholders."""

    def __init__(self, prefix: str = "<<PII:", suffix: str = ">>") -> None:
        self.prefix = prefix
        self.suffix = suffix
        self._lock = threading.RLock()
        self._session_raw_to_ph: dict[str, dict[str, str]] = defaultdict(dict)
        self._session_ph_to_raw: dict[str, dict[str, str]] = defaultdict(dict)
        self._global_ph_to_raw: dict[str, str] = {}
        self._session_counters: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._placeholder_re = re.compile(
            re.escape(prefix) + r"[A-Z0-9_]+_[0-9]+" + re.escape(suffix)
        )

    def get_or_create_placeholder(self, session_id: str, entity_type: str, raw_value: str) -> str:
        """Return deterministic placeholder for raw_value within a session."""
        clean_type = re.sub(r"[^A-Z0-9_]", "_", entity_type.upper())
        with self._lock:
            existing = self._session_raw_to_ph[session_id].get(raw_value)
            if existing:
                return existing

            self._session_counters[session_id][clean_type] += 1
            idx = self._session_counters[session_id][clean_type]
            placeholder = f"{self.prefix}{clean_type}_{idx}{self.suffix}"

            self._session_raw_to_ph[session_id][raw_value] = placeholder
            self._session_ph_to_raw[session_id][placeholder] = raw_value
            self._global_ph_to_raw[placeholder] = raw_value
            return placeholder

    def resolve(self, placeholder: str, session_id: str | None = None) -> str | None:
        with self._lock:
            if session_id:
                hit = self._session_ph_to_raw.get(session_id, {}).get(placeholder)
                if hit is not None:
                    return hit
            return self._global_ph_to_raw.get(placeholder)

    def unmask_text(self, text: str, session_id: str | None = None) -> tuple[str, int]:
        """Replace placeholders in text with their stored original values."""
        if not text or self.prefix not in text:
            return text, 0

        restored = 0

        def _replace(match: re.Match[str]) -> str:
            nonlocal restored
            ph = match.group(0)
            original = self.resolve(ph, session_id=session_id)
            if original is not None:
                restored += 1
                return original
            return ph

        return self._placeholder_re.sub(_replace, text), restored

    def clear(self, session_id: str | None = None) -> int:
        with self._lock:
            if session_id:
                removed = len(self._session_ph_to_raw.pop(session_id, {}))
                self._session_raw_to_ph.pop(session_id, None)
                self._session_counters.pop(session_id, None)
                return removed
            removed = len(self._global_ph_to_raw)
            self._session_raw_to_ph.clear()
            self._session_ph_to_raw.clear()
            self._global_ph_to_raw.clear()
            self._session_counters.clear()
            return removed

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "sessions": len(self._session_ph_to_raw),
                "active_placeholders": len(self._global_ph_to_raw),
            }


class StreamingUnmaskBuffer:
    """Buffers partial placeholder tokens across streaming SSE chunks so split tokens still unmask."""

    def __init__(
        self,
        vault: VaultStore,
        session_id: str | None = None,
        max_hold_len: int = 48,
    ) -> None:
        self.vault = vault
        self.session_id = session_id
        self.max_hold_len = max_hold_len
        self._buffer = ""

    def feed(self, chunk: str) -> str:
        """Process next text delta, holding back any incomplete trailing <<PII:... prefix."""
        if not chunk:
            return ""
        combined = self._buffer + chunk
        self._buffer = ""

        prefix = self.vault.prefix
        last_start = combined.rfind(prefix)
        if last_start != -1:
            tail = combined[last_start:]
            if self.vault.suffix not in tail and len(tail) <= self.max_hold_len:
                self._buffer = tail
                emit_part = combined[:last_start]
                unmasked, _ = self.vault.unmask_text(emit_part, session_id=self.session_id)
                return unmasked

        # Also check partial prefix at the very end (e.g. "<", "<<", "<<P", "<<PII:")
        for k in range(min(len(prefix) - 1, len(combined)), 0, -1):
            if combined.endswith(prefix[:k]):
                self._buffer = combined[-k:]
                emit_part = combined[:-k]
                unmasked, _ = self.vault.unmask_text(emit_part, session_id=self.session_id)
                return unmasked

        unmasked, _ = self.vault.unmask_text(combined, session_id=self.session_id)
        return unmasked

    def flush(self) -> str:
        if not self._buffer:
            return ""
        rem = self._buffer
        self._buffer = ""
        unmasked, _ = self.vault.unmask_text(rem, session_id=self.session_id)
        return unmasked
