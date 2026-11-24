"""Presidio-backed MaskingEngine for scanning, 2-way masking, and recursive JSON payload handling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider

from pii_shield.config import AppConfig, load_config
from pii_shield.patterns import PLACEHOLDER_RE
from pii_shield.recognizers import build_custom_recognizers
from pii_shield.vault import VaultStore

SKIP_JSON_KEYS = {
    "model",
    "role",
    "type",
    "id",
    "object",
    "tool_call_id",
    "call_id",
    "finish_reason",
    "status",
    "index",
    "created",
    "provider",
    "api",
    "response_id",
    "previous_response_id",
    "item_id",
    "output_index",
    "content_index",
}


@dataclass(frozen=True)
class DetectedEntity:
    entity_type: str
    start: int
    end: int
    score: float


@dataclass
class MaskResult:
    text: str
    entities: list[DetectedEntity]

    @property
    def count(self) -> int:
        return len(self.entities)

    @property
    def entity_types(self) -> list[str]:
        seen: list[str] = []
        for ent in self.entities:
            if ent.entity_type not in seen:
                seen.append(ent.entity_type)
        return seen


class MaskingEngine:
    """Combines Presidio PII/NLP + Secret Pattern Recognizers with a 2-way VaultStore."""

    def __init__(self, config: AppConfig | None = None) -> None:
        self.config = config or load_config()
        self.vault = VaultStore(
            prefix=self.config.masking.placeholder_prefix,
            suffix=self.config.masking.placeholder_suffix,
        )
        self.analyzer = self._build_analyzer()
        self.target_entities = self._resolve_target_entities()

    def _build_analyzer(self) -> AnalyzerEngine:
        nlp_provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
        )
        nlp_engine = nlp_provider.create_engine()

        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(nlp_engine=nlp_engine)
        for recognizer in build_custom_recognizers(self.config):
            registry.add_recognizer(recognizer)

        return AnalyzerEngine(
            nlp_engine=nlp_engine,
            registry=registry,
            supported_languages=["en"],
        )

    def _resolve_target_entities(self) -> list[str]:
        entities: list[str] = []
        if self.config.masking.detect_secrets:
            entities.extend(
                [
                    "PRIVATE_KEY",
                    "DB_URI",
                    "JWT_TOKEN",
                    "BEARER_TOKEN",
                    "ANTHROPIC_API_KEY",
                    "OPENAI_API_KEY",
                    "GOOGLE_API_KEY",
                    "AWS_ACCESS_KEY",
                    "GITHUB_TOKEN",
                    "GITLAB_TOKEN",
                    "SLACK_TOKEN",
                    "STRIPE_KEY",
                    "TELEGRAM_TOKEN",
                    "MIDTRANS_KEY",
                    "XENDIT_KEY",
                    "PACKAGE_TOKEN",
                    "SECRET_ASSIGNMENT",
                ]
            )
        if self.config.masking.detect_pii:
            entities.extend(
                [
                    "ID_NIK",
                    "ID_PHONE",
                    "EMAIL_ADDRESS",
                    "CREDIT_CARD",
                    "PHONE_NUMBER",
                    "IBAN_CODE",
                ]
            )
        if self.config.masking.detect_person_and_ip:
            entities.extend(["PERSON", "IP_ADDRESS", "LOCATION"])
        for custom in self.config.custom_patterns:
            if custom.name not in entities:
                entities.append(custom.name)
        return entities

    @staticmethod
    def _overlaps_placeholder(start: int, end: int, protected_spans: list[tuple[int, int]]) -> bool:
        for p_start, p_end in protected_spans:
            if start < p_end and end > p_start:
                return True
        return False

    @staticmethod
    def _resolve_overlaps(results: list[RecognizerResult]) -> list[RecognizerResult]:
        # Prefer earlier start; on overlap, prefer longer span then higher score.
        sorted_res = sorted(
            results,
            key=lambda r: (r.start, -(r.end - r.start), -r.score),
        )
        kept: list[RecognizerResult] = []
        for cand in sorted_res:
            if not kept:
                kept.append(cand)
                continue
            prev = kept[-1]
            if cand.start >= prev.end:
                kept.append(cand)
            else:
                prev_len = prev.end - prev.start
                cand_len = cand.end - cand.start
                if (cand_len > prev_len and cand.score >= 0.75) or (
                    cand_len == prev_len and cand.score > prev.score
                ):
                    kept[-1] = cand
        return kept

    def scan_text(self, text: str) -> list[DetectedEntity]:
        """Detect sensitive entities in text without modifying or storing them."""
        if not text or not self.target_entities:
            return []

        protected_spans = [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(text)]
        raw_results = self.analyzer.analyze(
            text=text,
            language="en",
            entities=self.target_entities,
            score_threshold=self.config.masking.score_threshold,
        )

        filtered: list[RecognizerResult] = []
        for res in raw_results:
            if self._overlaps_placeholder(res.start, res.end, protected_spans):
                continue
            snippet = text[res.start : res.end].strip()
            if not snippet or snippet.lower() in self.config.allowlist_values:
                continue
            filtered.append(res)

        resolved = self._resolve_overlaps(filtered)
        return [
            DetectedEntity(
                entity_type=r.entity_type,
                start=r.start,
                end=r.end,
                score=round(float(r.score), 3),
            )
            for r in resolved
        ]

    def mask_text(self, text: str, session_id: str = "default") -> MaskResult:
        """Replace detected entities with deterministic placeholders stored in the vault."""
        entities = self.scan_text(text)
        if not entities:
            return MaskResult(text=text, entities=[])

        out = text
        # Replace right-to-left to preserve character offsets.
        for ent in reversed(entities):
            raw_value = out[ent.start : ent.end]
            placeholder = self.vault.get_or_create_placeholder(
                session_id=session_id,
                entity_type=ent.entity_type,
                raw_value=raw_value,
            )
            out = out[: ent.start] + placeholder + out[ent.end :]

        return MaskResult(text=out, entities=entities)

    def unmask_text(self, text: str, session_id: str | None = None) -> tuple[str, int]:
        """Restore placeholders in text to their original values."""
        return self.vault.unmask_text(text, session_id=session_id)

    def mask_payload(
        self,
        obj: Any,
        session_id: str = "default",
        _key: str | None = None,
    ) -> tuple[Any, list[str]]:
        """Recursively mask strings inside JSON payloads while skipping structural keys."""
        types_found: list[str] = []

        def _walk(node: Any, key: str | None) -> Any:
            if key and key.lower() in SKIP_JSON_KEYS:
                return node
            if isinstance(node, str):
                res = self.mask_text(node, session_id=session_id)
                for t in res.entity_types:
                    if t not in types_found:
                        types_found.append(t)
                return res.text
            if isinstance(node, list):
                return [_walk(item, key) for item in node]
            if isinstance(node, dict):
                return {k: _walk(v, k) for k, v in node.items()}
            return node

        return _walk(obj, _key), types_found

    def unmask_payload(self, obj: Any, session_id: str | None = None) -> tuple[Any, int]:
        """Recursively unmask placeholders inside JSON payloads."""
        total_restored = 0

        def _walk(node: Any) -> Any:
            nonlocal total_restored
            if isinstance(node, str):
                restored_text, count = self.unmask_text(node, session_id=session_id)
                total_restored += count
                return restored_text
            if isinstance(node, list):
                return [_walk(item) for item in node]
            if isinstance(node, dict):
                return {k: _walk(v) for k, v in node.items()}
            return node

        return _walk(obj), total_restored
