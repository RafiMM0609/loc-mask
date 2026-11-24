"""Presidio PatternRecognizer and EntityRecognizer wrappers built from pii_shield.patterns."""

from __future__ import annotations

from presidio_analyzer import EntityRecognizer, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts

from pii_shield.config import AppConfig
from pii_shield.patterns import (
    BEARER_TOKEN_RE,
    PII_PATTERNS,
    PLACEHOLDER_RE,
    SECRET_ASSIGNMENT_RE,
    SECRET_PATTERNS,
    should_skip_secret_assignment,
)


class BearerTokenRecognizer(EntityRecognizer):
    """Extracts only the credential token after 'Bearer ' or 'Basic '."""

    def __init__(self, allowlist: set[str] | None = None) -> None:
        self.allowlist = allowlist or set()
        super().__init__(
            supported_entities=["BEARER_TOKEN"],
            supported_language="en",
            name="BearerTokenRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if entities and "BEARER_TOKEN" not in entities:
            return []
        results: list[RecognizerResult] = []
        for match in BEARER_TOKEN_RE.finditer(text):
            val = match.group("val")
            if val.lower() in self.allowlist or PLACEHOLDER_RE.match(val):
                continue
            results.append(
                RecognizerResult(
                    entity_type="BEARER_TOKEN",
                    start=match.start("val"),
                    end=match.end("val"),
                    score=0.92,
                )
            )
        return results


class SecretAssignmentRecognizer(EntityRecognizer):
    """Detects hardcoded secret values assigned in .env, JSON, YAML, or code."""

    def __init__(self, allowlist: set[str] | None = None) -> None:
        self.allowlist = allowlist or set()
        super().__init__(
            supported_entities=["SECRET_ASSIGNMENT"],
            supported_language="en",
            name="SecretAssignmentRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if entities and "SECRET_ASSIGNMENT" not in entities:
            return []
        results: list[RecognizerResult] = []
        for match in SECRET_ASSIGNMENT_RE.finditer(text):
            val = match.group("val")
            end_pos = match.end("val")
            following = text[end_pos : end_pos + 1]
            if should_skip_secret_assignment(val, following, self.allowlist):
                continue
            results.append(
                RecognizerResult(
                    entity_type="SECRET_ASSIGNMENT",
                    start=match.start("val"),
                    end=end_pos,
                    score=0.85,
                )
            )
        return results


def build_custom_recognizers(config: AppConfig) -> list[EntityRecognizer]:
    """Create all configured custom PatternRecognizer and EntityRecognizer instances."""
    recognizers: list[EntityRecognizer] = []

    if config.masking.detect_secrets:
        for entity_name, regex, score in SECRET_PATTERNS:
            recognizers.append(
                PatternRecognizer(
                    supported_entity=entity_name,
                    patterns=[Pattern(name=entity_name.lower(), regex=regex, score=score)],
                    supported_language="en",
                )
            )
        recognizers.append(BearerTokenRecognizer(allowlist=config.allowlist_values))
        recognizers.append(SecretAssignmentRecognizer(allowlist=config.allowlist_values))

    if config.masking.detect_pii:
        grouped_pii: dict[str, list[Pattern]] = {}
        for idx, (entity_name, regex, score) in enumerate(PII_PATTERNS):
            grouped_pii.setdefault(entity_name, []).append(
                Pattern(name=f"{entity_name.lower()}_{idx}", regex=regex, score=score)
            )
        for entity_name, patterns in grouped_pii.items():
            recognizers.append(
                PatternRecognizer(
                    supported_entity=entity_name,
                    patterns=patterns,
                    supported_language="en",
                )
            )

    for custom in config.custom_patterns:
        recognizers.append(
            PatternRecognizer(
                supported_entity=custom.name,
                patterns=[Pattern(name=custom.name.lower(), regex=custom.pattern, score=custom.score)],
                supported_language="en",
            )
        )

    return recognizers
