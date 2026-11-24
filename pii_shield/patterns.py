"""Zero-dependency secret & PII regex definitions and FastRegexFallbackScanner."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

PLACEHOLDER_RE = re.compile(r"<<PII:[A-Z0-9_]+_[0-9]+>>")

SECRET_PATTERNS: list[tuple[str, str, float]] = [
    (
        "PRIVATE_KEY",
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        0.99,
    ),
    (
        "DB_URI",
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|sqlserver)://[^\s'\"<>:]+:[^\s'\"<>@]+@[^\s'\"<>]+",
        0.96,
    ),
    (
        "JWT_TOKEN",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        0.95,
    ),
    (
        "ANTHROPIC_API_KEY",
        r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
        0.98,
    ),
    (
        "OPENAI_API_KEY",
        r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b",
        0.95,
    ),
    (
        "GOOGLE_API_KEY",
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        0.95,
    ),
    (
        "AWS_ACCESS_KEY",
        r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        0.95,
    ),
    (
        "GITHUB_TOKEN",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
        0.97,
    ),
    (
        "GITLAB_TOKEN",
        r"\bglpat-[A-Za-z0-9_-]{20,}\b",
        0.97,
    ),
    (
        "SLACK_TOKEN",
        r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
        0.95,
    ),
    (
        "STRIPE_KEY",
        r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b",
        0.96,
    ),
    (
        "TELEGRAM_TOKEN",
        r"\b[0-9]{8,10}:AA[A-Za-z0-9_-]{30,36}\b",
        0.92,
    ),
    (
        "MIDTRANS_KEY",
        r"\b(?:SB-)?Mid-(?:server|client)-[A-Za-z0-9_-]{16,}\b",
        0.96,
    ),
    (
        "XENDIT_KEY",
        r"\bxnd_(?:development|production)_[A-Za-z0-9+/=_:-]{20,}\b",
        0.96,
    ),
    (
        "PACKAGE_TOKEN",
        r"\b(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,}|hf_[A-Za-z0-9]{34,})\b",
        0.96,
    ),
]

PII_PATTERNS: list[tuple[str, str, float]] = [
    (
        "ID_NIK",
        r"\b(?:1[1-9]|21|3[1-6]|5[1-3]|6[1-5]|7[1-6]|8[12]|9[1-6])(?:0[1-9]|[1-9][0-9])(?:0[1-9]|[1-9][0-9])(?:0[1-9]|[12][0-9]|3[01]|4[1-9]|[56][0-9]|7[01])(?:0[1-9]|1[0-2])[0-9]{2}(?!0000)[0-9]{4}\b",
        0.85,
    ),
    (
        "ID_PHONE",
        r"(?<!\w)(?:\+62[-\s]?|62[-\s]?|0)8[1-9][0-9]{7,11}(?!\w)",
        0.85,
    ),
    (
        "ID_PHONE",
        r"(?<!\w)(?:\+62[-\s]?|62[-\s]?|0)8[1-9][0-9]{1,3}[-\s][0-9]{3,4}[-\s][0-9]{3,5}(?!\w)",
        0.85,
    ),
]

CODE_EXPR_PREFIXES = (
    "os.getenv",
    "os.environ",
    "process.env",
    "env.",
    "config.",
    "settings.",
    "ctx.",
    "self.",
    "<<pii:",
)

BEARER_TOKEN_RE = re.compile(r"(?i)\b(?:Bearer|Basic)\s+(?P<val>[A-Za-z0-9._~+/=-]{20,})")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd|client_secret|api_secret|secret_key|auth_token|access_token|refresh_token|private_key)\b"
    r"\s*(?:=|:)\s*(?P<quote>['\"]?)(?P<val>[^\s'\"`,;}{)(]{8,})(?P=quote)"
)


def should_skip_secret_assignment(val: str, following_char: str, allowlist: set[str]) -> bool:
    low = val.lower()
    if low in allowlist:
        return True
    if val.startswith(("$", "{{", "<")) or PLACEHOLDER_RE.match(val):
        return True
    if low.startswith(CODE_EXPR_PREFIXES) or following_char == "(":
        return True
    if low.startswith(("http://", "https://")) and "@" not in val:
        return True
    if re.fullmatch(r"[A-Z0-9_]+", val):
        return True
    return False


@dataclass(frozen=True)
class FallbackMatch:
    entity_type: str
    start: int
    end: int
    score: float


def _dedupe_matches(matches: Iterable[FallbackMatch]) -> list[FallbackMatch]:
    ordered = sorted(matches, key=lambda m: (m.start, -(m.end - m.start), -m.score))
    kept: list[FallbackMatch] = []
    last_end = -1
    for m in ordered:
        if m.start >= last_end:
            kept.append(m)
            last_end = m.end
    return kept


class FastRegexFallbackScanner:
    """Zero-dependency pure-regex scanner used by hook scripts if the local server is offline."""

    _EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    _CC_RE = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")

    def __init__(
        self,
        detect_secrets: bool = True,
        detect_pii: bool = True,
        allowlist_values: set[str] | None = None,
    ) -> None:
        self.detect_secrets = detect_secrets
        self.detect_pii = detect_pii
        self.allowlist = allowlist_values or set()
        self._compiled_secrets = [
            (name, re.compile(pattern), score) for name, pattern, score in SECRET_PATTERNS
        ]
        self._compiled_pii = [
            (name, re.compile(pattern), score) for name, pattern, score in PII_PATTERNS
        ]

    @staticmethod
    def _luhn_ok(digits: str) -> bool:
        nums = [int(ch) for ch in digits if ch.isdigit()]
        if len(nums) < 13:
            return False
        checksum = 0
        for idx, num in enumerate(nums[::-1]):
            if idx % 2 == 1:
                num *= 2
                if num > 9:
                    num -= 9
            checksum += num
        return checksum % 10 == 0

    def scan(self, text: str) -> list[FallbackMatch]:
        if not text:
            return []
        matches: list[FallbackMatch] = []

        if self.detect_secrets:
            for name, regex, score in self._compiled_secrets:
                for m in regex.finditer(text):
                    matches.append(FallbackMatch(name, m.start(), m.end(), score))
            for m in BEARER_TOKEN_RE.finditer(text):
                val = m.group("val")
                if val.lower() not in self.allowlist and not PLACEHOLDER_RE.match(val):
                    matches.append(FallbackMatch("BEARER_TOKEN", m.start("val"), m.end("val"), 0.92))
            for m in SECRET_ASSIGNMENT_RE.finditer(text):
                val = m.group("val")
                end_pos = m.end("val")
                following = text[end_pos : end_pos + 1]
                if not should_skip_secret_assignment(val, following, self.allowlist):
                    matches.append(
                        FallbackMatch("SECRET_ASSIGNMENT", m.start("val"), end_pos, 0.85)
                    )

        if self.detect_pii:
            for name, regex, score in self._compiled_pii:
                for m in regex.finditer(text):
                    matches.append(FallbackMatch(name, m.start(), m.end(), score))
            for m in self._EMAIL_RE.finditer(text):
                if m.group(0).lower() not in self.allowlist:
                    matches.append(FallbackMatch("EMAIL_ADDRESS", m.start(), m.end(), 0.9))
            for m in self._CC_RE.finditer(text):
                if self._luhn_ok(m.group(0)):
                    matches.append(FallbackMatch("CREDIT_CARD", m.start(), m.end(), 0.9))

        return _dedupe_matches(matches)
