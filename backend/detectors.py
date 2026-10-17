"""Bounded heuristic detectors for prompt injection and sensitive action data.

These patterns are one defense layer, not a guarantee that all attacks will be
identified. The caller should retain deterministic taint and action policies.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Dict, List, Tuple

from pydantic import BaseModel, Field


MAX_DETECTION_CHARS = 200_000


class InjectionDetectionResult(BaseModel):
    is_injection: bool
    score: float = Field(ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)


class PromptInjectionDetector:
    """Detect common explicit, hidden, encoded, and multilingual injection cues."""

    PATTERNS: List[Tuple[str, str, float]] = [
        (r"ignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+instructions?", "IGNORE_INSTRUCTIONS_DIRECTIVE", 0.95),
        (r"(?:disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|system)\s+instructions?", "DISREGARD_INSTRUCTIONS_DIRECTIVE", 0.90),
        (r"(?:system\s*:|\[system\]|\[instruction\]|<impersonate>)", "ROLE_IMPERSONATION_MARKER", 0.85),
        (r"(?:system|developer|admin)\s+(?:directive|instruction|override|message)\s*:", "PRIVILEGED_DIRECTIVE_MARKER", 0.90),
        (r"(?:call|execute|run|trigger)\s+(?:tool|function)\s+\w+", "TOOL_EXECUTION_COMMAND", 0.85),
        (r"(?:call|execute|run|trigger)\s+(?:export_customer_data|send_email|search_academic_db)\b", "DIRECT_TOOL_NAME_COMMAND", 0.90),
        (r"(?:override|bypass)\s+(?:the\s+)?(?:system\s+)?(?:rules|policy|instructions)", "POLICY_OVERRIDE_DIRECTIVE", 0.85),
        (r"(?:instrucci[oó]n(?:es)?\s+del\s+sistema|ignora\s+(?:las\s+)?instrucciones|ejecutar\s+(?:la\s+)?herramienta)", "SPANISH_INJECTION_CUE", 0.85),
        (r"(?:font-size\s*:\s*0|color\s*:\s*white|display\s*:\s*none)", "HIDDEN_TEXT_MARKER", 0.95),
        (r"<!--[\s\S]*?(?:instruction|ignore|call|export|system)[\s\S]*?-->", "HTML_COMMENT_INJECTION", 0.90),
        (r"please\s+(?:also\s+)?(?:send|export|transfer|email)\s+.*?\s+to\s+[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "POLITE_EXFILTRATION_PHRASING", 0.90),
        (r"(?:note\s+to\s+(?:the\s+)?model|message\s+to\s+the\s+assistant)\s*:", "MODEL_DIRECTIVE_MARKER", 0.75),
        (r"(?:base64|encoded)\s+(?:payload|instruction|directive)\s*:\s*[A-Za-z0-9+/]{20,}={0,2}", "ENCODED_DIRECTIVE_PAYLOAD", 0.80),
        (r"[A-Za-z0-9+/]{40,}={0,2}", "BASE64_BLOB_PATTERN", 0.60),
    ]

    @classmethod
    def detect(cls, text: str) -> InjectionDetectionResult:
        if not isinstance(text, str) or not text:
            return InjectionDetectionResult(is_injection=False, score=0.0, reasons=[])

        # Bound regex work on unusually large user-supplied text.
        sample = text[:MAX_DETECTION_CHARS]
        reasons: List[str] = []
        max_score = 0.0

        for pattern, label, weight in cls.PATTERNS:
            if re.search(pattern, sample, re.IGNORECASE):
                reasons.append(label)
                max_score = max(max_score, weight)

        decoded_reason = cls._detect_encoded_instruction(sample)
        if decoded_reason:
            reasons.append(decoded_reason)
            max_score = max(max_score, 0.9)

        is_injection = max_score >= 0.75 or len(reasons) >= 2
        return InjectionDetectionResult(is_injection=is_injection, score=min(max_score, 1.0), reasons=reasons)

    @staticmethod
    def _detect_encoded_instruction(text: str) -> str | None:
        """Flag a base64 token only when decoding reveals a likely action directive."""
        candidates = re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])", text[:MAX_DETECTION_CHARS])
        directive_pattern = re.compile(
            r"(?:ignore\s+(?:previous|prior)|system\s+instruction|export_customer_data|send_email|"
            r"call\s+(?:the\s+)?tool|execute\s+(?:the\s+)?tool|exfiltrat)",
            re.IGNORECASE,
        )
        for token in candidates[:20]:
            try:
                decoded = base64.b64decode(token + "=" * ((4 - len(token) % 4) % 4), validate=False)
                decoded_text = decoded.decode("utf-8", errors="ignore")[:2_000]
            except Exception:
                continue
            if len(decoded_text) >= 8 and directive_pattern.search(decoded_text):
                return "DECODED_BASE64_INSTRUCTION"
        return None


class SensitiveDataDetector:
    """Detect common API-key/SSN patterns and excessive record exports."""

    SECRET_PATTERNS = [
        re.compile(r"\b(?:sk|pk|api|key)_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bAIzaSy[A-Za-z0-9_-]{33}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    ]
    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    @classmethod
    def inspect_tool_args(cls, tool_args: Dict[str, Any], bulk_threshold: int = 100) -> List[str]:
        findings: List[str] = []
        try:
            text_repr = str(tool_args)[:MAX_DETECTION_CHARS]
        except Exception:
            return ["SENSITIVE_DATA: Unable to safely inspect tool arguments"]

        if any(pattern.search(text_repr) for pattern in cls.SECRET_PATTERNS):
            findings.append("SENSITIVE_DATA: Detected a possible API key or credential in arguments")
        if cls.SSN_PATTERN.search(text_repr):
            findings.append("SENSITIVE_DATA: Detected a possible SSN pattern in arguments")

        record_count = tool_args.get("records_count")
        if isinstance(record_count, int) and not isinstance(record_count, bool) and record_count > bulk_threshold:
            findings.append(
                f"BULK_DATA: Requested {record_count} records exceeds safety threshold ({bulk_threshold})"
            )
        return findings
