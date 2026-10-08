import re
from typing import List, Dict, Any, Tuple
from pydantic import BaseModel

class InjectionDetectionResult(BaseModel):
    is_injection: bool
    score: float
    reasons: List[str]

class PromptInjectionDetector:
    """
    Pluggable multi-heuristic prompt injection detector.
    Analyzes document chunks and prompts without relying on specific tool names alone.
    """

    PATTERNS: List[Tuple[str, str, float]] = [
        (r"ignore\s+(?:previous|prior|above|system)\s+instructions?", "IGNORE_INSTRUCTIONS_DIRECTIVE", 0.9),
        (r"(?:system\s*:|\[system\]|\[instruction\]|<impersonate>)", "ROLE_IMPERSONATION_MARKER", 0.85),
        (r"(?:call|execute|run|trigger)\s+(?:tool|function)\s+\w+", "TOOL_EXECUTION_COMMAND", 0.8),
        (r"(?:font-size:\s*0|color:\s*white|display:\s*none)", "HIDDEN_TEXT_MARKER", 0.95),
        (r"<!--[\s\S]*?(?:instruction|ignore|call|export)[\s\S]*?-->", "HTML_COMMENT_INJECTION", 0.9),
        (r"please\s+(?:also\s+)?(?:send|export|transfer|email)\s+.*?\s+to\s+[\w\.-]+@", "POLITE_EXFILTRATION_PHRASING", 0.85),
        (r"(?:[A-Za-z0-9+/]{40,}=*)", "BASE64_BLOB_PATTERN", 0.6)
    ]

    @classmethod
    def detect(cls, text: str) -> InjectionDetectionResult:
        reasons: List[str] = []
        max_score = 0.0

        for pattern, label, weight in cls.PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                reasons.append(f"Matched pattern: {label}")
                if weight > max_score:
                    max_score = weight

        is_inj = max_score >= 0.7 or len(reasons) >= 2
        return InjectionDetectionResult(
            is_injection=is_inj,
            score=max_score,
            reasons=reasons
        )

class SensitiveDataDetector:
    """
    Detects PII, secrets, credentials, and bulk data thresholds in tool arguments.
    """

    @staticmethod
    def inspect_tool_args(tool_args: Dict[str, Any], bulk_threshold: int = 100) -> List[str]:
        findings: List[str] = []
        text_repr = str(tool_args)

        # Check API key patterns
        if re.search(r"\b(?:sk|pk|api|key)_[a-zA-Z0-9]{20,}\b", text_repr) or re.search(r"\bAIzaSy[a-zA-Z0-9_-]{33}\b", text_repr):
            findings.append("SENSITIVE_DATA: Detected API Key in arguments")

        # Check SSN patterns
        if re.search(r"\b\d{3}-\d{2}-\d{4}\b", text_repr):
            findings.append("SENSITIVE_DATA: Detected SSN pattern in arguments")

        # Check bulk record count
        records_count = tool_args.get("records_count")
        if isinstance(records_count, int) and records_count > bulk_threshold:
            findings.append(f"BULK_DATA: Requested {records_count} records exceeds safety threshold ({bulk_threshold})")

        return findings
