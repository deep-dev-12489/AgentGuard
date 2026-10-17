"""Deterministic AgentGuard policy engine and single-use human approval gateway."""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

from backend.detectors import SensitiveDataDetector

from backend.agent_logic import (
    AgentGuardDecision,
    ContextItem,
    LineageNode,
    SecurityDecisionType,
    SessionContext,
    ToolRiskLevel,
)
from backend.database import (
    AuditLogger,
    audit_logger,
    claim_pending_approval,
    compute_canonical_hash,
    get_all_pending_approvals,
    log_audit_event,
    save_pending_approval,
    update_approval_status,
)


DEFAULT_FALLBACK_POLICY: Dict[str, Any] = {
    "tool_risk_levels": {
        "export_customer_data": "CRITICAL",
        "send_email": "HIGH",
        "search_academic_db": "LOW",
    },
    "defaults": {
        "unknown_tool_risk": "CRITICAL",
        "default_verdict": "BLOCK",
        "bulk_record_threshold": 100,
    },
    "destinations": {
        "allowed_email_domains": ["org.com", "trusted-partner.org", "company.com"],
        "allowed_api_hosts": ["api.ncbi.nlm.nih.gov", "export.arxiv.org"],
    },
    "evaluations": {
        "untrusted_context_high_critical": "BLOCK",
        "untrusted_context_medium": "REVIEW",
        "untrusted_context_low": "ALLOW",
        "untainted_critical": "REVIEW",
        "untainted_allowlisted": "ALLOW",
    },
}

EMAIL_TOOL_NAMES = {"send_email", "export_customer_data"}
EMAIL_PATTERN = re.compile(r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}$", re.I)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _safe_decision(value: Any, fallback: SecurityDecisionType = SecurityDecisionType.BLOCK) -> SecurityDecisionType:
    try:
        return SecurityDecisionType(str(value).strip().upper())
    except (ValueError, TypeError):
        return fallback


def _safe_lineage_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """Avoid embedding long email bodies, secrets, or unbounded values in lineage."""
    result: Dict[str, Any] = {}
    for key, value in list(args.items())[:30]:
        lower_key = str(key).lower()
        if any(word in lower_key for word in ("token", "password", "secret", "api_key", "credential")):
            result[str(key)] = "[REDACTED]"
        elif lower_key in {"body", "content", "document_text", "prompt"}:
            result[str(key)] = f"[redacted text: {len(str(value))} characters]"
        elif isinstance(value, str):
            result[str(key)] = value[:160]
        elif isinstance(value, (int, float, bool)) or value is None:
            result[str(key)] = value
        else:
            result[str(key)] = f"[{type(value).__name__}]"
    return result


class PolicyEngine:
    """Hot-reload policy.yaml and fail closed when the file is invalid."""

    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = Path(policy_path) if policy_path else Path(__file__).resolve().parent / "policy.yaml"
        self._cached_policy: Optional[Dict[str, Any]] = None
        self._last_mtime: Optional[float] = None
        self._lock = RLock()

    def load_policy(self) -> Dict[str, Any]:
        with self._lock:
            try:
                if not self.policy_path.exists():
                    return self._cached_policy or DEFAULT_FALLBACK_POLICY
                mtime = self.policy_path.stat().st_mtime
                if self._cached_policy is not None and mtime == self._last_mtime:
                    return self._cached_policy
                with self.policy_path.open("r", encoding="utf-8") as handle:
                    loaded = yaml.safe_load(handle)
                if not isinstance(loaded, dict):
                    raise ValueError("Policy root must be a YAML mapping")
                # Required top-level fields are normalized before accepting the update.
                for section in ("tool_risk_levels", "defaults", "destinations", "evaluations"):
                    if section in loaded and not isinstance(loaded[section], dict):
                        raise ValueError(f"Policy section '{section}' must be a mapping")
                merged = {
                    **DEFAULT_FALLBACK_POLICY,
                    **loaded,
                    "tool_risk_levels": {
                        **DEFAULT_FALLBACK_POLICY["tool_risk_levels"],
                        **loaded.get("tool_risk_levels", {}),
                    },
                    "defaults": {**DEFAULT_FALLBACK_POLICY["defaults"], **loaded.get("defaults", {})},
                    "destinations": {
                        **DEFAULT_FALLBACK_POLICY["destinations"],
                        **loaded.get("destinations", {}),
                    },
                    "evaluations": {
                        **DEFAULT_FALLBACK_POLICY["evaluations"],
                        **loaded.get("evaluations", {}),
                    },
                }
                self._cached_policy = merged
                self._last_mtime = mtime
                return merged
            except Exception:
                # Invalid policy must not accidentally authorize a new action.
                return DEFAULT_FALLBACK_POLICY

    def get_tool_risk_level(self, tool_name: str) -> ToolRiskLevel:
        policy = self.load_policy()
        raw = policy.get("tool_risk_levels", {}).get(
            tool_name,
            policy.get("defaults", {}).get("unknown_tool_risk", "CRITICAL"),
        )
        try:
            return ToolRiskLevel(str(raw).strip().upper())
        except (TypeError, ValueError):
            return ToolRiskLevel.CRITICAL

    def is_destination_allowlisted(self, destination: str) -> bool:
        destination = str(destination or "").strip()
        if not EMAIL_PATTERN.fullmatch(destination):
            return False
        domain = destination.rsplit("@", 1)[-1].lower().rstrip(".")
        allowed = self.load_policy().get("destinations", {}).get("allowed_email_domains", [])
        safe_allowed = {str(item).strip().lower().rstrip(".") for item in allowed if isinstance(item, str)}
        # Exact-domain matching avoids allowing lookalike subdomains.
        return domain in safe_allowed

    def get_bulk_threshold(self) -> int:
        try:
            value = int(self.load_policy().get("defaults", {}).get("bulk_record_threshold", 100))
            return max(1, min(value, 1_000_000))
        except (TypeError, ValueError):
            return 100


policy_engine = PolicyEngine()


class SecurityGateway:
    """Deterministic policy enforcement; model output is never the security authority."""

    def __init__(self, engine: Optional[PolicyEngine] = None):
        self.engine = engine or policy_engine

    def evaluate_action(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        session_context: SessionContext,
        detected_injection_text: Optional[str] = None,
        human_approved: bool = False,
    ) -> AgentGuardDecision:
        policy = self.engine.load_policy()
        rules = policy.get("evaluations", {})
        defaults = policy.get("defaults", {})
        risk_level = self.engine.get_tool_risk_level(tool_name)
        is_tainted = session_context.has_untrusted_content
        provenance_source = session_context.provenance_label
        checks: List[str] = []
        reasons: List[str] = []
        verdict = SecurityDecisionType.BLOCK

        args = tool_args if isinstance(tool_args, dict) else {}
        target_email = str(args.get("target_email", "")).strip()
        destination_allowlisted = self.engine.is_destination_allowlisted(target_email)
        records_count = args.get("records_count")
        bulk_threshold = self.engine.get_bulk_threshold()
        bulk_violation = (
            tool_name == "export_customer_data"
            and (
                isinstance(records_count, bool)
                or not isinstance(records_count, int)
                or records_count < 1
                or records_count > bulk_threshold
            )
        )

        sensitive_findings = SensitiveDataDetector.inspect_tool_args(args, bulk_threshold)
        sensitive_outbound_violation = tool_name in EMAIL_TOOL_NAMES and any(
            finding.startswith("SENSITIVE_DATA:") for finding in sensitive_findings
        )

        # Hard-stop checks always run before any ALLOW/REVIEW branch.
        # Preserve the taint decision priority so a malicious document is always
        # identified as the reason for blocking a high-risk action.
        if detected_injection_text:
            verdict = SecurityDecisionType.BLOCK
            checks.append("PROMPT_INJECTION_DETECTED_BLOCK")
            reasons.append("Prompt-injection-like content was detected; the proposed action was blocked.")
        elif is_tainted and risk_level in (ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL):
            verdict = _safe_decision(
                rules.get("untrusted_context_high_critical", "BLOCK"),
                SecurityDecisionType.BLOCK,
            )
            if verdict != SecurityDecisionType.BLOCK:
                # Never allow a configuration edit to turn tainted high-risk actions into ALLOW.
                verdict = SecurityDecisionType.BLOCK
            checks.append("TAINTED_CONTEXT_HIGH_RISK_BLOCK")
            reasons.append(
                f"Action '{tool_name}' was requested with untrusted document content in context. "
                f"Risk level is {risk_level.value}; document content is not authorization."
            )
        elif bulk_violation:
            verdict = SecurityDecisionType.BLOCK
            checks.append("BULK_THRESHOLD_EXCEEDED_BLOCK")
            reasons.append(
                f"Requested record count must be between 1 and {bulk_threshold}; the export was blocked."
            )
        elif sensitive_outbound_violation:
            verdict = SecurityDecisionType.BLOCK
            checks.append("SENSITIVE_DATA_OUTBOUND_BLOCK")
            reasons.append(
                "Outbound email/export arguments contain a possible credential or sensitive identifier; action blocked."
            )
        elif tool_name in EMAIL_TOOL_NAMES and not destination_allowlisted:
            verdict = SecurityDecisionType.BLOCK
            checks.append("DESTINATION_NOT_ALLOWLISTED_BLOCK")
            reasons.append("The destination email is invalid or its exact domain is not allowlisted.")
        elif tool_name == "send_email" and not all(
            isinstance(args.get(key), str) for key in ("subject", "body")
        ):
            verdict = SecurityDecisionType.BLOCK
            checks.append("EMAIL_ARGUMENTS_INVALID_BLOCK")
            reasons.append("Email action requires string subject and body fields.")
        elif tool_name == "search_academic_db" and not isinstance(args.get("query"), str):
            verdict = SecurityDecisionType.BLOCK
            checks.append("ACADEMIC_QUERY_INVALID_BLOCK")
            reasons.append("Academic search requires a string query.")
        else:
            if is_tainted and risk_level == ToolRiskLevel.MEDIUM:
                verdict = _safe_decision(rules.get("untrusted_context_medium", "REVIEW"))
                if verdict == SecurityDecisionType.ALLOW:
                    verdict = SecurityDecisionType.REVIEW
                checks.append("TAINTED_CONTEXT_MEDIUM_RISK_REVIEW")
                reasons.append("A medium-risk action with untrusted context requires human review.")
            elif is_tainted and risk_level == ToolRiskLevel.LOW:
                verdict = _safe_decision(rules.get("untrusted_context_low", "ALLOW"))
                checks.append("TAINTED_CONTEXT_LOW_RISK_POLICY")
                reasons.append("Low-risk read-only action was evaluated under the untrusted-context policy.")
            elif risk_level == ToolRiskLevel.CRITICAL:
                if human_approved:
                    verdict = SecurityDecisionType.ALLOW
                    checks.append("HUMAN_APPROVAL_VERIFIED")
                    reasons.append("The critical action passed policy checks and has a verified human approval.")
                else:
                    verdict = SecurityDecisionType.REVIEW
                    checks.append("CRITICAL_ACTION_REQUIRES_HUMAN_REVIEW")
                    reasons.append("Critical actions require a separate human approval before execution.")
            elif risk_level == ToolRiskLevel.HIGH:
                if destination_allowlisted:
                    verdict = _safe_decision(rules.get("untainted_allowlisted", "ALLOW"))
                    checks.append("HIGH_RISK_ALLOWLISTED_DESTINATION")
                    reasons.append("High-risk action targets an allowlisted destination.")
                else:
                    verdict = SecurityDecisionType.BLOCK
                    checks.append("HIGH_RISK_DESTINATION_BLOCK")
                    reasons.append("High-risk action is not allowed to use an unapproved destination.")
            elif risk_level == ToolRiskLevel.MEDIUM:
                verdict = SecurityDecisionType.ALLOW if human_approved else SecurityDecisionType.REVIEW
                checks.append("MEDIUM_RISK_POLICY")
                reasons.append("Medium-risk action was evaluated by deterministic policy.")
            else:
                verdict = SecurityDecisionType.ALLOW
                checks.append("LOW_RISK_READ_ONLY_POLICY")
                reasons.append("Low-risk action is permitted by policy.")

        # Unknown tools may appear as REVIEW for visibility, but MCPGateway will never
        # execute a tool that is not in GUARDED_TOOL_REGISTRY.
        safe_args = _safe_lineage_args(args)
        lineage: List[LineageNode] = []
        for index, item in enumerate(session_context.items, start=1):
            lineage.append(
                LineageNode(
                    id=f"node-{index}",
                    type="DOCUMENT" if not item.is_trusted else "USER_PROMPT",
                    label=f"{index}. Source Context ({item.source_type})",
                    details=f"Source={item.source_type}; trusted={item.is_trusted}; chars={len(item.content)}",
                    is_tainted=not item.is_trusted,
                )
            )
        next_id = len(lineage) + 1
        if detected_injection_text:
            lineage.append(
                LineageNode(
                    id=f"node-{next_id}",
                    type="INSTRUCTION",
                    label=f"{next_id}. Suspected Injection",
                    details="A prompt-injection detector supplied a blocking signal.",
                    is_tainted=True,
                )
            )
            next_id += 1
        lineage.extend(
            [
                LineageNode(
                    id=f"node-{next_id}",
                    type="AGENT",
                    label=f"{next_id}. Agent Action Proposal",
                    details=f"A proposal for tool '{tool_name}' was evaluated.",
                    is_tainted=is_tainted,
                ),
                LineageNode(
                    id=f"node-{next_id + 1}",
                    type="TOOL_REQUEST",
                    label=f"{next_id + 1}. Tool Request",
                    details=f"Tool={tool_name}; risk={risk_level.value}; args={safe_args}",
                    is_tainted=is_tainted,
                ),
                LineageNode(
                    id=f"node-{next_id + 2}",
                    type="SECURITY_DECISION",
                    label=f"{next_id + 2}. AgentGuard Decision ({verdict.value})",
                    details=reasons[0] if reasons else verdict.value,
                    is_tainted=is_tainted,
                ),
            ]
        )

        return AgentGuardDecision(
            decision=verdict,
            verdict=verdict.value,
            tool_name=tool_name,
            tool_args=args,
            provenance_source=provenance_source,
            is_tainted=is_tainted,
            risk_level=risk_level,
            reason=reasons[0] if reasons else verdict.value,
            reasons=reasons,
            checks_fired=checks,
            action_lineage=lineage,
        )


security_gateway = SecurityGateway()


class AgentGuardInterceptor:
    """Backward-compatible interceptor facade."""

    @staticmethod
    def inspect_and_evaluate(
        tool_name: str,
        tool_args: Dict[str, Any],
        session_context: SessionContext,
        detected_injection_text: Optional[str] = None,
        human_approved: bool = False,
    ) -> AgentGuardDecision:
        return security_gateway.evaluate_action(
            tool_name=tool_name,
            tool_args=tool_args,
            session_context=session_context,
            detected_injection_text=detected_injection_text,
            human_approved=human_approved,
        )


class PendingApproval(BaseModel):
    approval_id: str = Field(default_factory=lambda: f"appr-{uuid.uuid4().hex[:12]}")
    tool_name: str
    tool_args: Dict[str, Any]
    args_hash: str = ""
    reason: str
    risk_level: ToolRiskLevel
    provenance_source: str
    created_at: str = Field(default_factory=lambda: _utc_now().isoformat())
    status: str = "PENDING"


class MCPGateway:
    """Persistent approval queue with single-use, integrity-checked execution."""

    def __init__(self):
        self.pending_approvals: Dict[str, PendingApproval] = {}
        self._lock = RLock()
        self._sync_from_db()

    def _sync_from_db(self) -> None:
        rows = get_all_pending_approvals()
        with self._lock:
            self.pending_approvals = {}
            for row in rows:
                try:
                    approval = PendingApproval(
                        approval_id=row["approval_id"],
                        tool_name=row["tool_name"],
                        tool_args=row["tool_args"],
                        args_hash=row["args_hash"],
                        reason=row["reason"],
                        risk_level=self._normalize_risk(row["risk_level"]),
                        provenance_source=row["provenance_source"],
                        created_at=row["created_at"],
                        status=row["status"],
                    )
                    self.pending_approvals[approval.approval_id] = approval
                except Exception:
                    # Malformed historical entries are omitted, never executed.
                    continue

    @staticmethod
    def _normalize_risk(value: Any) -> ToolRiskLevel:
        try:
            return ToolRiskLevel(str(value).upper())
        except ValueError:
            return ToolRiskLevel.CRITICAL

    def queue_for_human_review(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        reason: str,
        risk_level: Any,
        provenance_source: str,
    ) -> PendingApproval:
        if not isinstance(tool_args, dict):
            raise ValueError("Tool arguments must be a JSON object.")
        approval_id = f"appr-{uuid.uuid4().hex[:12]}"
        risk = self._normalize_risk(risk_level)
        args_hash = save_pending_approval(
            approval_id=approval_id,
            tool_name=tool_name,
            tool_args=tool_args,
            reason=reason,
            risk_level=risk.value,
            provenance_source=provenance_source,
        )
        approval = PendingApproval(
            approval_id=approval_id,
            tool_name=tool_name,
            tool_args=tool_args,
            args_hash=args_hash,
            reason=reason,
            risk_level=risk,
            provenance_source=provenance_source,
        )
        with self._lock:
            self.pending_approvals[approval.approval_id] = approval
        return approval

    def approve_tool_call(
        self,
        approval_id: str,
        expected_hash: Optional[str] = None,
        canonical_args: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._sync_from_db()
        approval = self.pending_approvals.get(approval_id)
        if approval is None:
            raise KeyError(f"Approval ID '{approval_id}' was not found, is expired, or was already used.")

        try:
            is_expired = _utc_now() - _as_utc(approval.created_at) > timedelta(minutes=10)
        except (ValueError, TypeError):
            is_expired = True
        if is_expired:
            update_approval_status(approval_id, "EXPIRED")
            with self._lock:
                self.pending_approvals.pop(approval_id, None)
            raise ValueError("APPROVAL_EXPIRED: Approval requests are valid for 10 minutes.")

        if expected_hash is not None and expected_hash != approval.args_hash:
            raise ValueError("ARGUMENT_TAMPERING_REJECTED: The supplied hash does not match the stored hash.")

        effective_args = canonical_args if canonical_args is not None else approval.tool_args
        if not isinstance(effective_args, dict):
            raise ValueError("ARGUMENT_TAMPERING_REJECTED: Tool arguments must be a JSON object.")
        computed_hash = compute_canonical_hash(approval.tool_name, effective_args)
        # Always verify stored arguments, even when a caller omits expected_hash.
        if computed_hash != approval.args_hash:
            raise ValueError("ARGUMENT_TAMPERING_REJECTED: Stored or supplied arguments do not match the approval hash.")

        from backend.agent_logic import GUARDED_TOOL_REGISTRY

        tool = GUARDED_TOOL_REGISTRY.get(approval.tool_name)
        if tool is None:
            raise ValueError("UNKNOWN_TOOL_APPROVAL_REJECTED: Unregistered tools cannot be executed.")

        # Atomically transition PENDING -> PROCESSING to prevent duplicate execution.
        if not claim_pending_approval(approval_id):
            self._sync_from_db()
            raise ValueError("APPROVAL_ALREADY_USED: This approval is no longer pending.")

        trusted_context = SessionContext(
            items=[
                ContextItem(
                    id="human-approval",
                    source_type="human_reviewer",
                    content="Explicit human reviewer approval for this exact hash-bound action.",
                    is_trusted=True,
                )
            ]
        )
        decision, execution_result = tool.invoke_guarded(
            tool_args=effective_args,
            session_context=trusted_context,
            detected_injection_text=None,
            human_approved=True,
        )

        allowed = decision.decision == SecurityDecisionType.ALLOW
        final_status = "APPROVED" if allowed else "BLOCKED"
        update_approval_status(approval_id, final_status)
        log_audit_event(
            approval_id=approval_id,
            tool_name=approval.tool_name,
            tool_args=effective_args,
            decision="APPROVED" if allowed else "BLOCKED_BY_POLICY",
            result=execution_result,
        )
        with self._lock:
            self.pending_approvals.pop(approval_id, None)

        return {
            "approval_id": approval_id,
            "tool_name": approval.tool_name,
            "args": effective_args,
            "decision": "APPROVED" if allowed else "BLOCKED",
            "policy_decision": decision.decision.value,
            "result": execution_result,
            "timestamp": _utc_now().isoformat(),
        }

    def reject_tool_call(self, approval_id: str) -> Dict[str, Any]:
        self._sync_from_db()
        approval = self.pending_approvals.get(approval_id)
        if approval is None:
            raise KeyError(f"Approval ID '{approval_id}' was not found, expired, or already used.")
        if not claim_pending_approval(approval_id):
            self._sync_from_db()
            raise ValueError("APPROVAL_ALREADY_USED: This approval is no longer pending.")

        update_approval_status(approval_id, "REJECTED")
        result = "EXECUTION REJECTED BY HUMAN OPERATOR; no tool was run."
        log_audit_event(
            approval_id=approval_id,
            tool_name=approval.tool_name,
            tool_args=approval.tool_args,
            decision="REJECTED",
            result=result,
        )
        with self._lock:
            self.pending_approvals.pop(approval_id, None)
        return {
            "approval_id": approval_id,
            "tool_name": approval.tool_name,
            "args": approval.tool_args,
            "decision": "REJECTED",
            "result": result,
            "timestamp": _utc_now().isoformat(),
        }

    def get_pending_list(self) -> List[PendingApproval]:
        self._sync_from_db()
        return sorted(self.pending_approvals.values(), key=lambda item: item.created_at)


mcp_gateway = MCPGateway()

__all__ = [
    "PolicyEngine",
    "SecurityGateway",
    "policy_engine",
    "security_gateway",
    "AgentGuardInterceptor",
    "PendingApproval",
    "MCPGateway",
    "mcp_gateway",
    "AuditLogger",
    "audit_logger",
]
