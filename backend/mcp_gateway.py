import os
import sys
import uuid
import yaml

# Ensure backend directory is in sys.path
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from pydantic import BaseModel, Field

from fastapi import HTTPException

from agent_logic import (
    ToolRiskLevel,
    SecurityDecisionType,
    SessionContext,
    ContextItem,
    AgentGuardDecision,
    LineageNode,
)
from database import (
    save_pending_approval,
    get_all_pending_approvals,
    update_approval_status,
    log_audit_event,
    compute_canonical_hash,
    log_security_evaluation,
    get_security_audit_logs,
    AuditLogger,
    audit_logger,
)

# =====================================================================
# 1. Dynamic Policy Engine (PyYAML)
# =====================================================================

def normalize_risk_level(val: Any) -> ToolRiskLevel:
    """Safely normalizes any string or enum value to ToolRiskLevel."""
    if isinstance(val, ToolRiskLevel):
        return val
    s = str(val).strip().upper()
    if "CRITICAL" in s:
        return ToolRiskLevel.CRITICAL
    if "HIGH" in s:
        return ToolRiskLevel.HIGH
    if "MEDIUM" in s:
        return ToolRiskLevel.MEDIUM
    if "LOW" in s:
        return ToolRiskLevel.LOW
    return ToolRiskLevel.CRITICAL

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
        "allowed_api_hosts": ["api.ncbi.nlm.nih.gov", "export.arxiv.org", "internal-db.company.com"],
    },
    "evaluations": {
        "untrusted_context_high_critical": "BLOCK",
        "untrusted_context_medium": "REVIEW",
        "untrusted_context_low": "ALLOW",
        "untainted_critical": "REVIEW",
        "untainted_allowlisted": "ALLOW",
    },
}

class PolicyEngine:
    """
    Dynamic Security Policy Engine.
    Dynamically loads rules from policy.yaml via PyYAML and auto-refreshes when
    the configuration file is modified on disk, enabling zero-downtime policy updates.
    """

    def __init__(self, policy_path: Optional[str] = None):
        if policy_path is None:
            self.policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")
        else:
            self.policy_path = policy_path
        self._cached_policy: Optional[Dict[str, Any]] = None
        self._last_mtime: float = 0

    def load_policy(self) -> Dict[str, Any]:
        """Dynamically reads rules from policy.yaml using PyYAML."""
        try:
            if os.path.exists(self.policy_path):
                current_mtime = os.path.getmtime(self.policy_path)
                if self._cached_policy is None or current_mtime != self._last_mtime:
                    with open(self.policy_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if isinstance(data, dict):
                            self._cached_policy = data
                            self._last_mtime = current_mtime
                    return self._cached_policy
                return self._cached_policy
        except Exception:
            pass
        return self._cached_policy or DEFAULT_FALLBACK_POLICY

    def get_tool_risk_level(self, tool_name: str) -> ToolRiskLevel:
        """Determines tool risk level dynamically from policy.yaml."""
        policy = self.load_policy()
        tool_risk_levels = policy.get("tool_risk_levels", {})
        defaults = policy.get("defaults", {})
        risk_str = tool_risk_levels.get(tool_name, defaults.get("unknown_tool_risk", "CRITICAL"))
        try:
            return ToolRiskLevel(str(risk_str).upper())
        except ValueError:
            return ToolRiskLevel.CRITICAL

    def is_destination_allowlisted(self, destination: str) -> bool:
        """Evaluates whether an outbound destination is allowlisted in policy.yaml."""
        policy = self.load_policy()
        destinations = policy.get("destinations", {})
        allowed_domains = [d.lower() for d in destinations.get("allowed_email_domains", [])]
        if "@" in destination:
            domain = destination.split("@")[-1].lower()
            return domain in allowed_domains
        return False

    def get_bulk_threshold(self) -> int:
        """Reads bulk record safety threshold dynamically from policy.yaml."""
        policy = self.load_policy()
        return int(policy.get("defaults", {}).get("bulk_record_threshold", 100))

policy_engine = PolicyEngine()

# =====================================================================
# 2. Dynamic Security Gateway & Interceptor Logic
# =====================================================================

class SecurityGateway:
    """
    Security Gateway & Interceptor.
    Enforces 'Information != Authorization' with dynamic policy evaluation from policy.yaml.
    Tracks context provenance taint, destination allowlists, and bulk safety thresholds.
    """

    def __init__(self, engine: Optional[PolicyEngine] = None):
        self.engine = engine or policy_engine

    def evaluate_action(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        session_context: SessionContext,
        detected_injection_text: Optional[str] = None
    ) -> AgentGuardDecision:
        policy = self.engine.load_policy()
        eval_rules = policy.get("evaluations", {})
        defaults = policy.get("defaults", {})
        destinations = policy.get("destinations", {})
        allowed_domains = destinations.get("allowed_email_domains", [])
        default_verdict_str = defaults.get("default_verdict", "BLOCK")

        # 1. Dynamic Tool Risk Classification
        risk_level = self.engine.get_tool_risk_level(tool_name)

        # 2. Provenance Taint Determination
        is_tainted = session_context.has_untrusted_content
        provenance_source = session_context.provenance_label

        # 3. Dynamic Destination Allowlist Check
        target_email = tool_args.get("target_email", "")
        destination_allowlisted = self.engine.is_destination_allowlisted(target_email)

        # 4. Dynamic Bulk Data Safety Check
        bulk_threshold = self.engine.get_bulk_threshold()
        records_count = tool_args.get("records_count")
        bulk_violation = isinstance(records_count, int) and records_count > bulk_threshold

        checks_fired: List[str] = []
        reasons: List[str] = []

        # 5. Dynamic Evaluation Rules from policy.yaml
        if detected_injection_text:
            verdict = SecurityDecisionType.BLOCK
            checks_fired.append("PROMPT_INJECTION_DETECTED_BLOCK")
            reasons.append("SECURITY BLOCK [AGENTGUARD]: Malicious prompt injection detected. Access denied.")
            
        elif is_tainted and risk_level in [ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL]:
            verdict_rule = eval_rules.get("untrusted_context_high_critical", "BLOCK")
            verdict = SecurityDecisionType(verdict_rule.upper())
            checks_fired.append("TAINTED_CONTEXT_HIGH_RISK_BLOCK")
            reasons.append(
                f"SECURITY {verdict.value} [AGENTGUARD]: Action '{tool_name}' requested with untrusted document content in context. "
                f"Tool risk level is {risk_level.value}. Information contained in untrusted sources is not authorized to trigger high-risk external actions."
            )

        elif is_tainted and risk_level == ToolRiskLevel.MEDIUM:
            verdict_rule = eval_rules.get("untrusted_context_medium", "REVIEW")
            verdict = SecurityDecisionType(verdict_rule.upper())
            checks_fired.append("TAINTED_CONTEXT_MEDIUM_RISK_REVIEW")
            reasons.append(
                f"SECURITY {verdict.value} [AGENTGUARD]: Tool '{tool_name}' (MEDIUM risk) requested with untrusted context. "
                f"Requires human approval."
            )

        elif is_tainted and risk_level == ToolRiskLevel.LOW:
            verdict_rule = eval_rules.get("untrusted_context_low", "ALLOW")
            verdict = SecurityDecisionType(verdict_rule.upper())
            checks_fired.append("TAINTED_CONTEXT_LOW_RISK_ALLOW")
            reasons.append(
                f"SECURITY {verdict.value} [AGENTGUARD]: Tool '{tool_name}' is classified as LOW risk (Safe Academic Search). "
                f"Authorized with context taint logged."
            )

        elif not is_tainted and risk_level == ToolRiskLevel.CRITICAL:
            verdict_rule = eval_rules.get("untainted_critical", "REVIEW")
            verdict = SecurityDecisionType(verdict_rule.upper())
            checks_fired.append("UNTAINTED_CRITICAL_RISK_REVIEW")
            reasons.append(
                f"SECURITY {verdict.value} [AGENTGUARD]: Tool '{tool_name}' is classified as CRITICAL risk. "
                f"Even for untainted user requests, CRITICAL operations require human reviewer confirmation."
            )

        elif not is_tainted and risk_level == ToolRiskLevel.HIGH:
            if destination_allowlisted:
                verdict_rule = eval_rules.get("untainted_allowlisted", "ALLOW")
                verdict = SecurityDecisionType(verdict_rule.upper())
                checks_fired.append("UNTAINTED_HIGH_RISK_ALLOWLISTED_ALLOW")
                reasons.append(
                    f"SECURITY {verdict.value} [AGENTGUARD]: Action '{tool_name}' to allowlisted destination '{target_email}' authorized."
                )
            else:
                verdict_rule = eval_rules.get("untainted_non_allowlisted", default_verdict_str)
                verdict = SecurityDecisionType(verdict_rule.upper())
                checks_fired.append("UNTAINTED_HIGH_RISK_NON_ALLOWLISTED_BLOCK")
                reasons.append(
                    f"SECURITY {verdict.value} [AGENTGUARD]: Action '{tool_name}' destination '{target_email}' is not in the allowed email domain list ({allowed_domains}). Access denied."
                )

        else:
            verdict_rule = eval_rules.get("untainted_safe", "ALLOW")
            verdict = SecurityDecisionType(verdict_rule.upper())
            checks_fired.append("UNTAINTED_SAFE_ALLOW")
            reasons.append(f"SECURITY {verdict.value} [AGENTGUARD]: Action '{tool_name}' authorized.")

        if bulk_violation:
            checks_fired.append("BULK_THRESHOLD_EXCEEDED")
            reasons.append(f"Safety Warning: Requested {records_count} records exceeds safety threshold ({bulk_threshold}).")

        # 6. Action Lineage Graph Construction
        lineage: List[LineageNode] = []
        for idx, item in enumerate(session_context.items, start=1):
            lineage.append(LineageNode(
                id=f"node-{idx}",
                type="DOCUMENT" if not item.is_trusted else "USER_PROMPT",
                label=f"{idx}. Source Context ({item.source_type})",
                details=f"Source: {item.source_type} | Trusted: {item.is_trusted}",
                is_tainted=not item.is_trusted
            ))

        node_count = len(lineage)
        if detected_injection_text:
            node_count += 1
            lineage.append(LineageNode(
                id=f"node-{node_count}",
                type="INSTRUCTION",
                label=f"{node_count}. Extracted Directive",
                details=f"Directive: '{detected_injection_text[:70]}...'",
                is_tainted=True
            ))

        node_count += 1
        lineage.append(LineageNode(
            id=f"node-{node_count}",
            type="AGENT",
            label=f"{node_count}. Agent Reasoning",
            details=f"Agent requested tool call '{tool_name}'",
            is_tainted=is_tainted
        ))

        node_count += 1
        lineage.append(LineageNode(
            id=f"node-{node_count}",
            type="TOOL_REQUEST",
            label=f"{node_count}. Tool Request",
            details=f"Target: {tool_name} | Risk: {risk_level.value} | Args: {tool_args}",
            is_tainted=is_tainted
        ))

        node_count += 1
        decision_label = "ALLOWED" if verdict == SecurityDecisionType.ALLOW else ("BLOCKED" if verdict == SecurityDecisionType.BLOCK else "REVIEW REQUIRED")
        lineage.append(LineageNode(
            id=f"node-{node_count}",
            type="SECURITY_DECISION",
            label=f"{node_count}. AgentGuard Control Plane ({decision_label})",
            details=reasons[0] if reasons else verdict.value,
            is_tainted=is_tainted
        ))

        return AgentGuardDecision(
            decision=verdict,
            verdict=verdict.value,
            tool_name=tool_name,
            tool_args=tool_args,
            provenance_source=provenance_source,
            is_tainted=is_tainted,
            risk_level=risk_level,
            reason=reasons[0] if reasons else verdict.value,
            reasons=reasons,
            checks_fired=checks_fired,
            action_lineage=lineage
        )

security_gateway = SecurityGateway()

class AgentGuardInterceptor:
    """Class wrapper for backward compatibility across test suites."""
    @staticmethod
    def inspect_and_evaluate(
        tool_name: str,
        tool_args: Dict[str, Any],
        session_context: SessionContext,
        detected_injection_text: Optional[str] = None
    ) -> AgentGuardDecision:
        
        decision = security_gateway.evaluate_action(
            tool_name=tool_name,
            tool_args=tool_args,
            session_context=session_context,
            detected_injection_text=detected_injection_text
        )

        # --- HARD STOP FOR LLM (400 BAD REQUEST) ---
        if decision.decision == SecurityDecisionType.BLOCK:
            log_security_evaluation(decision)  # SQLite mein evidence permanently record kar
            raise HTTPException(
                status_code=400,
                detail={"status": "ERROR", "reason": decision.reason}
            )
        # -------------------------------------------
        
        return decision

# =====================================================================
# 3. Model Context Protocol (MCP) Proxy Gateway & Human Approval
# =====================================================================

class PendingApproval(BaseModel):
    approval_id: str = Field(default_factory=lambda: f"appr-{uuid.uuid4().hex[:8]}")
    tool_name: str
    tool_args: Dict[str, Any]
    args_hash: str = ""
    reason: str
    risk_level: ToolRiskLevel
    provenance_source: str
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    status: str = "PENDING"  # "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED"

class MCPGateway:
    """
    Model Context Protocol (MCP) Proxy Gateway & Human-in-the-Loop Approval System.
    Intercepts tool calls, persists pending approvals in SQLite, enforces
    SHA-256 hash integrity checks, and executes real guarded tools upon approval.
    """

    def __init__(self):
        self._sync_from_db()

    def _sync_from_db(self):
        self.pending_approvals: Dict[str, PendingApproval] = {}
        db_items = get_all_pending_approvals()
        for item in db_items:
            risk_lvl = normalize_risk_level(item["risk_level"])
            appr = PendingApproval(
                approval_id=item["approval_id"],
                tool_name=item["tool_name"],
                tool_args=item["tool_args"],
                args_hash=item["args_hash"],
                reason=item["reason"],
                risk_level=risk_lvl,
                provenance_source=item["provenance_source"],
                created_at=item["created_at"],
                status=item["status"]
            )
            self.pending_approvals[appr.approval_id] = appr

    def queue_for_human_review(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        reason: str,
        risk_level: Any,
        provenance_source: str
    ) -> PendingApproval:
        approval_id = f"appr-{uuid.uuid4().hex[:8]}"
        risk_lvl = normalize_risk_level(risk_level)
        args_hash = save_pending_approval(
            approval_id=approval_id,
            tool_name=tool_name,
            tool_args=tool_args,
            reason=reason,
            risk_level=risk_lvl.value,
            provenance_source=provenance_source
        )
        approval = PendingApproval(
            approval_id=approval_id,
            tool_name=tool_name,
            tool_args=tool_args,
            args_hash=args_hash,
            reason=reason,
            risk_level=risk_lvl,
            provenance_source=provenance_source
        )
        self.pending_approvals[approval.approval_id] = approval
        return approval

    def approve_tool_call(
        self,
        approval_id: str,
        expected_hash: Optional[str] = None,
        canonical_args: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        self._sync_from_db()
        if approval_id not in self.pending_approvals:
            raise KeyError(f"Approval ID '{approval_id}' not found or expired.")

        approval = self.pending_approvals[approval_id]

        # 1. Check Expiration (10 minutes)
        created_dt = datetime.fromisoformat(approval.created_at)
        if datetime.utcnow() - created_dt > timedelta(minutes=10):
            update_approval_status(approval_id, "EXPIRED")
            del self.pending_approvals[approval_id]
            raise ValueError(f"Approval '{approval_id}' has expired (valid for 10 minutes).")

        # 2. Check Tampering / SHA-256 Hash Match
        effective_args = canonical_args if canonical_args is not None else approval.tool_args
        computed = compute_canonical_hash(approval.tool_name, effective_args)

        if expected_hash and expected_hash != approval.args_hash:
            raise ValueError(f"ARGUMENT_TAMPERING_REJECTED: Expected hash '{expected_hash}' does not match stored approval hash '{approval.args_hash}'.")

        if canonical_args is not None and computed != approval.args_hash:
            raise ValueError(f"ARGUMENT_TAMPERING_REJECTED: Provided canonical arguments do not match approval hash '{approval.args_hash}'.")

        # 3. Perform REAL Tool Execution via Guarded Path (Trusted Approval Context)
        from agent_logic import GUARDED_TOOL_REGISTRY
        trusted_ctx = SessionContext(items=[
            ContextItem(id="appr-user", source_type="user_prompt", content="Human operator authorized execution", is_trusted=True)
        ])
        guarded_tool = GUARDED_TOOL_REGISTRY.get(approval.tool_name)

        if guarded_tool:
            decision, execution_result = guarded_tool.invoke_guarded(
                tool_args=effective_args,
                session_context=trusted_ctx,
                detected_injection_text=None
            )
        else:
            execution_result = f"EXECUTED AFTER HUMAN APPROVAL ({approval_id}): Tool '{approval.tool_name}' completed."

        update_approval_status(approval_id, "APPROVED")
        log_audit_event(
            approval_id=approval_id,
            tool_name=approval.tool_name,
            tool_args=effective_args,
            decision="APPROVED",
            result=execution_result
        )

        del self.pending_approvals[approval_id]
        return {
            "approval_id": approval_id,
            "tool_name": approval.tool_name,
            "args": effective_args,
            "decision": "APPROVED",
            "result": execution_result,
            "timestamp": datetime.utcnow().isoformat()
        }

    def reject_tool_call(self, approval_id: str) -> Dict[str, Any]:
        self._sync_from_db()
        if approval_id not in self.pending_approvals:
            raise KeyError(f"Approval ID '{approval_id}' not found.")

        approval = self.pending_approvals[approval_id]
        update_approval_status(approval_id, "REJECTED")
        result_text = "EXECUTION REJECTED BY HUMAN OPERATOR"

        log_audit_event(
            approval_id=approval_id,
            tool_name=approval.tool_name,
            tool_args=approval.tool_args,
            decision="REJECTED",
            result=result_text
        )

        del self.pending_approvals[approval_id]
        return {
            "approval_id": approval_id,
            "tool_name": approval.tool_name,
            "args": approval.tool_args,
            "decision": "REJECTED",
            "result": result_text,
            "timestamp": datetime.utcnow().isoformat()
        }

    def get_pending_list(self) -> List[PendingApproval]:
        self._sync_from_db()
        return list(self.pending_approvals.values())

mcp_gateway = MCPGateway()
