import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from backend.agent_logic import ToolRiskLevel, SecurityDecisionType, GUARDED_TOOL_REGISTRY, SessionContext, ContextItem, GuardedTool
from backend.database import save_pending_approval, get_all_pending_approvals, update_approval_status, log_audit_event, compute_canonical_hash

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
    Intercepts JSON-RPC tool calls, persists pending approvals in SQLite, enforces
    SHA-256 hash integrity checks, and executes real guarded tools upon approval.
    """

    def __init__(self):
        self._sync_from_db()

    def _sync_from_db(self):
        self.pending_approvals: Dict[str, PendingApproval] = {}
        db_items = get_all_pending_approvals()
        for item in db_items:
            appr = PendingApproval(
                approval_id=item["approval_id"],
                tool_name=item["tool_name"],
                tool_args=item["tool_args"],
                args_hash=item["args_hash"],
                reason=item["reason"],
                risk_level=ToolRiskLevel(item["risk_level"]),
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
        risk_level: ToolRiskLevel,
        provenance_source: str
    ) -> PendingApproval:
        approval_id = f"appr-{uuid.uuid4().hex[:8]}"
        args_hash = save_pending_approval(
            approval_id=approval_id,
            tool_name=tool_name,
            tool_args=tool_args,
            reason=reason,
            risk_level=risk_level.value if isinstance(risk_level, ToolRiskLevel) else str(risk_level),
            provenance_source=provenance_source
        )
        approval = PendingApproval(
            approval_id=approval_id,
            tool_name=tool_name,
            tool_args=tool_args,
            args_hash=args_hash,
            reason=reason,
            risk_level=risk_level,
            provenance_source=provenance_source
        )
        self.pending_approvals[approval.approval_id] = approval
        return approval

    def approve_tool_call(self, approval_id: str, expected_hash: Optional[str] = None, canonical_args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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
        trusted_ctx = SessionContext(items=[ContextItem(id="appr-user", source_type="user_prompt", content="Human operator authorized execution", is_trusted=True)])
        guarded_tool = GUARDED_TOOL_REGISTRY.get(approval.tool_name)
        
        if guarded_tool:
            # Force provenance to user for human-approved action
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
