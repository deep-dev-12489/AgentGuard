import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from agent_logic import ToolRiskLevel, SecurityDecisionType

class PendingApproval(BaseModel):
    approval_id: str = Field(default_factory=lambda: f"appr-{uuid.uuid4().hex[:8]}")
    tool_name: str
    tool_args: Dict[str, Any]
    reason: str
    risk_level: ToolRiskLevel
    provenance_source: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: str = "PENDING"  # "PENDING" | "APPROVED" | "REJECTED"

class MCPGateway:
    """
    Model Context Protocol (MCP) Proxy Gateway & Human-in-the-Loop Queue.
    Intercepts JSON-RPC tool call payloads before execution.
    """

    def __init__(self):
        self.pending_approvals: Dict[str, PendingApproval] = {}
        self.execution_history: List[Dict[str, Any]] = []

    def queue_for_human_review(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        reason: str,
        risk_level: ToolRiskLevel,
        provenance_source: str
    ) -> PendingApproval:
        """Queue a CRITICAL or HIGH risk tool call for human approval."""
        approval = PendingApproval(
            tool_name=tool_name,
            tool_args=tool_args,
            reason=reason,
            risk_level=risk_level,
            provenance_source=provenance_source
        )
        self.pending_approvals[approval.approval_id] = approval
        return approval

    def approve_tool_call(self, approval_id: str) -> Dict[str, Any]:
        """Human operator approves a queued tool call."""
        if approval_id not in self.pending_approvals:
            raise KeyError(f"Approval ID '{approval_id}' not found in queue.")

        approval = self.pending_approvals[approval_id]
        approval.status = "APPROVED"

        # Execute mock MCP tool
        execution_result = f"EXECUTED AFTER HUMAN APPROVAL ({approval_id}): Tool '{approval.tool_name}' completed."
        
        history_entry = {
            "approval_id": approval_id,
            "tool_name": approval.tool_name,
            "args": approval.tool_args,
            "decision": "APPROVED",
            "result": execution_result,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.execution_history.append(history_entry)
        del self.pending_approvals[approval_id]

        return history_entry

    def reject_tool_call(self, approval_id: str) -> Dict[str, Any]:
        """Human operator denies a queued tool call."""
        if approval_id not in self.pending_approvals:
            raise KeyError(f"Approval ID '{approval_id}' not found in queue.")

        approval = self.pending_approvals[approval_id]
        approval.status = "REJECTED"

        history_entry = {
            "approval_id": approval_id,
            "tool_name": approval.tool_name,
            "args": approval.tool_args,
            "decision": "REJECTED",
            "result": "EXECUTION REJECTED BY HUMAN OPERATOR",
            "timestamp": datetime.utcnow().isoformat()
        }
        self.execution_history.append(history_entry)
        del self.pending_approvals[approval_id]

        return history_entry

    def get_pending_list(self) -> List[PendingApproval]:
        """Get all tool calls waiting for human approval."""
        return list(self.pending_approvals.values())

mcp_gateway = MCPGateway()
