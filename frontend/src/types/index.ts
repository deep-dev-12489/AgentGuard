// ============================================================
// AgentGuard – Shared TypeScript Types
// ============================================================

export interface LineageNode {
  id: string;
  type: string;
  label: string;
  details: string;
  is_tainted: boolean;
}

export interface SecurityDecision {
  verdict?: string;
  reasons?: string[];
  checks_fired?: string[];
  decision: "ALLOW" | "REVIEW" | "BLOCK";
  tool_name: string;
  tool_args: Record<string, unknown>;
  provenance_source: string;
  is_tainted: boolean;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reason: string;
  action_lineage: LineageNode[];
}

export interface AnalysisResponse {
  mode?: string;
  mode_reason?: string;
  tool_call_source?: string;
  status: string;
  extracted_claims: string[];
  summary: string;
  tool_call_attempted?: string;
  tool_execution_result?: string;
  security_decision?: SecurityDecision;
  action_lineage: LineageNode[];
  approval_id?: string;
  approval_hash?: string;
}

export type Verdict = "ALLOW" | "BLOCK" | "REVIEW";

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  fileName: string;
  verdict: Verdict;
  payload: AnalysisResponse;
  riskLevel?: string;
}

export type ScanState = "idle" | "scanning" | "result_allow" | "result_block" | "result_review";
