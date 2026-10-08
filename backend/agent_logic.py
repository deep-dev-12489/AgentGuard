import os
import re
import yaml
from typing import Dict, Any, List, Optional, Callable, Tuple
from enum import Enum
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

# ==========================================
# 1. Enums and Data Models
# ==========================================

class SecurityDecisionType(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"

class ToolRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class LineageNode(BaseModel):
    id: str
    type: str  # DOCUMENT, INSTRUCTION, AGENT, TOOL_REQUEST, SECURITY_DECISION
    label: str
    details: str
    is_tainted: bool = False

class ContextItem(BaseModel):
    id: str
    source_type: str  # "user_prompt", "pdf_chunk", "web_result", "tool_output"
    content: str
    is_trusted: bool = True

class SessionContext(BaseModel):
    items: List[ContextItem] = Field(default_factory=list)

    @property
    def has_untrusted_content(self) -> bool:
        return any(not item.is_trusted for item in self.items)

    @property
    def provenance_label(self) -> str:
        return "untrusted_pdf" if self.has_untrusted_content else "user"

class AgentGuardDecision(BaseModel):
    decision: SecurityDecisionType
    verdict: str
    tool_name: str
    tool_args: Dict[str, Any]
    provenance_source: str  # "user" or "untrusted_pdf"
    is_tainted: bool
    risk_level: ToolRiskLevel
    reason: str
    reasons: List[str]
    checks_fired: List[str]
    action_lineage: List[LineageNode]

class AnalysisRequest(BaseModel):
    prompt: str = Field(...)
    document_text: str = Field("")
    scenario_id: Optional[str] = Field(None, description="Explicit scenario for simulated replay mode: 'safe_search', 'malicious_export', 'user_export', 'mixed_context'")
    force_provenance: Optional[str] = Field(None, description="Override provenance source for testing ('user' or 'untrusted_pdf')")

class AnalysisResponse(BaseModel):
    mode: str = Field(..., description="'live_llm', 'simulated', or 'unavailable'")
    mode_reason: Optional[str] = Field(None, description="Explanation for why mode was chosen")
    tool_call_source: Optional[str] = Field(None, description="'llm', 'scripted_fixture', or None")
    status: str
    extracted_claims: List[str]
    summary: str
    tool_call_attempted: Optional[str] = None
    tool_execution_result: Optional[str] = None
    security_decision: Optional[AgentGuardDecision] = None
    action_lineage: List[LineageNode]

# ==========================================
# 2. Policy Configuration Loader
# ==========================================

def load_policy() -> Dict[str, Any]:
    policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")
    if os.path.exists(policy_path):
        with open(policy_path, "r") as f:
            return yaml.safe_load(f)
    return {
        "tool_risk_levels": {
            "export_customer_data": "CRITICAL",
            "send_email": "HIGH",
            "search_academic_db": "LOW"
        },
        "defaults": {"unknown_tool_risk": "CRITICAL", "default_verdict": "BLOCK"},
        "destinations": {
            "allowed_email_domains": ["org.com", "trusted-partner.org", "company.com"],
            "allowed_api_hosts": ["api.ncbi.nlm.nih.gov", "export.arxiv.org"]
        }
    }

# ==========================================
# 3. Raw Tool Implementations
# ==========================================

def raw_export_customer_data(target_email: str, records_count: int = 100) -> str:
    """Mock external tool to export customer DB records. CRITICAL RISK."""
    return f"SUCCESS: Exported {records_count} customer records to {target_email}."

def raw_send_email(target_email: str, subject: str, body: str) -> str:
    """Mock external tool to send email. HIGH RISK."""
    return f"SUCCESS: Email sent to {target_email} with subject '{subject}'."

def raw_search_academic_db(query: str, max_results: int = 3) -> str:
    """External tool to search arXiv / PubMed academic databases. LOW RISK."""
    import urllib.request, urllib.parse, xml.etree.ElementTree as ET
    try:
        encoded_query = urllib.parse.quote(query)
        url = f"http://export.arxiv.org/api/query?search_query=all:{encoded_query}&start=0&max_results={max_results}"
        with urllib.request.urlopen(url, timeout=4) as resp:
            tree = ET.fromstring(resp.read())
            entries = tree.findall("{http://www.w3.org/2005/Atom}entry")
            if entries:
                citations = []
                for idx, e in enumerate(entries, 1):
                    title = e.find("{http://www.w3.org/2005/Atom}title").text.strip().replace("\n", " ")
                    id_url = e.find("{http://www.w3.org/2005/Atom}id").text.strip()
                    citations.append(f"[{idx}] '{title}' (URL: {id_url})")
                return f"SUCCESS (LIVE arXiv API): Retrieved {len(citations)} citations for query '{query}'. " + " ".join(citations)
    except Exception:
        pass

    return (
        f"SUCCESS [MOCK DATA]: Retrieved {max_results} academic citations for query '{query}'. "
        f"Citations: [1] [MOCK DATA] PubMed ID:34829102 (AI Clinical Diagnostics 2025), "
        f"[2] [MOCK DATA] ArXiv:2403.0912 (Deep Learning Neural Verification)."
    )

# ==========================================
# 4. AgentGuard Control Plane Interceptor
# ==========================================

class AgentGuardInterceptor:
    """
    AgentGuard Control Plane Engine.
    Taint-based, fail-closed security control plane enforcing 'Information != Authorization'.
    """

    @staticmethod
    def inspect_and_evaluate(
        tool_name: str,
        tool_args: Dict[str, Any],
        session_context: SessionContext,
        detected_injection_text: Optional[str] = None
    ) -> AgentGuardDecision:
        policy = load_policy()
        tool_risk_levels = policy.get("tool_risk_levels", {})
        defaults = policy.get("defaults", {})
        destinations = policy.get("destinations", {})
        allowed_domains = destinations.get("allowed_email_domains", [])

        # 1. Determine Risk Level (Unknown tools fail-closed to CRITICAL)
        if tool_name in tool_risk_levels:
            risk_str = tool_risk_levels[tool_name]
        else:
            risk_str = defaults.get("unknown_tool_risk", "CRITICAL")

        try:
            risk_level = ToolRiskLevel(risk_str)
        except ValueError:
            risk_level = ToolRiskLevel.CRITICAL

        # 2. Determine Taint Status (PIGGYBACKING FIX: Any untrusted context taints the request)
        is_tainted = session_context.has_untrusted_content
        provenance_source = session_context.provenance_label

        # 3. Check Destination Allowlist
        target_email = tool_args.get("target_email", "")
        email_domain = target_email.split("@")[-1].lower() if "@" in target_email else ""
        destination_allowlisted = email_domain in allowed_domains if email_domain else False

        checks_fired: List[str] = []
        reasons: List[str] = []

        # 4. Evaluate Security Rules (Strict Fail-Closed Logic)
        if is_tainted and risk_level in [ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL]:
            verdict = SecurityDecisionType.BLOCK
            checks_fired.append("TAINTED_CONTEXT_HIGH_RISK_BLOCK")
            reasons.append(
                f"SECURITY BLOCK [AGENTGUARD]: Action '{tool_name}' requested with untrusted document content in context. "
                f"Tool risk level is {risk_level.value}. Information contained in untrusted sources is not authorized to trigger high-risk external actions."
            )

        elif is_tainted and risk_level == ToolRiskLevel.MEDIUM:
            verdict = SecurityDecisionType.REVIEW
            checks_fired.append("TAINTED_CONTEXT_MEDIUM_RISK_REVIEW")
            reasons.append(
                f"SECURITY REVIEW [AGENTGUARD]: Tool '{tool_name}' (MEDIUM risk) requested with untrusted context. "
                f"Requires human approval."
            )

        elif is_tainted and risk_level == ToolRiskLevel.LOW:
            verdict = SecurityDecisionType.ALLOW
            checks_fired.append("TAINTED_CONTEXT_LOW_RISK_ALLOW")
            reasons.append(
                f"SECURITY ALLOW [AGENTGUARD]: Tool '{tool_name}' is classified as LOW risk (Safe Academic Search). "
                f"Authorized with context taint logged."
            )

        elif not is_tainted and risk_level == ToolRiskLevel.CRITICAL:
            verdict = SecurityDecisionType.REVIEW
            checks_fired.append("UNTAINTED_CRITICAL_RISK_REVIEW")
            reasons.append(
                f"SECURITY REVIEW [AGENTGUARD]: Tool '{tool_name}' is classified as CRITICAL risk. "
                f"Even for untainted user requests, CRITICAL operations require human reviewer confirmation."
            )

        elif not is_tainted and risk_level == ToolRiskLevel.HIGH:
            if destination_allowlisted:
                verdict = SecurityDecisionType.ALLOW
                checks_fired.append("UNTAINTED_HIGH_RISK_ALLOWLISTED_ALLOW")
                reasons.append(f"SECURITY ALLOW [AGENTGUARD]: Action '{tool_name}' to allowlisted destination '{target_email}' authorized.")
            else:
                verdict = SecurityDecisionType.BLOCK
                checks_fired.append("UNTAINTED_HIGH_RISK_NON_ALLOWLISTED_BLOCK")
                reasons.append(
                    f"SECURITY BLOCK [AGENTGUARD]: Action '{tool_name}' destination '{target_email}' is not in the allowed email domain list ({allowed_domains}). Access denied."
                )

        else:
            verdict = SecurityDecisionType.ALLOW
            checks_fired.append("UNTAINTED_SAFE_ALLOW")
            reasons.append(f"SECURITY ALLOW [AGENTGUARD]: Action '{tool_name}' authorized.")

        # 5. Build Dynamic Real Event Lineage Graph
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

# ==========================================
# 5. Guarded Tool Registry
# ==========================================

class GuardedTool:
    def __init__(self, name: str, risk_level: ToolRiskLevel, description: str, func: Callable):
        self.name = name
        self.risk_level = risk_level
        self.description = description
        self._raw_func = func

    def invoke_guarded(
        self,
        tool_args: Dict[str, Any],
        session_context: SessionContext,
        detected_injection_text: Optional[str] = None
    ) -> Tuple[AgentGuardDecision, str]:
        decision = AgentGuardInterceptor.inspect_and_evaluate(
            tool_name=self.name,
            tool_args=tool_args,
            session_context=session_context,
            detected_injection_text=detected_injection_text
        )

        if decision.decision == SecurityDecisionType.ALLOW:
            result = self._raw_func(**tool_args)
            return decision, result
        elif decision.decision == SecurityDecisionType.BLOCK:
            return decision, "EXECUTION PREVENTED BY AGENTGUARD CONTROL PLANE"
        else:
            return decision, "PENDING HUMAN OPERATOR APPROVAL"

GUARDED_TOOL_REGISTRY: Dict[str, GuardedTool] = {
    "export_customer_data": GuardedTool(
        name="export_customer_data",
        risk_level=ToolRiskLevel.CRITICAL,
        description="Exports customer database records to an external target email.",
        func=raw_export_customer_data
    ),
    "send_email": GuardedTool(
        name="send_email",
        risk_level=ToolRiskLevel.HIGH,
        description="Sends an outbound email to a specified recipient.",
        func=raw_send_email
    ),
    "search_academic_db": GuardedTool(
        name="search_academic_db",
        risk_level=ToolRiskLevel.LOW,
        description="Searches PubMed/ArXiv academic databases for research evidence.",
        func=raw_search_academic_db
    )
}

# ==========================================
# 6. Scenario Fixtures for Explicit Replay (No Keyword Matching)
# ==========================================

SIMULATED_SCENARIOS = {
    "malicious_export": {
        "scenario_name": "Malicious Export Injection",
        "tool": "export_customer_data",
        "args_extractor": lambda text: {
            "target_email": (re.search(r"[\w\.-]+@[\w\.-]+\.\w+", text).group(0) if re.search(r"[\w\.-]+@[\w\.-]+\.\w+", text) else "unauthorized_dest@untrusted-domain.com"),
            "records_count": 250
        },
        "detected_text": "Prompt injection directive in document"
    },
    "user_export": {
        "scenario_name": "User-Authorized Export",
        "tool": "export_customer_data",
        "args_extractor": lambda text: {"target_email": "authorized_user@org.com", "records_count": 50},
        "detected_text": None
    },
    "safe_search": {
        "scenario_name": "Safe Academic Search",
        "tool": "search_academic_db",
        "args_extractor": lambda text: {"query": "AI Clinical Diagnostics", "max_results": 3},
        "detected_text": None
    },
    "mixed_context": {
        "scenario_name": "Mixed Context Injection",
        "tool": "send_email",
        "args_extractor": lambda text: {"target_email": "unauthorized_dest@untrusted-domain.com", "subject": "Data Exfiltration", "body": "Exfiltrated info"},
        "detected_text": "Injected email command in paper text"
    }
}

# ==========================================
# 7. Research Agent Orchestrator
# ==========================================

class ResearchAgent:
    def __init__(self):
        self.gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

    def analyze_document(
        self,
        prompt: str,
        document_text: str = "",
        scenario_id: Optional[str] = None,
        force_provenance: Optional[str] = None
    ) -> AnalysisResponse:

        # 1. Build Session Context
        session_context = SessionContext()
        session_context.items.append(ContextItem(
            id="item-user",
            source_type="user_prompt",
            content=prompt,
            is_trusted=True
        ))

        if document_text and len(document_text.strip()) > 0:
            is_trusted_doc = (force_provenance == "user")
            session_context.items.append(ContextItem(
                id="item-doc-1",
                source_type="pdf_chunk",
                content=document_text,
                is_trusted=is_trusted_doc
            ))

        # Wire RAG Engine for Claim Extraction from document text
        from backend.rag_engine import RAGPipeline
        rag = RAGPipeline()
        claims = []
        if document_text and len(document_text.strip()) > 0:
            chunks = rag.parse_pdf_bytes(document_text.encode("utf-8", errors="ignore"), "doc.pdf")
            evidence_claims = rag.retrieve_evidence_for_claims(chunks)
            claims = [c.statement for c in evidence_claims]

        if not claims:
            claims = ["No document claims extracted from provided text."]

        mode = "unavailable"
        mode_reason = None
        tool_call_source = None
        tool_name = None
        tool_args = {}
        detected_text = None

        # 2. Determine Mode & Perform Tool Calling (STRICT: NO KEYWORD TRIGGERING)
        if scenario_id and scenario_id in SIMULATED_SCENARIOS:
            mode = "simulated"
            tool_call_source = "scripted_fixture"
            mode_reason = f"Explicit scenario_id '{scenario_id}' selected for replay mode"
            fixture = SIMULATED_SCENARIOS[scenario_id]
            tool_name = fixture["tool"]
            tool_args = fixture["args_extractor"](document_text)
            detected_text = fixture.get("detected_text")

        elif self.gemini_key:
            try:
                claims_llm, tool_name, tool_args, detected_text = self._analyze_with_gemini(prompt, document_text)
                if claims_llm and len(document_text.strip()) == 0:
                    claims = claims_llm
                mode = "live_llm"
                tool_call_source = "llm"
            except Exception as e:
                mode = "unavailable"
                tool_call_source = None
                mode_reason = f"Gemini API execution unavailable ({e})"
                tool_name = None
                tool_args = {}
                detected_text = None
        else:
            mode = "unavailable"
            tool_call_source = None
            mode_reason = "GEMINI_API_KEY environment variable is not set and no explicit scenario_id was provided"
            tool_name = None
            tool_args = {}
            detected_text = None

        if not tool_name:
            lineage = [
                LineageNode(
                    id="node-1",
                    type="DOCUMENT",
                    label="1. Source Context",
                    details=f"Parsed {len(document_text)} characters from document.",
                    is_tainted=session_context.has_untrusted_content
                ),
                LineageNode(
                    id="node-2",
                    type="AGENT",
                    label="2. Research Analysis",
                    details="Extracted claims without invoking external tools.",
                    is_tainted=session_context.has_untrusted_content
                )
            ]
            return AnalysisResponse(
                mode=mode,
                mode_reason=mode_reason,
                tool_call_source=tool_call_source,
                status="SUCCESS",
                extracted_claims=claims,
                summary=f"Analysis completed [{mode.upper()}]. Extracted {len(claims)} key claims.",
                action_lineage=lineage
            )

        # 3. Enforce Guarded Execution
        guarded_tool = GUARDED_TOOL_REGISTRY.get(tool_name)
        if not guarded_tool:
            guarded_tool = GuardedTool(
                name=tool_name,
                risk_level=ToolRiskLevel.CRITICAL,
                description="Unknown external tool",
                func=lambda **kwargs: f"Executed unknown tool {tool_name}"
            )

        decision, tool_execution_result = guarded_tool.invoke_guarded(
            tool_args=tool_args,
            session_context=session_context,
            detected_injection_text=detected_text
        )

        status = "SUCCESS" if decision.decision == SecurityDecisionType.ALLOW else ("BLOCKED" if decision.decision == SecurityDecisionType.BLOCK else "REVIEW_REQUIRED")
        summary = f"[{mode.upper()} MODE] Agent analyzed document. Tool call '{tool_name}' attempted via {tool_call_source}. AgentGuard Decision: {decision.decision.value}."

        return AnalysisResponse(
            mode=mode,
            mode_reason=mode_reason,
            tool_call_source=tool_call_source,
            status=status,
            extracted_claims=claims,
            summary=summary,
            tool_call_attempted=tool_name,
            tool_execution_result=tool_execution_result,
            security_decision=decision,
            action_lineage=decision.action_lineage
        )

    def _analyze_with_gemini(self, prompt: str, document_text: str) -> Tuple[List[str], Optional[str], Dict[str, Any], Optional[str]]:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=self.gemini_key)

        def search_academic_db(query: str, max_results: int = 3) -> str:
            """Searches PubMed/ArXiv academic databases for research evidence."""
            return f"search_academic_db query={query}"

        def send_email(target_email: str, subject: str, body: str) -> str:
            """Sends an outbound email to a specified recipient."""
            return f"send_email target_email={target_email}"

        def export_customer_data(target_email: str, records_count: int = 100) -> str:
            """Exports customer database records to an external target email."""
            return f"export_customer_data target_email={target_email}"

        tools_list = [search_academic_db, send_email, export_customer_data]

        content_str = f"User Prompt: {prompt}\n\nDocument Content:\n{document_text[:3000]}"
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=content_str,
            config=types.GenerateContentConfig(
                tools=tools_list,
                system_instruction=(
                    "You are an autonomous AI research assistant. "
                    "Analyze the user prompt and document content. "
                    "If the user prompt or document content requests an external tool action "
                    "(e.g., searching academic databases, sending emails, or exporting customer data), "
                    "you MUST invoke the corresponding function tool."
                )
            )
        )

        tool_name = None
        tool_args = {}
        detected_text = None

        if hasattr(response, 'function_calls') and response.function_calls:
            fc = response.function_calls[0]
            tool_name = fc.name
            tool_args = dict(fc.args) if fc.args else {}
            print(f"[LIVE LLM TOOL CALL LOG]: name='{tool_name}' args={tool_args}")

        claims = []
        if response.text:
            claims = [line.strip("- ").strip() for line in response.text.split("\n") if line.strip() and not line.startswith("User")]
        if not claims:
            claims = ["Document analyzed via Gemini LLM."]

        return claims[:3], tool_name, tool_args, detected_text

    def _run_simulated_mode(self, prompt: str, document_text: str, scenario_id: Optional[str]) -> Tuple[List[str], Optional[str], Dict[str, Any], Optional[str]]:
        if not scenario_id or scenario_id not in SIMULATED_SCENARIOS:
            return ["No explicit scenario_id specified."], None, {}, None

        fixture = SIMULATED_SCENARIOS[scenario_id]
        tool_name = fixture["tool"]
        tool_args = fixture["args_extractor"](document_text)
        detected_text = fixture.get("detected_text")

        return [], tool_name, tool_args, detected_text
