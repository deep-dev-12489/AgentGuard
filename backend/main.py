import os
import sys
import time
import logging

# Ensure backend directory is in sys.path regardless of execution root
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Header, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field

from agent_logic import AnalysisRequest, AnalysisResponse, ResearchAgent
from rag_engine import RAGPipeline
from mcp_gateway import mcp_gateway, audit_logger

logger = logging.getLogger("agentguard")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="AgentGuard Security Control Plane API",
    version="1.0.0",
    description="Enterprise Autonomous AI Research Agent with Security Control Plane, Dynamic Policy Enforcement, Persistent Audit Logging, and MCP Tool Proxy Gateway."
)

from starlette.exceptions import HTTPException as StarletteHTTPException

# =====================================================================
# 1. API Hardening: CORS Middleware
# =====================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================================
# 2. API Hardening: Global Structured Exception Handlers
# =====================================================================

@app.exception_handler(StarletteHTTPException)
async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Ensures all Starlette/FastAPI HTTP exceptions return structured JSON."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "ERROR",
            "error_type": "HTTPException",
            "message": exc.detail if isinstance(exc.detail, str) else "HTTP Exception",
            "detail": exc.detail,
            "path": request.url.path
        }
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Ensures FastAPI HTTP exceptions always return structured JSON with consistent detail formatting."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "ERROR",
            "error_type": "HTTPException",
            "message": exc.detail if isinstance(exc.detail, str) else "HTTP Exception",
            "detail": exc.detail,
            "path": request.url.path
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handles Pydantic/FastAPI request validation errors returning structured JSON."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "ERROR",
            "error_type": "ValidationError",
            "message": "Invalid request schema or payload parameters.",
            "detail": exc.errors(),
            "path": request.url.path
        }
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Catches all unhandled server exceptions, preventing raw 500 HTML or unhandled crashes."""
    logger.error(f"Global unhandled exception on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "ERROR",
            "error_type": type(exc).__name__,
            "message": "Internal AgentGuard Server Error",
            "detail": str(exc),
            "path": request.url.path
        }
    )

# =====================================================================
# 3. Core Dependencies & Rate Limiting
# =====================================================================

agent = ResearchAgent()
rag = RAGPipeline()

RATE_LIMIT_STORE: Dict[str, list] = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 30     # max requests per window

def enforce_rate_limit(client_ip: str):
    now = time.time()
    timestamps = RATE_LIMIT_STORE.get(client_ip, [])
    timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(timestamps) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Rate limit exceeded: Max 30 requests per minute.")
    timestamps.append(now)
    RATE_LIMIT_STORE[client_ip] = timestamps

class ApprovalDecisionRequest(BaseModel):
    approval_id: str
    approve: bool
    expected_hash: Optional[str] = None
    canonical_args: Optional[Dict[str, Any]] = None

# =====================================================================
# 4. Endpoints
# =====================================================================

@app.get("/health", summary="Health Check")
async def health_check():
    return {
        "status": "healthy",
        "service": "AgentGuard Security Control Plane",
        "version": "1.0.0"
    }

@app.get("/api/audit_logs", summary="Threat Matrix: Persistent Audit Logs")
async def get_audit_logs(limit: int = 50):
    """
    Threat Matrix Endpoint.
    Returns the last 50 recorded security evaluation events from the persistent SQLite database.
    Fields per record: Timestamp, File Name, User Prompt, Verdict (ALLOW/REVIEW/BLOCK), and Reason.
    """
    try:
        logs = audit_logger.get_recent_logs(limit=min(limit, 50))
        return {
            "status": "SUCCESS",
            "count": len(logs),
            "audit_logs": logs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch audit logs: {str(e)}")

@app.post("/api/analyze", response_model=AnalysisResponse, summary="Analyze Document Text & Intercept Tools")
async def analyze_document(request: AnalysisRequest, req: Request):
    client_ip = req.client.host if req.client else "127.0.0.1"
    enforce_rate_limit(client_ip)

    response = agent.analyze_document(
        prompt=request.prompt,
        document_text=request.document_text,
        scenario_id=request.scenario_id,
        force_provenance=request.force_provenance
    )

    # Persistent Audit Logging & Human Review Queueing
    if response.security_decision:
        verdict = response.security_decision.decision.value
        reason = response.security_decision.reason
        if verdict == "REVIEW":
            approval = mcp_gateway.queue_for_human_review(
                tool_name=response.security_decision.tool_name,
                tool_args=response.security_decision.tool_args,
                reason=response.security_decision.reason,
                risk_level=response.security_decision.risk_level,
                provenance_source=response.security_decision.provenance_source
            )
            response.summary += f" Queued for human review (ID: {approval.approval_id})."
    else:
        verdict = "ALLOW"
        reason = "Benign request: No unauthorized tool execution or policy violation detected."

    audit_logger.log_evaluation(
        verdict=verdict,
        reason=reason,
        user_prompt=request.prompt,
        file_name="direct_input"
    )

    return response

@app.post("/api/upload_and_analyze", response_model=AnalysisResponse, summary="Upload Hardened PDF Analysis")
async def upload_and_analyze(
    req: Request,
    file: UploadFile = File(...),
    user_prompt: str = Form("Analyze this uploaded PDF paper and extract research evidence.")
):
    client_ip = req.client.host if req.client else "127.0.0.1"
    enforce_rate_limit(client_ip)

    # 1. File Size Limit (10 MB)
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        audit_logger.log_evaluation(
            verdict="BLOCK",
            reason="UPLOAD ERROR: File size exceeds 10MB limit.",
            user_prompt=user_prompt,
            file_name=file.filename
        )
        raise HTTPException(status_code=400, detail="UPLOAD ERROR: File size exceeds 10MB limit.")

    # 2. PDF Magic Byte Check
    if not content.startswith(b"%PDF"):
        audit_logger.log_evaluation(
            verdict="BLOCK",
            reason="UPLOAD ERROR: File is not a valid PDF (missing %PDF header).",
            user_prompt=user_prompt,
            file_name=file.filename
        )
        raise HTTPException(status_code=400, detail="UPLOAD ERROR: File is not a valid PDF (missing %PDF header).")

    chunks = rag.parse_pdf_bytes(content, filename=file.filename)
    
    # 3. Page Count Limit Check (50 pages)
    max_page = max([c.page_number for c in chunks]) if chunks else 0
    if max_page > 50:
        audit_logger.log_evaluation(
            verdict="BLOCK",
            reason="UPLOAD ERROR: Document exceeds 50 page maximum limit.",
            user_prompt=user_prompt,
            file_name=file.filename
        )
        raise HTTPException(status_code=400, detail="UPLOAD ERROR: Document exceeds 50 page maximum limit.")

    full_text = "\n\n".join([c.text for c in chunks])

    # =================================================================
    # 4. STRICT PRE-LLM HEURISTIC SCANNER (PROMPT INJECTION FIREWALL)
    # =================================================================
    injection_keywords = [
        "ignore previous", "system instruction", "system prompt", 
        "bypass", "override", "do not execute", "new instructions",
        "forget all", "disregard"
    ]
    
    text_to_scan = (full_text + " " + user_prompt).lower()
    
    for keyword in injection_keywords:
        if keyword in text_to_scan:
            error_msg = f"SECURITY BLOCK [AGENTGUARD]: Malicious prompt injection detected via heuristic ('{keyword}'). Access denied."
            
            # Database mein attack permanently save karo
            audit_logger.log_evaluation(
                verdict="BLOCK",
                reason=error_msg,
                user_prompt=user_prompt,
                file_name=file.filename
            )
            
            # API ko yahi rok do aur 400 Bad Request phenk do (LLM bacha lo)
            raise HTTPException(
                status_code=400, 
                detail={"status": "ERROR", "reason": error_msg}
            )
    # =================================================================
    
    response = agent.analyze_document(
        prompt=user_prompt,
        document_text=full_text
    )

    # Persistent Audit Logging & Human Review Queueing
    if response.security_decision:
        verdict = response.security_decision.decision.value
        reason = response.security_decision.reason
        if verdict == "REVIEW":
            mcp_gateway.queue_for_human_review(
                tool_name=response.security_decision.tool_name,
                tool_args=response.security_decision.tool_args,
                reason=response.security_decision.reason,
                risk_level=response.security_decision.risk_level,
                provenance_source=response.security_decision.provenance_source
            )
    else:
        verdict = "ALLOW"
        reason = "Benign document analysis: No unauthorized tool execution or policy violation detected."

    audit_logger.log_evaluation(
        verdict=verdict,
        reason=reason,
        user_prompt=user_prompt,
        file_name=file.filename
    )

    return response

@app.get("/api/pending_approvals", summary="Get Pending Human Approvals")
async def get_pending_approvals():
    return {"pending": mcp_gateway.get_pending_list()}

@app.post("/api/approve", summary="Human Approval Decision Endpoint")
async def approve_tool_call(
    request: ApprovalDecisionRequest,
    x_reviewer_token: Optional[str] = Header(None, alias="X-Reviewer-Token")
):
    expected_token = os.getenv("REVIEWER_TOKEN", "secret_reviewer_token_123")
    if not x_reviewer_token or x_reviewer_token != expected_token:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing X-Reviewer-Token header.")

    try:
        if request.approve:
            result = mcp_gateway.approve_tool_call(
                approval_id=request.approval_id,
                expected_hash=request.expected_hash,
                canonical_args=request.canonical_args
            )
        else:
            result = mcp_gateway.reject_tool_call(request.approval_id)
        return {"status": "SUCCESS", "decision": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Approval Error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
