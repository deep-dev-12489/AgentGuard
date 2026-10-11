from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
import os
import time

from agent_logic import AnalysisRequest, AnalysisResponse, ResearchAgent
from rag_engine import RAGPipeline
from mcp_gateway import mcp_gateway

app = FastAPI(
    title="AgentGuard Security Control Plane API",
    version="0.3.0",
    description="Autonomous AI Research Agent with Built-in Security Control Plane, RAG, and MCP Tool Proxy Gateway."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

agent = ResearchAgent()
rag = RAGPipeline()

# Simple Rate Limiter state
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

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "AgentGuard Security Control Plane",
        "version": "0.3.0"
    }

@app.post("/api/analyze", response_model=AnalysisResponse, summary="Analyze Document Text & Intercept Tools")
async def analyze_document(request: AnalysisRequest, req: Request):
    client_ip = req.client.host if req.client else "127.0.0.1"
    enforce_rate_limit(client_ip)
    try:
        response = agent.analyze_document(
            prompt=request.prompt,
            document_text=request.document_text,
            scenario_id=request.scenario_id,
            force_provenance=request.force_provenance
        )

        if response.security_decision and response.security_decision.decision.value == "REVIEW":
            approval = mcp_gateway.queue_for_human_review(
                tool_name=response.security_decision.tool_name,
                tool_args=response.security_decision.tool_args,
                reason=response.security_decision.reason,
                risk_level=response.security_decision.risk_level,
                provenance_source=response.security_decision.provenance_source
            )
            response.summary += f" Queued for human review (ID: {approval.approval_id})."

        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal AgentGuard Server Error: {str(e)}")

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
        raise HTTPException(status_code=400, detail="UPLOAD ERROR: File size exceeds 10MB limit.")

    # 2. PDF Magic Byte Check
    if not content.startswith(b"%PDF"):
        raise HTTPException(status_code=400, detail="UPLOAD ERROR: File is not a valid PDF (missing %PDF header).")

    try:
        chunks = rag.parse_pdf_bytes(content, filename=file.filename)
        
        # 3. Page Count Limit Check (50 pages)
        max_page = max([c.page_number for c in chunks]) if chunks else 0
        if max_page > 50:
            raise HTTPException(status_code=400, detail="UPLOAD ERROR: Document exceeds 50 page maximum limit.")

        full_text = "\n\n".join([c.text for c in chunks])

        response = agent.analyze_document(
            prompt=user_prompt,
            document_text=full_text
        )

        if response.security_decision and response.security_decision.decision.value == "REVIEW":
            mcp_gateway.queue_for_human_review(
                tool_name=response.security_decision.tool_name,
                tool_args=response.security_decision.tool_args,
                reason=response.security_decision.reason,
                risk_level=response.security_decision.risk_level,
                provenance_source=response.security_decision.provenance_source
            )

        return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Ingestion Analysis Error: {str(e)}")

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
        if "ARGUMENT_TAMPERING" in str(e):
            raise HTTPException(status_code=400, detail=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Approval Error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
