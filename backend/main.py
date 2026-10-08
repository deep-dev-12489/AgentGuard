from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from pydantic import BaseModel

from agent_logic import AnalysisRequest, AnalysisResponse, ResearchAgent
from rag_engine import RAGPipeline
from mcp_gateway import mcp_gateway

app = FastAPI(
    title="AgentGuard Security Control Plane API",
    version="0.2.5",
    description="Autonomous AI Research Agent with Built-in Security Control Plane, RAG, and MCP Tool Proxy Gateway."
)

# Enable CORS for Next.js frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
agent = ResearchAgent()
rag = RAGPipeline()

class ApprovalDecisionRequest(BaseModel):
    approval_id: str
    approve: bool

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "AgentGuard Security Control Plane",
        "version": "0.2.5"
    }

@app.post("/api/analyze", response_model=AnalysisResponse, summary="Analyze Document Text & Intercept Tools")
async def analyze_document(request: AnalysisRequest):
    """
    Primary API Endpoint for AgentGuard Analysis:
    1. Reads user prompt and document text.
    2. Runs Research Agent to extract claims.
    3. Intercepts any tool calls via AgentGuard Security Control Plane.
    4. Returns security decision (ALLOW, REVIEW, or BLOCK) and full Action Lineage.
    """
    try:
        response = agent.analyze_document(
            prompt=request.prompt,
            document_text=request.document_text,
            force_provenance=request.force_provenance
        )

        # Queue for human approval if decision is REVIEW
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

@app.post("/api/upload_and_analyze", response_model=AnalysisResponse, summary="Upload PDF Stream & Run Full Analysis")
async def upload_and_analyze(
    file: UploadFile = File(...),
    user_prompt: str = Form("Analyze this uploaded PDF paper and extract research evidence.")
):
    """
    Upload a binary PDF file stream, parse raw text using pypdf,
    attach untrusted_pdf provenance tag, and evaluate via AgentGuard.
    """
    try:
        content = await file.read()
        chunks = rag.parse_pdf_bytes(content, filename=file.filename)
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Ingestion Analysis Error: {str(e)}")

@app.get("/api/pending_approvals", summary="Get Pending Human Approvals")
async def get_pending_approvals():
    """Retrieve list of tool calls currently awaiting human operator approval."""
    return {"pending": mcp_gateway.get_pending_list()}

@app.post("/api/approve", summary="Human Approval Decision Endpoint")
async def approve_tool_call(request: ApprovalDecisionRequest):
    """Approve or deny a queued tool call."""
    try:
        if request.approve:
            result = mcp_gateway.approve_tool_call(request.approval_id)
        else:
            result = mcp_gateway.reject_tool_call(request.approval_id)
        return {"status": "SUCCESS", "decision": result}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Approval Error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
