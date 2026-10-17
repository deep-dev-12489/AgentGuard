"""FastAPI entrypoint for the AgentGuard demo backend."""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock
from typing import Deque, Dict, Optional

from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

# Load the project-level .env independent of the terminal's current directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env", override=False)

from backend.agent_logic import (  # noqa: E402
    AnalysisRequest,
    AnalysisResponse,
    LineageNode,
    ResearchAgent,
    SecurityDecisionType,
)
from backend.detectors import PromptInjectionDetector  # noqa: E402
from backend.mcp_gateway import audit_logger, mcp_gateway  # noqa: E402
from backend.rag_engine import MAX_PDF_PAGES, MAX_TEXT_CHARS, RAGPipeline  # noqa: E402

logger = logging.getLogger("agentguard")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 30
RATE_LIMIT_STORE: Dict[str, Deque[float]] = defaultdict(deque)
_RATE_LIMIT_LOCK = Lock()

app = FastAPI(
    title="AgentGuard Security Control Plane API",
    version="1.1.0",
    description=(
        "A demo control plane for deterministic tool-call policy enforcement, "
        "prompt-injection-aware document ingestion, and human-reviewed actions."
    ),
)

origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Reviewer-Token"],
)

agent = ResearchAgent()
rag = RAGPipeline()


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(..., min_length=8, max_length=100)
    approve: bool
    expected_hash: Optional[str] = Field(default=None, max_length=128)
    canonical_args: Optional[dict] = None


def _get_client_ip(request: Request) -> str:
    # Do not trust X-Forwarded-For unless the app is behind a configured trusted proxy.
    return request.client.host if request.client else "unknown"


def enforce_rate_limit(client_ip: str) -> None:
    now = time.monotonic()
    with _RATE_LIMIT_LOCK:
        recent = RATE_LIMIT_STORE[client_ip]
        while recent and now - recent[0] >= RATE_LIMIT_WINDOW_SECONDS:
            recent.popleft()
        if len(recent) >= RATE_LIMIT_MAX_REQUESTS:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Try again in a minute.",
                headers={"Retry-After": "60"},
            )
        recent.append(now)
        # Keep the in-process demo limiter from growing without bound.
        if len(RATE_LIMIT_STORE) > 5_000:
            expired_keys = [key for key, values in RATE_LIMIT_STORE.items() if not values or now - values[-1] > 120]
            for key in expired_keys:
                RATE_LIMIT_STORE.pop(key, None)


def _expected_reviewer_token() -> str:
    token = os.getenv("REVIEWER_TOKEN", "").strip()
    if len(token) < 32 or token.lower().startswith(("replace_with", "change_me", "your_")):
        return ""
    return token


def _require_reviewer_token(provided_token: Optional[str]) -> None:
    expected = _expected_reviewer_token()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Reviewer authentication is not configured. Set REVIEWER_TOKEN in the backend environment.",
        )
    if not provided_token or not __import__("hmac").compare_digest(provided_token, expected):
        raise HTTPException(status_code=401, detail="Unauthorized reviewer token.")


def _write_audit(response: AnalysisResponse, prompt: str, file_name: str) -> None:
    decision = response.security_decision
    if decision is not None:
        verdict = decision.decision.value
        reason = decision.reason
    elif response.status.upper() in {"BLOCKED", "ERROR"} or response.mode == "blocked":
        verdict = "BLOCK"
        reason = response.summary
    else:
        verdict = "ALLOW"
        reason = response.mode_reason or "No tool action was proposed; analysis completed without external execution."

    audit_logger.log_evaluation(
        verdict=verdict,
        reason=reason,
        user_prompt=prompt,
        file_name=file_name,
    )


def _queue_review_if_required(response: AnalysisResponse) -> AnalysisResponse:
    decision = response.security_decision
    if decision and decision.decision == SecurityDecisionType.REVIEW:
        approval = mcp_gateway.queue_for_human_review(
            tool_name=decision.tool_name,
            tool_args=decision.tool_args,
            reason=decision.reason,
            risk_level=decision.risk_level,
            provenance_source=decision.provenance_source,
        )
        response.approval_id = approval.approval_id
        response.approval_hash = approval.args_hash
        response.summary += f" Human review is required before this action can run (approval ID: {approval.approval_id})."
    return response


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    detail = exc.detail
    message = detail if isinstance(detail, str) else "Request could not be completed."
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "ERROR",
            "error_type": "HTTPException",
            "message": message,
            "detail": detail,
            "path": request.url.path,
        },
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Do not echo invalid input values; they can contain prompts or sensitive content.
    safe_errors = [
        {"loc": list(item.get("loc", [])), "msg": item.get("msg", "Invalid value"), "type": item.get("type", "value_error")}
        for item in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "ERROR",
            "error_type": "ValidationError",
            "message": "Invalid request schema or payload parameters.",
            "detail": safe_errors,
            "path": request.url.path,
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(
        "Unhandled exception on %s %s (%s)", request.method, request.url.path, type(exc).__name__,
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "ERROR",
            "error_type": "InternalServerError",
            "message": "AgentGuard encountered an internal error. Check the server log for details.",
            "path": request.url.path,
        },
    )


@app.get("/health", summary="Health Check")
async def health_check():
    return {
        "status": "healthy",
        "service": "AgentGuard Security Control Plane",
        "version": app.version,
        "reviewer_auth_configured": bool(_expected_reviewer_token()),
        "llm_configured": bool(os.getenv("GROQ_API_KEY", "").strip()),
    }


@app.post("/api/analyze", response_model=AnalysisResponse, summary="Analyze text and evaluate proposed actions")
async def analyze_document(request: AnalysisRequest, req: Request):
    enforce_rate_limit(_get_client_ip(req))
    try:
        response = agent.analyze_document(
            prompt=request.prompt,
            document_text=request.document_text,
            scenario_id=request.scenario_id,
            force_provenance=request.force_provenance,
        )
        response = _queue_review_if_required(response)
        _write_audit(response, request.prompt, "direct_input")
        return response
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail="Document analysis failed. Check the server log.") from exc


@app.post("/api/upload_and_analyze", response_model=AnalysisResponse, summary="Upload and inspect a PDF")
async def upload_and_analyze(
    req: Request,
    file: UploadFile = File(...),
    user_prompt: str = Form("Analyze this research paper and extract source-grounded claims."),
):
    enforce_rate_limit(_get_client_ip(req))
    filename = os.path.basename(file.filename or "document.pdf")[:255]
    buffers: list[bytes] = []
    total_bytes = 0

    # Stream and cap upload bytes rather than loading an unbounded request into memory.
    try:
        while True:
            part = await file.read(64 * 1024)
            if not part:
                break
            total_bytes += len(part)
            if total_bytes > MAX_UPLOAD_BYTES:
                audit_logger.log_evaluation(
                    verdict="BLOCK",
                    reason="Upload rejected because it exceeded the 10 MB byte limit.",
                    user_prompt=user_prompt,
                    file_name=filename,
                )
                raise HTTPException(status_code=413, detail="PDF size exceeds the 10 MB upload limit.")
            buffers.append(part)
    finally:
        await file.close()

    content = b"".join(buffers)
    if not content.startswith(b"%PDF-"):
        audit_logger.log_evaluation(
            verdict="BLOCK",
            reason="Upload rejected because it did not contain a PDF file header.",
            user_prompt=user_prompt,
            file_name=filename,
        )
        raise HTTPException(status_code=400, detail="The uploaded file is not a valid PDF.")

    try:
        chunks = rag.parse_pdf_bytes(content, filename=filename, max_pages=MAX_PDF_PAGES)
    except ValueError as exc:
        audit_logger.log_evaluation(
            verdict="BLOCK",
            reason=f"PDF ingestion rejected: {str(exc)[:500]}",
            user_prompt=user_prompt,
            file_name=filename,
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    full_text = "\n\n".join(chunk.text for chunk in chunks)
    if len(full_text) > MAX_TEXT_CHARS:
        audit_logger.log_evaluation(
            verdict="BLOCK",
            reason=f"Extracted PDF text exceeded the {MAX_TEXT_CHARS:,}-character processing limit.",
            user_prompt=user_prompt,
            file_name=filename,
        )
        raise HTTPException(status_code=413, detail=f"Extracted PDF text exceeds the {MAX_TEXT_CHARS:,}-character limit.")
    if not full_text.strip():
        audit_logger.log_evaluation(
            verdict="BLOCK",
            reason="PDF had no extractable text. OCR is not implemented in this MVP.",
            user_prompt=user_prompt,
            file_name=filename,
        )
        raise HTTPException(
            status_code=422,
            detail="No selectable text was found in this PDF. Scanned-image OCR is not implemented yet.",
        )

    # Fail before the LLM when suspicious instructions are found in the PDF.
    detection = PromptInjectionDetector.detect(full_text)
    if detection.is_injection:
        reason_text = "; ".join(detection.reasons[:5]) or "Suspicious instruction pattern detected"
        response = AnalysisResponse(
            mode="blocked",
            mode_reason="Pre-LLM document inspection blocked potential prompt injection.",
            tool_call_source=None,
            status="BLOCKED",
            extracted_claims=[
                "[NOT_ENOUGH_EVIDENCE] Claim extraction was skipped because the PDF was flagged for review."
            ],
            summary=(
                "AgentGuard detected prompt-injection-like content in the uploaded PDF. "
                "The document was not sent to the LLM, and no external tool was invoked. "
                f"Detector signals: {reason_text}."
            ),
            tool_call_attempted=None,
            tool_execution_result="NO TOOL EXECUTED",
            security_decision=None,
            action_lineage=[
                LineageNode(
                    id="node-upload",
                    type="DOCUMENT",
                    label="1. Uploaded PDF",
                    details=f"{filename}: {len(full_text)} extracted characters; marked untrusted.",
                    is_tainted=True,
                ),
                LineageNode(
                    id="node-detector",
                    type="INSTRUCTION",
                    label="2. Prompt-Injection Detector",
                    details=reason_text,
                    is_tainted=True,
                ),
                LineageNode(
                    id="node-block",
                    type="SECURITY_DECISION",
                    label="3. AgentGuard Pre-LLM BLOCK",
                    details="No LLM processing or external tool execution was allowed for this upload.",
                    is_tainted=True,
                ),
            ],
        )
        _write_audit(response, user_prompt, filename)
        return response

    try:
        response = agent.analyze_document(prompt=user_prompt, document_text=full_text)
        response = _queue_review_if_required(response)
        _write_audit(response, user_prompt, filename)
        return response
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Uploaded PDF analysis failed")
        audit_logger.log_evaluation(
            verdict="BLOCK",
            reason="Uploaded PDF analysis failed; details were kept in the server log.",
            user_prompt=user_prompt,
            file_name=filename,
        )
        raise HTTPException(status_code=500, detail="PDF analysis failed. Check the server log.") from exc


@app.get("/api/audit_logs", summary="Recent security audit logs")
async def get_audit_logs(
    req: Request,
    limit: int = Query(default=50, ge=1, le=100),
    x_reviewer_token: Optional[str] = Header(default=None, alias="X-Reviewer-Token"),
):
    enforce_rate_limit(_get_client_ip(req))
    _require_reviewer_token(x_reviewer_token)
    logs = audit_logger.get_recent_logs(limit=limit)
    return {"status": "SUCCESS", "count": len(logs), "audit_logs": logs}


@app.get("/api/pending_approvals", summary="Pending human approvals")
async def get_pending_approvals(
    req: Request,
    x_reviewer_token: Optional[str] = Header(default=None, alias="X-Reviewer-Token"),
):
    enforce_rate_limit(_get_client_ip(req))
    _require_reviewer_token(x_reviewer_token)
    approvals = mcp_gateway.get_pending_list()
    return {
        "pending": [
            {
                "approval_id": item.approval_id,
                "tool_name": item.tool_name,
                "tool_args": item.tool_args,
                "args_hash": item.args_hash,
                "reason": item.reason,
                "risk_level": item.risk_level.value,
                "provenance_source": item.provenance_source,
                "created_at": item.created_at,
                "status": item.status,
            }
            for item in approvals
        ]
    }


@app.post("/api/approve", summary="Approve or reject one pending tool action")
async def approve_tool_call(
    request: ApprovalDecisionRequest,
    req: Request,
    x_reviewer_token: Optional[str] = Header(default=None, alias="X-Reviewer-Token"),
):
    enforce_rate_limit(_get_client_ip(req))
    _require_reviewer_token(x_reviewer_token)
    try:
        if request.approve:
            result = mcp_gateway.approve_tool_call(
                approval_id=request.approval_id,
                expected_hash=request.expected_hash,
                canonical_args=request.canonical_args,
            )
        else:
            result = mcp_gateway.reject_tool_call(request.approval_id)
        return {"status": "SUCCESS", "decision": result}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Approval workflow failed")
        raise HTTPException(status_code=500, detail="Approval workflow failed. Check the server log.") from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
