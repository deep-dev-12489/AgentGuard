# hackindia-ai-cybertech-hackathon-2026-deepai
Hackathon team repository for Deep.ai - [hackindia-team:hackindia-ai-cybertech-hackathon-2026:deepai]

# AgentGuard: Autonomous Security Control Plane for AI Research Agents

AgentGuard is a security control plane and runtime interceptor for AI research agents. It enforces the principle **"Information != Authorization"** by tracking data provenance, detecting prompt injections, and intercepting unauthorized tool calls before execution.

---

## Key Features

1. **Guarded Tool Execution (`GuardedTool`)**: In-process security interception wrapper for tool execution (`export_customer_data`, `send_email`, `search_academic_db`).
2. **Data Provenance & Taint Tracking (`SessionContext`)**: Distinguishes trusted user context from untrusted PDF chunks and web data. Tainted contexts block high-risk tool calls (unit-tested with mocked LLM).
3. **Pluggable Multi-Heuristic Detector (`PromptInjectionDetector`)**: Detects role impersonation, system overrides, hidden text markers, base64 blobs, and polite exfiltration phrasing.
4. **Human-in-the-Loop Approval Queue (`MCPGateway` + SQLite)**: Persists pending approvals in SQLite (`agentguard_audit.db`) (SQLite reload verified in the same process), enforces SHA-256 argument hash verification, single-use approval tokens, and reviewer authentication.
5. **Real Free arXiv Search Integration**: Direct integration with arXiv API for academic evidence queries.
6. **Hardened Upload Pipeline**: Enforces 10MB size limits, `%PDF` header validation, 50-page limits, and per-IP rate limiting.

---

## Measured Implementation Facts

- **Execution Architecture**: Guard runs in the same Python process as the research agent (single process).
- **Taint Enforcement**: Guard blocks HIGH/CRITICAL tool calls when untrusted content is in context (verified via unit tests with a mocked LLM).
- **Evaluation Corpus**: 15/15 attacks flagged, 10/10 benign allowed, measured on a tuned test set, NOT a held-out set. First-run benchmark was 14/15 (attack-05 base64 missed; see `results_history.md`).
- **Claim Extraction**: Document claim verdicts use a keyword heuristic (`verdict_method: keyword_heuristic`).
- **Live LLM Execution**: Live Gemini tool-calling is NOT RUN (429 quota limit exceeded).
- **Docker Deployment**: Docker build is NOT RUN (Docker daemon unavailable).

---

## System Architecture

```
[ User Prompt / PDF Document ] 
           │
           ▼
 [ RAG & Document Pipeline ] ──► [ PromptInjectionDetector ]
           │                                 │
           ▼ (Taint Tagging)                 ▼
  [ Research Agent / Gemini LLM ] ◄── [ SessionContext ]
           │
           ▼ (Tool Call Attempt)
  [ AgentGuard Interceptor ] ──► [ policy.yaml ]
           │
 ┌─────────┼─────────┐
 ▼         ▼         ▼
ALLOW   REVIEW    BLOCK
 │         │         │
 ▼         ▼         ▼
Tool    SQLite    Prevent
Run     Queue    Execution
```

> **Note**: Document claim verdicts are derived via a `keyword_heuristic` matching engine in `backend/rag_engine.py`.

---

## Quick Start Guide

### Prerequisites
- Python 3.10+
- Node.js 18+

### Setup & Execution

1. **Environment Configuration**:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and set your `GEMINI_API_KEY`.

2. **Backend Execution**:
   ```bash
   pip install -r backend/requirements.txt
   uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
   ```

3. **Frontend Execution**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   Open `http://localhost:3000` in your browser.

4. **Docker Execution (Optional Container Build)**:
   ```bash
   docker-compose up --build
   ```

---

## Test & Evaluation Suite

Run the unit test suite:
```bash
python -m pytest tests/test_agent_guard.py -v
```

Run the attack corpus benchmark:
```bash
python evaluate.py
```

---

## Known Limitations & Security Posture

- **Single-Process Scope**: AgentGuard runs as a Python class wrapper within the agent process, not as an isolated container sandbox.
- **Novel Obfuscation**: Highly sophisticated or previously unknown prompt obfuscations may bypass pattern heuristics; AgentGuard mitigates this by enforcing strict taint-based control flow policies.
- **Allowed Tools & Destinations**: Requests targeting allowlisted email domains or safe tools pass security checks by design; granular data loss prevention policies should complement transport safety.
- **Model-Level Jailbreaks**: Model alignment failures are handled in-process by the AgentGuard policy interceptor.
