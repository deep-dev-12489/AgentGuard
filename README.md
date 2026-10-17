AgentGuard — AI Agent Runtime Security Control Plane

AgentGuard is a hackathon MVP that demonstrates a simple principle: information is not authorization. Documents and other external content are treated as untrusted input, while tool actions are evaluated by deterministic policy before a registered tool can run.

What is implemented

Pre-LLM PDF inspection: PDF uploads are streamed with a 10 MB cap, validated as PDFs, limited to 50 pages, and scanned for prompt-injection-like patterns before general LLM analysis.

Deterministic tool policy: action risk, source provenance, destination allowlists, and export record limits are evaluated in Python. LLM output is not the authority for ALLOW/REVIEW/BLOCK.

Single-use human approval: critical trusted actions can be queued for review. The approval is bound to a SHA-256 hash of the tool name and arguments, expires after 10 minutes, and is atomically claimed before execution.

SQLite audit trail: security evaluations and approval outcomes persist across backend restarts.

Scripted demo scenarios: the UI includes three intentionally scripted scenarios (malicious export, safe academic search, and a review-required user export) to make the control-plane decisions reproducible.

Bounded PDF parsing and rate limits: PDF byte size, page count, text length, request sizes, and per-IP request rate are capped.

Optional Groq text analysis: set GROQ_API_KEY to enable text-only analysis through the OpenAI-compatible Groq API. This adapter does not generate live tool calls.

Important implementation boundaries

export_customer_data and send_email are mock tools. No real customer database is connected and no real email is sent. An allowed result is labelled MOCK EXECUTION.

search_academic_db attempts the public arXiv API. If it cannot retrieve results, the response explicitly says MOCK DATA ONLY; it does not invent realistic-looking citations.

Claim extraction is document-only. It is not independent research verification and does not use a trusted vector database or external evidence corpus yet. Extracted claims remain NOT_ENOUGH_EVIDENCE until that evidence retrieval is implemented.

The prompt-injection detector is heuristic. It can have false positives and false negatives; it is one defense layer, not a guarantee that all prompt injection is prevented.

This is a local/demo MVP, not an isolated production sandbox. Tools execute in the backend process, so do not connect real data or real outbound actions without additional authentication, isolation, monitoring, and deployment hardening.

Project structure

AgentGuard/
├── backend/
│   ├── main.py                 # FastAPI endpoints, input limits, audit workflow
│   ├── agent_logic.py          # Data models, guarded tools, scripted scenarios
│   ├── detectors.py            # Prompt-injection and sensitive-data heuristics
│   ├── rag_engine.py           # Bounded PDF/text ingestion and claim extraction
│   ├── mcp_gateway.py          # Policy engine and human approval enforcement
│   ├── database.py             # SQLite audit and approval persistence
│   ├── policy.yaml             # Risk levels and allowlists
│   └── samples/                # Sample PDFs for the demo
├── frontend/
│   ├── src/app/page.tsx        # Dashboard and interactive scenarios
│   └── src/app/api/approve/    # Server-side approval proxy (keeps token out of browser)
├── tests/test_agent_guard.py
├── evaluate.py
├── .env.example
├── Dockerfile
└── docker-compose.yml

Run locally (Windows PowerShell)

Use Python 3.11+ and Node.js 20+.

1. Configure the backend

From the repository root:

Copy-Item .env.example .env

Edit .env. Set REVIEWER_TOKEN to a random value of at least 32 characters; the example placeholder is deliberately rejected by the API. Copy the same value into frontend/.env.local. GROQ_API_KEY is optional; without it, the project runs in local fallback mode.

To generate a strong token in PowerShell, run:

$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$token = [Convert]::ToBase64String($bytes)
$rng.Dispose()
$token

Paste the printed token into both environment files. Do not commit either real .env file.

2. Start FastAPI

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

Health check: http://127.0.0.1:8000/health
API docs: http://127.0.0.1:8000/docs

3. Start Next.js

In a second terminal:

Copy-Item frontend/.env.local.example frontend/.env.local
Set-Location frontend
npm ci
npm run dev

Open http://localhost:3000. Confirm that REVIEWER_TOKEN in frontend/.env.local matches the backend token. The reviewer token is read by the Next.js server-side route and is not embedded in browser code.

Test the backend

From the repository root, with the virtual environment active:

python -m pytest tests/test_agent_guard.py -v
python evaluate.py

The evaluation script uses a small, hand-built corpus. Its results are not a held-out security benchmark and must not be described as a general detection guarantee.

Optional Docker Compose

Create .env from .env.example and set REVIEWER_TOKEN.

Run:

docker compose up --build

The app should be available at http://localhost:3000, with FastAPI at http://localhost:8000. Docker deployment should be tested in the target environment before a live demo.

Main API routes

Method

Route

Purpose

GET

/health

Basic health and configuration status

POST

/api/analyze

Analyze text or run a scripted demo scenario

POST

/api/upload_and_analyze

Upload and inspect a PDF

GET

/api/pending_approvals

List pending approvals; reviewer token required

POST

/api/approve

Approve/reject an action; reviewer token required

GET

/api/audit_logs

Read audit records; reviewer token required

Demo storyline

Indirect prompt injection: choose the malicious preset. AgentGuard blocks the scripted action because the source is untrusted and injection is flagged.

Safe academic search: choose the academic search preset. The read-only search action is evaluated as LOW risk.

Human approval: choose the user export preset. The critical action enters REVIEW; approve it to run the mock tool through the hash-verified, guarded path, or reject it to prevent execution.

Every demo label should make the distinction between scripted simulation, LLM text analysis, and mock tool execution clear.