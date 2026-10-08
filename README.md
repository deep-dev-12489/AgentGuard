# AgentGuard 🛡️ — Autonomous AI Agent Security Control Plane

[![Next.js 14](https://img.shields.io/badge/Frontend-Next.js%2014-000000?style=for-the-badge&logo=nextdotjs)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![PydanticAI](https://img.shields.io/badge/Agent-PydanticAI-E92063?style=for-the-badge)](https://ai.pydantic.dev/)
[![MCP Protocol](https://img.shields.io/badge/Tools-Model%20Context%20Protocol-6A1B9A?style=for-the-badge)](https://modelcontextprotocol.io/)
[![Tailwind CSS](https://img.shields.io/badge/Styling-Tailwind%20CSS-38BDF8?style=for-the-badge&logo=tailwindcss)](https://tailwindcss.com/)

> **The Core Axiom**: **"Information ≠ Authorization"**  
> *Autonomous AI agents can freely read and analyze untrusted research papers, but their ability to execute real-world tools (via Model Context Protocol) is strictly firewalled at runtime based on data provenance taint tracking.*

---

## 🎯 The Problem AgentGuard Solves

Standard AI guardrails only inspect user prompts. However, when an autonomous AI agent ingests external documents (like research PDFs or web pages), **indirect prompt injections** embedded within those documents can manipulate the LLM into executing unauthorized external tools (e.g., exfiltrating database records to an attacker's email).

**AgentGuard** intercepts every tool call request at the runtime proxy level before execution and evaluates data provenance to enforce strict security boundaries.

---

## 🛡️ The 3-Tier Security Decision Engine

```
                                  [ Tool Call Attempted ]
                                             │
                                             ▼
                          [ AgentGuard Security Control Plane ]
                                             │
             ┌───────────────────────────────┼───────────────────────────────┐
             ▼                               ▼                               ▼
     🟢  [ ALLOW ]                   🟡  [ REVIEW ]                  🔴  [ BLOCK ]
  Safe, user-authorized           High-risk action requiring       Indirect prompt injection
 tool call (e.g., academic       human operator approval          or data taint detected from
 search). Dispatched to MCP.     via interactive UI modal.         untrusted PDF. Halted instantly.
```

---

## 🏗️ System Architecture

```
┌──────────────────────────────────┐
│  Uploaded Research PDF / Stream  │
└────────────────┬─────────────────┘
                 │
                 ▼
┌──────────────────────────────────┐         ┌──────────────────────────────────┐
│ Next.js 14 Enterprise Dashboard  ├────────►│ FastAPI Security Server (Port 800)│
└──────────────────────────────────┘         └────────────────┬─────────────────┘
                                                              │
                                                              ▼
                                             ┌──────────────────────────────────┐
                                             │ Research Agent (PydanticAI / LLM)│
                                             │ - pypdf Document Parser & RAG    │
                                             │ - Claim & Evidence Reasoning     │
                                             └────────────────┬─────────────────┘
                                                              │
                                                  (Tool Request Intercepted)
                                                              │
                                                              ▼
                                             ┌──────────────────────────────────┐
                                             │ AgentGuard Security Control Plane│
                                             │ 1. Provenance Taint Tracker      │
                                             │ 2. Tool Risk Classifier          │
                                             │ 3. PII & Exfiltration Check      │
                                             │ 4. Policy Engine Evaluation      │
                                             └────────────────┬─────────────────┘
                                                              │
                                 ┌────────────────────────────┼────────────────────────────┐
                                 ▼                            ▼                            ▼
                            🟢 [ ALLOW ]                 🟡 [ REVIEW ]                🔴 [ BLOCK ]
                                 │                            │                            │
                                 ▼                            ▼                            ▼
                        (Execute MCP Tool)          (Human Approval Modal)        (Halt & Audit Log)
```

---

## 📂 Project Repository Structure

```
.
├── backend/
│   ├── main.py                  # FastAPI server (/api/analyze, /api/upload_and_analyze, /api/approve)
│   ├── agent_logic.py           # ResearchAgent & AgentGuardInterceptor Control Plane Engine
│   ├── rag_engine.py            # pypdf document chunking & provenance tagging
│   ├── mcp_gateway.py           # Model Context Protocol Proxy & Human Review Queue
│   ├── create_sample_pdfs.py    # Test PDF generator script
│   ├── samples/                 # Sample test PDF papers (Safe & Malicious)
│   └── requirements.txt         # Backend Python dependencies
│
└── frontend/
    ├── src/
    │   └── app/
    │       ├── page.tsx          # Lakera-style Enterprise Dashboard & Live Simulator
    │       ├── layout.tsx        # App Router layout
    │       └── globals.css       # Tailwind CSS & theme styling
    ├── package.json             # Frontend Node.js dependencies
    ├── postcss.config.js        # PostCSS configuration
    ├── tailwind.config.ts       # Tailwind styling setup
    └── tsconfig.json            # TypeScript configuration
```

---

## ⚡ Quick Start & Local Setup

### 1. Prerequisites
* **Python 3.10+**
* **Node.js 18+** & **npm**

### 2. Backend Setup (FastAPI)
```bash
# Navigate to backend directory
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Start FastAPI server on port 8000
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
* **Swagger API Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### 3. Frontend Setup (Next.js)
```bash
# Navigate to frontend directory in a new terminal
cd frontend

# Install Node dependencies
npm install

# Start Next.js development server on port 3000
npm run dev
```
* **Live Enterprise Dashboard**: [http://localhost:3000](http://localhost:3000)

---

## 🧪 Testing the 3 Security Scenarios

1. **🔴 Prompt Injection Attack (`BLOCK`)**:
   * Click the **"🔴 Prompt Injection (BLOCK)"** tab on [http://localhost:3000](http://localhost:3000).
   * AgentGuard intercepts the embedded payload attempting to exfiltrate patient records via `export_customer_data` $\rightarrow$ Outputs a **`BLOCK`** verdict and highlights tainted lineage nodes.

2. **🟢 Safe Academic Search (`ALLOW`)**:
   * Click the **"🟢 Safe Research (ALLOW)"** tab.
   * Triggers `search_academic_db` $\rightarrow$ AgentGuard evaluates tool risk as `LOW` $\rightarrow$ Outputs an **`ALLOW`** verdict and returns PubMed/ArXiv citations.

3. **🟡 Human Operator Review (`REVIEW`)**:
   * Click the **"🟡 Human Review (REVIEW)"** tab.
   * User requests `export_customer_data` $\rightarrow$ AgentGuard flags `CRITICAL` tool risk $\rightarrow$ Renders the interactive **Human Authorization Panel** with **Approve/Deny** buttons.

---

## 📄 License & Attribution
Built for the **AgentGuard Hackathon**. Released under the MIT License.
