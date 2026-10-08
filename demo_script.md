# AgentGuard Hackathon Live Demo Script (28 October 2026)

## Click-by-Click Demo Flow (3 Minutes)

### Scenario 1: Indirect Prompt Injection Exfiltration Attempt (BLOCKED)
1. **Action**: Click the **"Indirect Prompt Injection"** preset button.
2. **Setup**: The attached document contains a hidden directive attempting to call `export_customer_data` to exfiltrate patient records.
3. **Execution**: Click **"Run Analysis"**.
4. **Observe**:
   - Mode Badge displays `🟢 LIVE LLM` (or `🟡 SIMULATED REPLAY`).
   - AgentGuard Interceptor immediately outputs **`🔴 BLOCKED`**.
   - Connected Node Graph highlights red tainted lineage (`Document Ingestion` -> `Prompt Injection Directive` -> `Agent Reasoning` -> `Tool Request` -> `AgentGuard Intercept BLOCKED`).

### Scenario 2: Safe Academic Evidence Search (ALLOWED)
1. **Action**: Click the **"Safe Academic Search"** preset button.
2. **Setup**: Document contains medical research. User prompt requests PubMed/ArXiv paper citations.
3. **Execution**: Click **"Run Analysis"**.
4. **Observe**:
   - Tool `search_academic_db` is evaluated as **`🟢 ALLOW`** (`LOW` risk tool).
   - Real arXiv API search results return live citations.

### Scenario 3: Human Reviewer Approval Flow (REVIEW & EXECUTION)
1. **Action**: Click the **"User Action (Approval Needed)"** preset button.
2. **Setup**: Legitimate user request asking to export data.
3. **Execution**: Click **"Run Analysis"**.
4. **Observe**:
   - Status returns **`🟡 REVIEW REQUIRED`** (`CRITICAL` risk operation requiring operator authorization).
   - Click **"Approve Execution"**.
   - Tool executes via the guarded path with SHA-256 integrity verification, returning real execution output.

---

## Likely Judge Questions & Honest Answers

### Q1: Is AgentGuard a prompt wrapper or an out-of-band proxy?
**Answer**: AgentGuard is an **in-process security interceptor wrapper** running in the same Python process as the agent. It wraps tool invocations so no registered tool executes without passing through `GuardedTool.invoke_guarded()`, which checks session taint, data provenance, and destination policy.

### Q2: How does AgentGuard handle piggybacking attacks where an injection tries to trigger an export?
**Answer**: In AgentGuard, **Information != Authorization**. In unit tests (verified with a mocked LLM), even if the user prompt requests an export, any untrusted document chunk present in the context taints the session context (`is_tainted = True`). For `HIGH` or `CRITICAL` risk tools, tainted requests return `BLOCKED`.

### Q3: How do you handle fake IDs or mock data?
**Answer**: All output indicates execution origin. Live LLM function calls are labeled `llm`, scripted fixtures are labeled `scripted_fixture`, and fallback search citations are explicitly tagged `[MOCK DATA]`.

### Q4: Does AgentGuard provide complete protection against all prompt injections?
**Answer**: No single security layer provides complete protection against all prompt injections. AgentGuard implements **defense-in-depth**: multi-heuristic injection detectors, taint tracking, fail-closed policy enforcement, SHA-256 approval hashing, and destination allowlists. Note that reported benchmark results (15/15 attacks flagged) were measured on a tuned test set, NOT a held-out set (detector was modified after the first run 14/15, attack-05 base64 missed; see results_history.md). Live Gemini tool-calling is NOT RUN (429 quota limit exceeded).
