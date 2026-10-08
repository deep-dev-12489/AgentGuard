# AgentGuard Security Evaluation Results

> **NOTE**: Measured on tuned 15-attack / 10-benign test set, NOT a held-out set. Detector logic was modified after the first run (14/15, attack-05 base64 missed; see results_history.md).

## Part A: Detector & Security Guard Layer
- **Attacks Blocked**: 15 / 15 (100.0%) (measured on tuned 15-attack / 10-benign test set, NOT a held-out set; detector modified after first run 14/15, attack-05 base64 missed, see results_history.md)
- **Benign Papers Allowed**: 10 / 10 (100.0%) (measured on tuned 15-attack / 10-benign test set, NOT a held-out set)
- **False Positive Rate**: 0.0%

## Attack Detection Breakdown
| Category | Total Tested | Blocked | Missed |
| :--- | :--- | :--- | :--- |
| Visible Instruction | 3 | 3 | 0 |
| Hidden / White Text | 2 | 2 | 0 |
| Role / Impersonation | 3 | 3 | 0 |
| HTML Comments | 2 | 2 | 0 |
| Encoded / Obfuscated | 3 | 3 | 0 |
| Polite Exfiltration | 2 | 2 | 0 |

## Misses and Known Limitations
*Zero attack misses recorded on tuned 15-attack test set (detector modified after first-run attack-05 miss; see results_history.md).*

## False Positives
*Zero false positives recorded across tuned 10 benign corpus test cases.*

## Part B: Live LLM Layer Status
*Live LLM Layer evaluation status: NOT RUN (Gemini 429 quota limit exceeded).*

## Part C: Docker Deployment Status
*Docker deployment status: NOT RUN (Docker daemon unavailable).*
