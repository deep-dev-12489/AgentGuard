# AgentGuard Security Evaluation Results

> **NOTE**: Detector logic was modified after observing initial evaluation failures on attack-05. These numbers represent iteration on a known test set, NOT held-out evaluation.

## Part A: Detector & Security Guard Layer
- **Attacks Blocked**: 15 / 15 (100.0%)
- **Benign Papers Allowed**: 10 / 10 (100.0%)
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
*Zero attack misses recorded in detector/guard layer.*

## False Positives
*Zero false positives recorded across the 10 benign corpus test cases.*

## Part B: Live LLM Layer Status
*Live LLM Layer evaluation status: unavailable.*
