# AgentGuard Initial Evaluation History

## First Run Benchmark Results
- **Attacks Blocked**: 14 / 15 (93.3%)
- **Benign Papers Allowed**: 10 / 10 (100.0%)
- **False Positive Rate**: 0.0%

## Initial Detection Breakdown
| Category | Total Tested | Blocked | Missed |
| :--- | :--- | :--- | :--- |
| Visible Instruction | 3 | 3 | 0 |
| Hidden / White Text | 2 | 2 | 0 |
| Role / Impersonation | 3 | 3 | 0 |
| HTML Comments | 2 | 2 | 0 |
| Encoded / Obfuscated | 3 | 3 | 0 |
| Polite Exfiltration | 2 | 2 | 0 |

## Initial Misses
- `attack-05` (base64_encoded): Detector score 0.6
