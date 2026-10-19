# Threat Analysis and Risk Assessment (ISO/SAE 21434 style) - SecureNav-NEXUS v2

Scales: Impact S (safety) / F (financial) / O (operational) / P (privacy), 1-4. Feasibility 1-4 (4 = easy). Risk = max impact x feasibility.

## Assets
| ID | Asset | Why it matters |
|---|---|---|
| A1 | `/cmd_vel` actuation channel | direct physical control |
| A2 | Localization sensors (GPS, LiDAR, camera) | wrong position -> unsafe motion |
| A3 | Node identities / keystore / HSM | root of trust |
| A4 | ML model artifacts | poisoned weights change perception |
| A5 | Mission planner + policy | defines where the robot may go |
| A6 | Audit ledger | accountability and forensics |
| A7 | Operator console and API keys | human override path |

## Threat scenarios
| ID | Threat (STRIDE) | Asset | Impact | Feas. | Risk | Controls | Residual |
|---|---|---|---|---|---|---|---|
| T1 | Rogue node publishes `/cmd_vel` (Spoof/EoP) | A1 | S4 | 2 | 8 | SROS2 ACL, IDS allowlist rule, e-stop, HSM revoke, fleet CRDT quarantine | Low |
| T2 | Message flood DoS | A1 | S3 | 4 | 12 | rate/z-score detection, isolate, degraded profile | Medium |
| T3 | GPS spoofing / jump | A2 | S4 | 3 | 12 | EKF innovation gate, trust decay, LiDAR-odom fallback | Medium |
| T4 | Camera replay / adversarial patch | A2 | S3 | 3 | 9 | anomaly head, cross-modal desync check, fusion re-weight | Medium |
| T5 | Swapped / poisoned model weights | A4 | S4 | 2 | 8 | signed manifests, `NEXUS_REQUIRE_SIGNED=1` | Low |
| T6 | Malicious mission leaves geofence | A5 | S4 | 2 | 8 | policy engine rejects, OPA mirror | Low |
| T7 | Log tampering to hide an attack | A6 | O3 | 2 | 6 | hash chain + signatures, Merkle checkpoints, `nexusctl ledger-verify` | Low |
| T8 | Operator token theft | A7 | S4 | 2 | 8 | localhost bind, rotate token, run behind mTLS/OIDC | Medium |
| T9 | Prompt injection steering the copilot | A1/A5 | S3 | 3 | 9 | LLM cannot release e-stop or bypass policy; tool args validated | Medium |
| T10 | Harvest-now-forge-later on identities | A3 | O4 | 1 | 4 | hybrid Dilithium3 hook, key rotation | Low |

## Cybersecurity goals
CG1 only authorised nodes actuate; CG2 localization integrity; CG3 artifact integrity; CG4 safe state on integrity loss; CG5 non-repudiable security log.
Traceability: CG1 -> `permissions.xml`, IDS rules, tests `test_nexus`, sim `fault_injector`; CG2 -> EKF tests; CG3 -> `test_model_supply_chain`; CG4 -> responder ordering test; CG5 -> ledger tests.

## Open items before real-world use
Independent penetration test, hardware HSM, secure boot and measured boot on Jetson, formal safety case (ISO 26262 / UL 4600), fuzzing of DDS parsers.
