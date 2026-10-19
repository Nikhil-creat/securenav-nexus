# SecureNav-NEXUS v2 architecture

## Planes
| Plane | Components | Trust boundary |
|---|---|---|
| Control (DDS, domain 42) | Nav2, vision, brain, IDS, HSM, fusion | SROS2: authenticated, encrypted, per-topic ACL |
| Intelligence | LangGraph agents, Qdrant RAG, Redis, Groq copilot | LLM can only escalate severity or engage e-stop |
| Assurance | audit ledger, policy engine, model signing | Ed25519 signatures, hash chain |
| Operations | FastAPI hub, Prometheus, Grafana, nexusctl | bearer token, localhost bind |
| Fleet | fleet manager, revocation CRDT | signed records only |

## Safety-critical principles
1. **Fail-safe first**: e-stop is asserted before analysis, revocation or logging.
2. **Deterministic core**: hard rules (allowlists, z-score limit, geofence) never depend on an LLM or learned model.
3. **AI may tighten, never loosen**: agents can slow, stop or isolate. Releasing the e-stop is a human action.
4. **Verify before trust**: models are signature-checked; revocations are signature-checked; missions are policy-checked.
5. **Evidence by default**: security events are appended to a signed hash-chained ledger.

## Data flows
```
sensors -> vision (CNN+ViT) -> /perception/* -> brain (RAG triage) -> /agent/actions
sensors -> fusion (EKF, gating) -> /fusion/weights -> nav2
telemetry -> IDS (IsoForest + AE + rules + eBPF) -> /sys/e_stop, /security/alerts -> HSM revoke -> fleet CRDT gossip
operator directive -> brain planner -> policy engine -> /mission/waypoints (rejected if violating)
threats/overrides -> dashboard -> audit ledger (/api/ledger) + Prometheus (/metrics)
```

## Key modules
- `src/security/security_ids_node.py` IDS + responder; `src/security/hsm_emulator.py` HSM.
- `src/fusion/ekf_fusion.py` EKF with chi-square gate (99%, 2 DoF = 9.21).
- `src/common/policy_engine.py` geofence/no-go/speed; `policy/nexus.rego` OPA mirror.
- `src/fleet/fleet_manager.py` Hungarian allocation, revocation CRDT.
- `src/supply_chain/model_signer.py` signed model manifests.
- `src/common/audit_ledger.py` tamper-evident ledger; `src/nexusctl.py` CLI.

## Architecture decision records
- **ADR-1 Hybrid PQC signatures**: Ed25519 + Dilithium3 when liboqs is present; both must verify. Reason: harvest-now-forge-later risk for long-lived identities.
- **ADR-2 Rule engine beside ML**: Isolation Forest under-scores far out-of-range values, so z-score and allowlist rules run independently.
- **ADR-3 CRDT revocations**: robots can be offline or partitioned; a grow-only record set converges without a coordinator.
- **ADR-4 LLM as advisor**: LLM output never lowers severity or releases safety interlocks.
