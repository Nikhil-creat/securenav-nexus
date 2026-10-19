# Changelog

## 2.0.0
### Added
- **EKF sensor fusion** (`src/fusion`): trust-weighted fusion of GPS / LiDAR-odometry / vision with chi-square innovation gating; spoofed sources are rejected, down-weighted and flagged.
- **Tamper-evident audit ledger** (`src/common/audit_ledger.py`): SHA-256 hash chain, Ed25519 signature per entry, Merkle checkpoints; wired into the dashboard (threats, operator overrides) and exposed at `GET /api/ledger`.
- **Policy engine** (`src/common/policy_engine.py`, `policy/nexus.rego`): geofence, no-go zones, speed zones, mission limits. The agentic brain refuses to publish missions that violate policy.
- **Fleet orchestration** (`src/fleet`): Hungarian optimal task allocation, heartbeats, and signed revocation gossip as a grow-only CRDT with fleet-wide quarantine.
- **Model supply-chain integrity** (`src/supply_chain`): signed manifests; the vision node refuses unsigned/modified weights when `NEXUS_REQUIRE_SIGNED=1`.
- **Observability**: Prometheus `/metrics`, Grafana dashboard, `docker compose --profile observability up`.
- **`nexusctl`** operator CLI (keygen, sign/verify models, verify ledger, plan + policy check).
- **Training pipeline** (`vision.train_vision`) with synthetic scenes and a spoof-detection head.
- **Kubernetes manifests** with default-deny NetworkPolicy and restricted pod security.
- CodeQL, Dependabot and a release workflow publishing images to GHCR.
- TARA (ISO/SAE 21434), architecture, security policy and ADR documents.
- Groq tool-calling copilot with model fallback; isometric 3D console on GitHub Pages.
### Changed
- Mission parser moved to `common.mission_parser`; shared by brain, CLI and tests.
- CI: flake8 line length 170, MyPy advisory.

## 1.0.0
- Initial platform: SROS2 zero trust, CNN+ViT perception, LangGraph agentic RAG, ML IDS + eBPF, HSM emulator, dashboard, simulation harness.
