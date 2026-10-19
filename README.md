# SecureNav-NEXUS v2: Autonomous Cyber-Physical Defense Platform

[![ci](https://github.com/Nikhil-creat/securenav-nexus/actions/workflows/ci.yml/badge.svg)](https://github.com/Nikhil-creat/securenav-nexus/actions)
[![codeql](https://github.com/Nikhil-creat/securenav-nexus/actions/workflows/codeql.yml/badge.svg)](https://github.com/Nikhil-creat/securenav-nexus/actions)
![version](https://img.shields.io/badge/version-2.0.0-orange) ![license](https://img.shields.io/badge/license-MIT-green)

A zero-trust platform that lets an autonomous robot or drone **detect cyber-physical attacks, fail safe, prove what happened, and keep a fleet consistent**.
ROS 2 + SROS2, edge CNN+ViT perception, EKF sensor fusion, agentic RAG, ML intrusion detection with eBPF, a software HSM with
post-quantum hooks, a signed audit ledger, mission policy enforcement, fleet orchestration, and a Groq-powered AI copilot.

**Live console:** https://nikhil-creat.github.io/securenav-nexus/ (isometric digital twin, attack lab, copilot, ledger).

> **Status honesty.** The pure-logic core (IDS engine, HSM, EKF, policy, ledger, fleet, supply chain, CLI, mission parser) is unit-tested.
> ROS 2 nodes, TensorRT, eBPF, GPU paths, Docker/K8s deployments and Groq calls need a real environment and were not executed in the
> generation sandbox, so expect small integration fixes on first bring-up. The HSM is an emulator and the default vision weights are
> untrained until you run `vision.train_vision`. Not a certified safety product (see `SECURITY.md`).

## What is new in v2
| Capability | Module | Why it matters |
|---|---|---|
| EKF sensor fusion + spoof gating | `src/fusion` | rejects GPS/camera spoofing with chi-square innovation tests, down-weights liars |
| Tamper-evident audit ledger | `src/common/audit_ledger.py` | hash chain + Ed25519 + Merkle root; `GET /api/ledger`; `nexusctl ledger-verify` |
| Mission policy engine | `src/common/policy_engine.py`, `policy/nexus.rego` | geofence, no-go and speed zones; brain refuses violating missions |
| Fleet orchestration | `src/fleet` | Hungarian optimal allocation, signed revocation CRDT, fleet-wide quarantine |
| Model supply-chain integrity | `src/supply_chain` | signed manifests; vision node rejects tampered weights (`NEXUS_REQUIRE_SIGNED=1`) |
| Observability | `src/common/metrics.py`, `deploy/` | Prometheus `/metrics`, Grafana dashboard, `--profile observability` |
| Operator CLI | `src/nexusctl.py` | keygen, sign/verify models, verify ledger, plan + policy check |
| Training pipeline | `src/vision/train_vision.py` | synthetic scenes + spoof-detection head |
| Kubernetes | `deploy/k8s/nexus.yaml` | default-deny network policy, restricted pod security |
| DevSecOps | `.github/workflows` | CI, CodeQL, Dependabot, SBOM, GHCR release images |
| Assurance docs | `documentation/` | ISO/SAE 21434 style TARA, architecture, ADRs, roadmap |

## Architecture (summary)
```
sensors -> vision (CNN+ViT) --------------------> brain (LangGraph + Qdrant RAG) --policy gate--> /mission/waypoints
sensors -> fusion (EKF, gating) -> /fusion/weights                         ^
telemetry -> IDS (IsoForest + AE + rules + eBPF) -> /sys/e_stop -> HSM revoke -> fleet CRDT gossip
threats / overrides -> dashboard (FastAPI WS) -> signed ledger + Prometheus -> Grafana ; Groq copilot (can stop, never release)
```
Full detail: `documentation/ARCHITECTURE.md`. Threat model: `documentation/TARA.md`.

## Quick start
```bash
pip install -r requirements/dev.txt
pytest -q                                   # unit tests (no ROS needed)
PYTHONPATH=src python3 -m nexusctl plan "go to (25,4) then north 6 m"      # approved
PYTHONPATH=src python3 -m nexusctl plan "go to (4,3) then (14,16)"         # rejected: crosses no-go zone

source /opt/ros/iron/setup.bash && ./scripts/setup_sros2.sh               # keystore, signed policies, secrets/
docker compose up --build -d                                              # full stack (Jetson: --build-arg BASE_IMAGE=...)
docker compose --profile observability up -d                              # Prometheus :9090, Grafana :3000
cat secrets/dashboard_token.txt                                           # token for http://localhost:8080
```
Optional Groq copilot: put a free key from https://console.groq.com/keys in `secrets/groq_api_key.txt`.

## Operations
```bash
nexusctl keygen --out keys/ && nexusctl sign-model /models --key keys/ed25519.key
export NEXUS_REQUIRE_SIGNED=1 NEXUS_MODEL_PUBKEY=$(cat keys/ed25519.pub)   # vision node now refuses tampered weights
nexusctl ledger-verify ledger.jsonl --pub keys/ed25519.pub                 # prove the audit log was not altered
make attack                                                                # DoS, rogue publisher, camera spoof, GPS denial
```

## Repository map
`docker/` images | `scripts/` SROS2 PKI | `security/` governance + ACLs | `policy/` OPA | `src/vision` perception + training |
`src/fusion` EKF | `src/agents` brain | `src/security` IDS + HSM | `src/fleet` fleet | `src/supply_chain` model signing |
`src/common` ledger, policy, metrics, logging | `src/dashboard` hub | `src/assistant` Groq copilot | `sim/` fault injection |
`deploy/` Prometheus, Grafana, K8s | `documentation/` | `docs/` GitHub Pages console | `tests/`

## Safety and security principles
Fail-safe first (e-stop before analysis) | deterministic rules beside ML | AI may tighten, never loosen, safety | verify models, revocations and
missions before trusting them | security events are signed evidence. See `SECURITY.md` for scope and reporting.

## Author
Nikhil Chary Sriramoju: [GitHub](https://github.com/Nikhil-creat) | [LinkedIn](https://in.linkedin.com/in/nikhil-chary-sriramoju-95041b38a)

MIT licensed.
