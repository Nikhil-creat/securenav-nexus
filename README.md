# SecureNav-NEXUS Ultimate

Secure, autonomous mobile-robot / drone platform: ROS 2 + SROS2 zero-trust, edge CNN+ViT perception
(ONNX/TensorRT), LangGraph agentic RAG (Qdrant + Redis), ML intrusion detection with eBPF auditing,
software-HSM with post-quantum hooks, Gazebo/Isaac fault-injection, and a live WebSocket ops dashboard.

> **Status honesty:** pure-logic components (IDS engine, HSM, mission parser, responder ordering) were executed
> and tested during generation. ROS 2 nodes, TensorRT engines, eBPF probes, Docker builds and GPU paths need a
> real ROS 2 Iron / NVIDIA / privileged-Linux host and have **not** been run here. Expect small integration fixes
> on first bring-up. The HSM is an emulator; the vision net ships untrained (random init, demo mode).

## 1. Topology

```
                         +-------------------- dashboard (FastAPI + WS, :8080 localhost) ---------------------+
                         |   /ws/clients  <-- fan-out --  /ws/ingest <-- telemetry/threats ; overrides -->    |
                         +-------------------------------------^---------------------------------------------+
                                                               | (token-auth WS)
 sensors/Gazebo --> [ros2-core-node: Nav2 + SROS2] <==DDS ENCRYPT==> [sec-ids-guardian: IsoForest+AE+rules+eBPF]
  /camera /lidar        ^   | /cmd_vel                                   | /sys/e_stop  /security/alerts
        |               |   v                                          v
        +--> [vision-perception-node: CNN+ViT, TRT/ONNX/Torch] --> /perception/*
                         |                                             |  revoke (unix socket)
                 /mission/waypoints <-- [agentic-rag-core: LangGraph] <-+--> [hsm-emulator-node: Ed25519 + Dilithium3 hybrid]
                                          | Qdrant (KB)  | Redis (state)
```

| Layer | Hardware | Software |
|---|---|---|
| Edge target | NVIDIA Jetson Orin (JetPack 6, CUDA 12) | ROS 2 Iron, TensorRT 8.6+, Docker + NVIDIA toolkit |
| Dev target | x86 workstation + NVIDIA GPU (8 GB+) | Ubuntu 22.04, Docker 24+, Gazebo Harmonic |
| Optional | TPM / PKCS#11 HSM | liboqs-python for real Dilithium3 |

## 2. Layout

| Path | What |
|---|---|
| `docker/Dockerfile`, `docker-compose.yml` | multi-stage image (targets: core, vision, brain, ids, hsm, dashboard) |
| `scripts/setup_sros2.sh`, `security/*.xml` | keystore, CA, enclaves, signed governance + per-node ACLs |
| `src/vision/vision_node.py` | CNN+ViT net, ONNX/TensorRT export, backend auto-select, ROS node |
| `src/agents/agentic_brain.py` | LangGraph: Security Audit (RAG) -> Self-Healing; Mission Planner |
| `src/security/security_ids_node.py` | features, IsolationForest + autoencoder + hard rules, eBPF, fail-safe responder |
| `src/security/hsm_emulator.py` | encrypted vault, hybrid signatures, signed revocations |
| `src/dashboard/` | FastAPI hub + Tailwind UI (vanilla JS, no build step) |
| `sim/` | Gazebo bridge launch, fault injector, attack suite |
| `.github/workflows/ci.yml` | flake8, mypy, bandit, pytest, SROS2 smoke test, Trivy |

## 2b. AI copilot, live demo and portfolio

| Path | What |
|---|---|
| `src/assistant/groq_assistant.py` | NEXUS-AI: Groq tool-calling copilot (state, threats, RAG, e-stop engage only) with offline fallback |
| `POST /api/assistant` | dashboard endpoint; put your free key in `secrets/groq_api_key.txt` (https://console.groq.com/keys) |
| `docs/index.html` | GitHub Pages demo: live digital twin, attack lab, in-browser IDS, RAG search, voice, Groq chat, credentials |
| `DEPLOY_GITHUB_PAGES.md` | step-by-step Pages deployment |

Safety rule: the AI may engage the e-stop but can never release it; that stays a human action.

## 3. Quick start

```bash
git clone <repo> && cd securenav-nexus
source /opt/ros/iron/setup.bash
./scripts/setup_sros2.sh                 # keystore + signed policies + secrets/
docker compose build                     # add --build-arg BASE_IMAGE=... on Jetson
make export                              # .pt -> ONNX -> TensorRT FP16 (needs TensorRT)
docker compose up -d
cat secrets/dashboard_token.txt          # paste into http://localhost:8080
```

SROS2 note: `permissions.xml` subject names (`CN=ids,...`) must match the enclave certificate subjects that
`ros2 security create_enclave` generates; adjust the templates if your CA subject format differs.

## 4. Attack and recovery testing

```bash
ros2 launch sim/nexus_sim.launch.py world:=warehouse.sdf drive:=diff   # simulation
docker compose logs -f sec-ids-guardian                                 # wait for "baseline trained" (~60 s)
make attack                                                             # dos, rogue, spoof, gps_denial
```

Expected: **rogue /cmd_vel** -> critical -> `/sys/e_stop` true, HSM revokes the publisher, brain applies PB-01.
**dos** -> ML + rate rule -> high -> degraded-safe profile. **spoof** -> vision anomaly + sensor desync -> camera
fusion weight drops to 0.1, speed cap 0.3 m/s. Verify RAG triage: `ros2 topic echo /agent/actions`.
Release the e-stop from the dashboard (human-in-the-loop). Run the injector only in simulation.

## 5. Security design notes

- Fail-safe first: the responder asserts e-stop *before* analysis or revocation; revocation errors never block it.
- The LLM (optional) can only escalate severity; rule-based critical decisions never depend on it.
- Hard rules (allowlisted `/cmd_vel` publishers, e-stop override, unknown subscribers, eBPF hits, z-score limit) run
  independently of the learned models, because Isolation Forest under-scores far out-of-range values.
- Baseline learning assumes the first `IDS_WARMUP` seconds are clean; train on recorded clean runs for production.
- Compose runs services read-only with dropped capabilities; only the IDS holds BPF/PERFMON/SYS_ADMIN. For production
  replace shared-token dashboard auth with mTLS/OIDC and the HSM emulator with a hardware module.
- Quantum readiness: hybrid Ed25519 + Dilithium3 signatures when `oqs` is present; Kyber KEM for key transport is the next hook.

## 6. Roadmap, compliance and scaling

- **ISO/SAE 21434:** run a TARA per release (assets: `/cmd_vel`, localization, update channel, keystore); trace cybersecurity
  goals -> `governance.xml`/`permissions.xml` -> tests in `tests/` and `sim/`; keep the cybersecurity case and monitoring/incident
  playbooks (`knowledge/playbooks.md`) under change control. Pair with UN R155/R156 if used on-road.
- **IEC 62443 / NIST 800-82:** segment the DDS domain from the dashboard network; log retention and tamper-evident audit trail.
- **Fleet scaling:** replace multicast discovery with a Fast DDS Discovery Server; per-robot enclaves and a fleet CA; central
  Qdrant/Redis; OTA with signed images.
- **Swarm path:** add a mission-allocation agent, inter-robot SROS2 federation, and consensus on revocation lists.
- **Next engineering steps:** train the perception net on your dataset, INT8 calibration, Kyber hook, hardware HSM driver,
  real eBPF allowlists from observed baselines.
