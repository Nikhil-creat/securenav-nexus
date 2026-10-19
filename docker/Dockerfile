# syntax=docker/dockerfile:1.6
# SecureNav-NEXUS Ultimate - multi-stage image. Build one service with --target <name>.
# Jetson Orin: --build-arg BASE_IMAGE=dustynv/ros:iron-pytorch-l4t-r36.2.0
ARG BASE_IMAGE=nvidia/cuda:12.2.2-cudnn8-runtime-ubuntu22.04

# ---------- Stage 1: ROS 2 Iron base ----------
FROM ${BASE_IMAGE} AS ros-base
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 PYTHONUNBUFFERED=1 \
    ROS_DISTRO=iron RMW_IMPLEMENTATION=rmw_fastrtps_cpp
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl gnupg2 lsb-release ca-certificates locales python3 python3-pip python3-venv \
    && curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key \
       -o /usr/share/keyrings/ros-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/ros-archive-keyring.gpg] http://packages.ros.org/ros2/ubuntu $(lsb_release -cs) main" \
       > /etc/apt/sources.list.d/ros2.list \
    && apt-get update && apt-get install -y --no-install-recommends \
      ros-iron-ros-base ros-iron-sensor-msgs ros-iron-geometry-msgs ros-iron-nav2-bringup \
      ros-iron-vision-msgs ros-iron-cv-bridge ros-iron-sros2 ros-iron-ros2cli \
      ros-iron-ros-gz python3-colcon-common-extensions \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 nexus
WORKDIR /opt/nexus
COPY requirements/base.txt /tmp/base.txt
RUN pip3 install --no-cache-dir -r /tmp/base.txt
COPY src/common /opt/nexus/common
ENV PYTHONPATH=/opt/nexus
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

# ---------- ros2-core-node ----------
FROM ros-base AS core
USER nexus
CMD ["ros2", "launch", "nav2_bringup", "navigation_launch.py", "use_sim_time:=false"]

# ---------- vision-perception-node (PyTorch + ONNX + TensorRT) ----------
FROM ros-base AS vision
COPY requirements/vision.txt /tmp/vision.txt
RUN pip3 install --no-cache-dir -r /tmp/vision.txt
COPY src/vision /opt/nexus/vision
COPY src/supply_chain /opt/nexus/supply_chain
USER nexus
CMD ["python3", "-m", "vision.vision_node"]

# ---------- agentic-rag-core ----------
FROM ros-base AS brain
COPY requirements/agents.txt /tmp/agents.txt
RUN pip3 install --no-cache-dir -r /tmp/agents.txt
COPY src/agents /opt/nexus/agents
COPY src/fleet /opt/nexus/fleet
COPY policy /opt/nexus/policy
COPY knowledge /opt/nexus/knowledge
USER nexus
CMD ["python3", "-m", "agents.agentic_brain"]

# ---------- sec-ids-guardian (needs CAP_BPF / CAP_SYS_ADMIN at runtime) ----------
FROM ros-base AS ids
RUN apt-get update && apt-get install -y --no-install-recommends bpfcc-tools python3-bpfcc \
    && rm -rf /var/lib/apt/lists/*
COPY requirements/ids.txt /tmp/ids.txt
RUN pip3 install --no-cache-dir -r /tmp/ids.txt
COPY src/security /opt/nexus/security_nodes
CMD ["python3", "-m", "security_nodes.security_ids_node"]

# ---------- hsm-emulator-node ----------
FROM ros-base AS hsm
COPY src/security /opt/nexus/security_nodes
USER nexus
CMD ["python3", "-m", "security_nodes.hsm_emulator"]

# ---------- ekf fusion node ----------
FROM ros-base AS fusion
RUN apt-get update && apt-get install -y --no-install-recommends ros-iron-nav-msgs && rm -rf /var/lib/apt/lists/*
COPY src/fusion /opt/nexus/fusion
USER nexus
CMD ["python3", "-m", "fusion.ekf_fusion"]

# ---------- dashboard ----------
FROM python:3.14-slim AS dashboard
ENV PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir httpx==0.27.0 pydantic==2.6.4 fastapi==0.110.0 "uvicorn[standard]==0.29.0" websockets==12.0
COPY src/dashboard /app
COPY src/assistant /app/assistant
COPY src/common /app/common
COPY knowledge /app/knowledge
WORKDIR /app
RUN useradd -m nexus
USER nexus
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8080/health')"
CMD ["uvicorn", "dashboard_backend:app", "--host", "0.0.0.0", "--port", "8080"]
