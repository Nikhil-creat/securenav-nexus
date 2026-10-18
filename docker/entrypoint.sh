#!/usr/bin/env bash
# Sources ROS 2 and turns on SROS2 enforcement when a keystore + enclave are provided.
set -eo pipefail
# shellcheck disable=SC1091
source /opt/ros/iron/setup.bash
if [[ -n "${NEXUS_ENCLAVE:-}" && -d "${ROS_SECURITY_KEYSTORE:-}" ]]; then
  export ROS_SECURITY_ENABLE=true
  export ROS_SECURITY_STRATEGY=Enforce
  export ROS_SECURITY_ENCLAVE_OVERRIDE="${NEXUS_ENCLAVE}"
fi
exec "$@"
