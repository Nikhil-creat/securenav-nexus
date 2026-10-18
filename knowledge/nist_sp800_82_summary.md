# NIST SP 800-82 (OT security) - guidance themes (original summary)

- Network segmentation: separate control traffic from supervisory and enterprise traffic; the robot control DDS domain must not be reachable from the dashboard network except through the authenticated gateway.
- Least privilege: each software component receives only the topics and resources it needs.
- Defense in depth: combine authentication, encryption, anomaly detection and physical safety interlocks.
- Fail-safe behavior: on loss of integrity or availability the system should move to a safe state (stop or controlled degradation) rather than continue unsupervised.
- Logging and monitoring: retain tamper-evident logs of commands, configuration changes and security events.
- Incident response: predefined playbooks, containment first (isolate compromised component), then recovery and lessons learned.
- Patch and vulnerability management with testing in a simulated environment before fleet rollout.
