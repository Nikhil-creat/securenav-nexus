# MITRE ATT&CK for ICS - mobile robot relevant techniques (original summary)

## T0855 Unauthorized Command Message
An adversary sends command messages such as velocity commands from a node that is not authorized to actuate. Indicators: /cmd_vel publishers other than nav2 or the mission brain, command rate spikes, commands during e-stop. Response: revoke the offending node certificate, assert e-stop, fall back to nav2-only command path.

## T0856 Spoof Reporting Message
False sensor or status data is injected to mislead the controller. Indicators: camera anomaly score high while LiDAR range disagrees, odometry jumping, GPS position inconsistent with wheel odometry. Response: lower fusion weight of the suspect sensor, rely on remaining modalities, slow the robot.

## T0814 Denial of Service
Message flooding exhausts CPU or network. Indicators: topic frequency far above nominal, dropped packets, CPU saturation, DDS discovery storms. Response: isolate the flooding publisher, rate-limit, switch to degraded safe navigation profile.

## T0830 Adversary-in-the-Middle
Traffic is intercepted or altered on the network path. Indicators: SROS2 authentication failures, unexpected participants, certificate mismatch. Response: rotate keys, enforce Enforce strategy, re-establish trust through the HSM.

## T0886 Remote Services / Rogue Node Injection
A new node joins the DDS domain and subscribes to sensitive topics. Indicators: unexpected subscriptions, unknown node names, new network sockets from robot processes. Response: revoke certificate, audit syscalls with the eBPF guardian.

## T0836 Modify Parameter
Navigation or safety parameters are altered to unsafe values. Indicators: parameter_events on speed limits or costmap inflation. Response: restore last known-good parameters and flag for human review.

## T0881 Service Stop
Critical processes are killed. Indicators: missing heartbeats from nav2, vision or brain. Response: restart container, hold position until health restored.
