# NEXUS response playbooks

## PB-01 Rogue /cmd_vel publisher
Severity critical. Actions: assert e_stop, revoke certificate of publisher, resume only after nav2 identity verified, replan mission with reduced speed.

## PB-02 Camera spoofing or replay
Severity high. Actions: reduce camera fusion weight to 0.1, raise LiDAR weight, cap speed at 0.3 m/s, request operator confirmation before resuming mission.

## PB-03 Message flood or DoS
Severity high. Actions: isolate flooding node, enable rate limits, switch to degraded navigation profile with larger safety margins.

## PB-04 GPS denial
Severity medium. Actions: switch localization to LiDAR odometry plus wheel odometry, shrink mission radius, return to last verified waypoint if drift exceeds threshold.

## PB-05 Unknown participant on DDS domain
Severity high. Actions: revoke identity, rotate permissions, audit eBPF logs for the originating process.
