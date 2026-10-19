# Open Policy Agent policy mirroring src/common/policy_engine.py and security/permissions.xml
# opa eval -d policy/nexus.rego -i input.json "data.nexus.allow_mission"
package nexus

import rego.v1

default allow_mission := false
default allow_publish := false

# --- mission policy ---------------------------------------------------------
allow_mission if {
	count(violations) == 0
}

violations contains msg if {
	some i
	wp := input.mission.waypoints[i]
	not in_arena(wp)
	msg := sprintf("outside_geofence:wp%d", [i])
}

violations contains "too_many_waypoints" if count(input.mission.waypoints) > 50

violations contains "speed_exceeds_limit" if input.mission.speed > 1.0

in_arena(wp) if {
	wp.x >= 0
	wp.x <= 30
	wp.y >= 0
	wp.y <= 18
}

# --- topic least-privilege (who may publish what) ----------------------------
publishers := {
	"/cmd_vel": {"nav2", "brain"},
	"/sys/e_stop": {"ids"},
	"/security/cert_revocations": {"hsm"},
	"/mission/waypoints": {"brain"},
}

allow_publish if {
	allowed := publishers[input.topic]
	allowed[input.enclave]
}
