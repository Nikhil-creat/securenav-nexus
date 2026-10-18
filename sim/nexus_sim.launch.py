"""Gazebo Harmonic bridge launch: differential-drive robot world + ros_gz bridges for NEXUS topics.

ros2 launch sim/nexus_sim.launch.py world:=warehouse.sdf drive:=diff   (drive: diff | ackermann)
Isaac Sim: enable the ROS2 bridge extension and publish the same topic names; no code change required.
"""
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, ExecuteProcess
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description() -> LaunchDescription:
    bridges = [
        "/cmd_vel@geometry_msgs/msg/Twist]gz.msgs.Twist",
        "/odom@nav_msgs/msg/Odometry[gz.msgs.Odometry",
        "/scan@sensor_msgs/msg/LaserScan[gz.msgs.LaserScan",
        "/camera/color/image_raw@sensor_msgs/msg/Image[gz.msgs.Image",
        "/camera/depth/image_raw@sensor_msgs/msg/Image[gz.msgs.Image",
        "/lidar/points@sensor_msgs/msg/PointCloud2[gz.msgs.PointCloudPacked",
        "/clock@rosgraph_msgs/msg/Clock[gz.msgs.Clock",
    ]
    return LaunchDescription([
        DeclareLaunchArgument("world", default_value="empty.sdf"),
        DeclareLaunchArgument("drive", default_value="diff", description="diff | ackermann"),
        ExecuteProcess(cmd=["gz", "sim", "-r", LaunchConfiguration("world")], output="screen"),
        Node(package="ros_gz_bridge", executable="parameter_bridge", arguments=bridges, output="screen"),
    ])
