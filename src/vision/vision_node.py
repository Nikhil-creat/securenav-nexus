"""SecureNav-NEXUS vision perception node.

Hybrid CNN + lightweight ViT network producing, per frame:
  * semantic segmentation logits
  * monocular depth map
  * a spoofing/anomaly score (is the camera feed being replayed/adversarially patched?)
plus a ROS 2 node that subscribes to /camera/color/image_raw (and /lidar/points for range
cross-checking), runs inference on the best available backend (TensorRT > ONNX Runtime > PyTorch)
and publishes detections on /perception/*.

Run:  python3 -m vision.vision_node            # ROS 2 node
      python3 -m vision.vision_node --export   # export .pt -> ONNX -> TensorRT engine
"""
from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from common.logging_setup import get_logger

log = get_logger("nexus.vision")

NUM_CLASSES = 12
INPUT_HW = (256, 320)  # H, W (divisible by 16)


# ------------------------------------------------------------------ model
class ConvBlock(nn.Module):
    def __init__(self, cin: int, cout: int, stride: int = 1) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv2d(cin, cout, 3, stride, 1, bias=False),
            nn.BatchNorm2d(cout),
            nn.ReLU(inplace=True),
            nn.Conv2d(cout, cout, 3, 1, 1, bias=False),
            nn.BatchNorm2d(cout),
            nn.ReLU(inplace=True),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class ViTBlock(nn.Module):
    """Pre-norm transformer encoder block operating on flattened feature maps."""

    def __init__(self, dim: int, heads: int = 4, mlp_ratio: float = 2.0) -> None:
        super().__init__()
        self.n1 = nn.LayerNorm(dim)
        self.attn = nn.MultiheadAttention(dim, heads, batch_first=True)
        self.n2 = nn.LayerNorm(dim)
        hidden = int(dim * mlp_ratio)
        self.mlp = nn.Sequential(nn.Linear(dim, hidden), nn.GELU(), nn.Linear(hidden, dim))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        h = self.n1(x)
        x = x + self.attn(h, h, h, need_weights=False)[0]
        return x + self.mlp(self.n2(x))


class NexusPerceptionNet(nn.Module):
    """CNN encoder -> ViT bottleneck -> segmentation + depth decoders + anomaly head."""

    def __init__(self, num_classes: int = NUM_CLASSES, dim: int = 128, vit_depth: int = 2) -> None:
        super().__init__()
        self.enc1 = ConvBlock(3, 32, 2)     # /2
        self.enc2 = ConvBlock(32, 64, 2)    # /4
        self.enc3 = ConvBlock(64, 96, 2)    # /8
        self.enc4 = ConvBlock(96, dim, 2)   # /16
        self.vit = nn.ModuleList(ViTBlock(dim) for _ in range(vit_depth))
        # learned positional embedding sized for INPUT_HW/16
        self.pos = nn.Parameter(torch.zeros(1, (INPUT_HW[0] // 16) * (INPUT_HW[1] // 16), dim))
        nn.init.trunc_normal_(self.pos, std=0.02)
        self.up3 = ConvBlock(dim + 96, 96)
        self.up2 = ConvBlock(96 + 64, 64)
        self.up1 = ConvBlock(64 + 32, 32)
        self.seg_head = nn.Conv2d(32, num_classes, 1)
        self.depth_head = nn.Sequential(nn.Conv2d(32, 1, 1), nn.Softplus())
        self.anomaly_head = nn.Sequential(nn.Linear(dim, 64), nn.ReLU(inplace=True), nn.Linear(64, 1), nn.Sigmoid())

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        h, w = x.shape[-2:]
        e1 = self.enc1(x)
        e2 = self.enc2(e1)
        e3 = self.enc3(e2)
        e4 = self.enc4(e3)
        b, c, fh, fw = e4.shape
        tokens = e4.flatten(2).transpose(1, 2) + self.pos[:, : fh * fw]
        for blk in self.vit:
            tokens = blk(tokens)
        anomaly = self.anomaly_head(tokens.mean(dim=1))
        f4 = tokens.transpose(1, 2).reshape(b, c, fh, fw)
        d3 = self.up3(torch.cat([F.interpolate(f4, size=e3.shape[-2:], mode="bilinear", align_corners=False), e3], 1))
        d2 = self.up2(torch.cat([F.interpolate(d3, size=e2.shape[-2:], mode="bilinear", align_corners=False), e2], 1))
        d1 = self.up1(torch.cat([F.interpolate(d2, size=e1.shape[-2:], mode="bilinear", align_corners=False), e1], 1))
        seg = F.interpolate(self.seg_head(d1), size=(h, w), mode="bilinear", align_corners=False)
        depth = F.interpolate(self.depth_head(d1), size=(h, w), mode="bilinear", align_corners=False)
        return seg, depth, anomaly


# ------------------------------------------------------------------ export
def export_onnx(model: nn.Module, path: Path) -> Path:
    model.eval()
    dummy = torch.randn(1, 3, *INPUT_HW)
    torch.onnx.export(
        model, dummy, str(path), opset_version=17, input_names=["image"],
        output_names=["seg", "depth", "anomaly"], dynamic_axes={"image": {0: "batch"}},
    )
    log.info("onnx exported", extra={"fields": {"path": str(path)}})
    return path


def build_tensorrt_engine(onnx_path: Path, engine_path: Path, precision: str = "fp16",
                          calib_images: Optional[list[np.ndarray]] = None) -> Path:
    """Build a TensorRT engine (FP16 or INT8). Requires the `tensorrt` python package (JetPack/NGC)."""
    import tensorrt as trt  # type: ignore[import-not-found]

    logger = trt.Logger(trt.Logger.WARNING)
    builder = trt.Builder(logger)
    network = builder.create_network(1 << int(trt.NetworkDefinitionCreationFlag.EXPLICIT_BATCH))
    parser = trt.OnnxParser(network, logger)
    with open(onnx_path, "rb") as fh:
        if not parser.parse(fh.read()):
            errs = "; ".join(str(parser.get_error(i)) for i in range(parser.num_errors))
            raise RuntimeError(f"ONNX parse failed: {errs}")
    config = builder.create_builder_config()
    config.set_memory_pool_limit(trt.MemoryPoolType.WORKSPACE, 1 << 30)
    if precision in ("fp16", "int8") and builder.platform_has_fast_fp16:
        config.set_flag(trt.BuilderFlag.FP16)
    if precision == "int8":
        if not builder.platform_has_fast_int8 or not calib_images:
            raise RuntimeError("INT8 requires hardware support and calibration images")
        config.set_flag(trt.BuilderFlag.INT8)
        config.int8_calibrator = _make_calibrator(trt, calib_images)
    blob = builder.build_serialized_network(network, config)
    if blob is None:
        raise RuntimeError("TensorRT engine build failed")
    engine_path.write_bytes(bytes(blob))
    log.info("tensorrt engine built", extra={"fields": {"path": str(engine_path), "precision": precision}})
    return engine_path


def _make_calibrator(trt: Any, images: list[np.ndarray]) -> Any:
    import pycuda.autoinit  # type: ignore[import-not-found]  # noqa: F401
    import pycuda.driver as cuda  # type: ignore[import-not-found]

    class Calib(trt.IInt8EntropyCalibrator2):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__()
            self.imgs = iter(images)
            self.dev = cuda.mem_alloc(images[0].nbytes)

        def get_batch_size(self) -> int:
            return 1

        def get_batch(self, names: list[str]) -> Optional[list[int]]:
            try:
                cuda.memcpy_htod(self.dev, np.ascontiguousarray(next(self.imgs)))
                return [int(self.dev)]
            except StopIteration:
                return None

        def read_calibration_cache(self) -> None:
            return None

        def write_calibration_cache(self, cache: bytes) -> None:
            return None

    return Calib()


# ------------------------------------------------------------------ inference backends
@dataclass
class InferenceResult:
    seg: np.ndarray       # (H, W) int class ids
    depth: np.ndarray     # (H, W) float meters-ish
    anomaly: float        # 0..1 spoof/anomaly score
    latency_ms: float
    backend: str


class Backend:
    name = "base"

    def infer(self, tensor: np.ndarray) -> tuple[np.ndarray, np.ndarray, float]:
        raise NotImplementedError


class TorchBackend(Backend):
    name = "torch"

    def __init__(self, weights: Optional[Path]) -> None:
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = NexusPerceptionNet().to(self.device).eval()
        if weights and weights.exists():
            self.model.load_state_dict(torch.load(weights, map_location=self.device))
        else:
            log.warning("no trained weights found - running with random init (demo mode)")

    @torch.inference_mode()
    def infer(self, tensor: np.ndarray) -> tuple[np.ndarray, np.ndarray, float]:
        t = torch.from_numpy(tensor).to(self.device)
        seg, depth, anom = self.model(t)
        return seg.argmax(1)[0].cpu().numpy(), depth[0, 0].cpu().numpy(), float(anom[0, 0])


class OnnxBackend(Backend):
    name = "onnxruntime"

    def __init__(self, onnx_path: Path) -> None:
        import onnxruntime as ort

        providers = [p for p in ("TensorrtExecutionProvider", "CUDAExecutionProvider", "CPUExecutionProvider")
                     if p in ort.get_available_providers()]
        self.sess = ort.InferenceSession(str(onnx_path), providers=providers)

    def infer(self, tensor: np.ndarray) -> tuple[np.ndarray, np.ndarray, float]:
        seg, depth, anom = self.sess.run(None, {"image": tensor})
        return seg.argmax(1)[0], depth[0, 0], float(anom[0, 0])


class TensorRTBackend(Backend):
    name = "tensorrt"

    def __init__(self, engine_path: Path) -> None:
        import pycuda.autoinit  # type: ignore[import-not-found]  # noqa: F401
        import pycuda.driver as cuda  # type: ignore[import-not-found]
        import tensorrt as trt  # type: ignore[import-not-found]

        self.cuda = cuda
        rt = trt.Runtime(trt.Logger(trt.Logger.WARNING))
        self.engine = rt.deserialize_cuda_engine(engine_path.read_bytes())
        self.ctx = self.engine.create_execution_context()
        self.stream = cuda.Stream()
        self.bufs: list[tuple[str, np.ndarray, Any]] = []
        for i in range(self.engine.num_io_tensors):
            name = self.engine.get_tensor_name(i)
            shape = tuple(self.engine.get_tensor_shape(name))
            dtype = trt.nptype(self.engine.get_tensor_dtype(name))
            host = np.zeros(shape, dtype=dtype)
            self.bufs.append((name, host, cuda.mem_alloc(host.nbytes)))

    def infer(self, tensor: np.ndarray) -> tuple[np.ndarray, np.ndarray, float]:
        for name, host, dev in self.bufs:
            self.ctx.set_tensor_address(name, int(dev))
        _, in_host, in_dev = self.bufs[0]
        np.copyto(in_host, tensor.astype(in_host.dtype))
        self.cuda.memcpy_htod_async(in_dev, in_host, self.stream)
        self.ctx.execute_async_v3(self.stream.handle)
        for _, host, dev in self.bufs[1:]:
            self.cuda.memcpy_dtoh_async(host, dev, self.stream)
        self.stream.synchronize()
        seg, depth, anom = (b[1] for b in self.bufs[1:4])
        return seg.argmax(1)[0], depth[0, 0], float(anom.reshape(-1)[0])


def select_backend(model_dir: Path, preference: str = "auto") -> Backend:
    """Pick TensorRT > ONNX > Torch, falling back gracefully on any failure. Verifies model signatures first."""
    from supply_chain.model_signer import enforce

    enforce(model_dir)  # raises when NEXUS_REQUIRE_SIGNED=1 and the artifacts are unsigned or modified
    engine, onnx_p, pt = model_dir / "nexus.engine", model_dir / "nexus.onnx", model_dir / "nexus.pt"
    order = ["tensorrt", "onnx", "torch"] if preference == "auto" else [preference, "torch"]
    for choice in order:
        try:
            if choice == "tensorrt" and engine.exists():
                return TensorRTBackend(engine)
            if choice == "onnx" and onnx_p.exists():
                return OnnxBackend(onnx_p)
            if choice == "torch":
                return TorchBackend(pt)
        except Exception as exc:  # noqa: BLE001 - backend probing must never crash the node
            log.warning("backend unavailable", extra={"fields": {"backend": choice, "error": str(exc)}})
    return TorchBackend(None)


# ------------------------------------------------------------------ preprocessing
_MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32).reshape(1, 3, 1, 1)
_STD = np.array([0.229, 0.224, 0.225], dtype=np.float32).reshape(1, 3, 1, 1)


def preprocess(rgb: np.ndarray) -> np.ndarray:
    """HxWx3 uint8 RGB -> 1x3xHxW float32 normalized at INPUT_HW."""
    import cv2

    resized = cv2.resize(rgb, (INPUT_HW[1], INPUT_HW[0]), interpolation=cv2.INTER_LINEAR)
    chw = resized.astype(np.float32).transpose(2, 0, 1)[None] / 255.0
    return np.ascontiguousarray((chw - _MEAN) / _STD)


def extract_boxes(seg: np.ndarray, depth: np.ndarray, min_area: int = 200) -> list[dict[str, Any]]:
    """Convert non-background segmentation regions into bounding boxes with median depth."""
    import cv2

    boxes: list[dict[str, Any]] = []
    for cls in np.unique(seg):
        if cls == 0:
            continue
        mask = (seg == cls).astype(np.uint8)
        n, _, stats, _ = cv2.connectedComponentsWithStats(mask)
        for i in range(1, n):
            x, y, w, h, area = stats[i]
            if area < min_area:
                continue
            region = depth[y:y + h, x:x + w][mask[y:y + h, x:x + w] > 0]
            boxes.append({"cls": int(cls), "x": int(x), "y": int(y), "w": int(w), "h": int(h),
                          "depth_m": float(np.median(region)) if region.size else -1.0})
    return boxes


def run_inference(backend: Backend, rgb: np.ndarray) -> InferenceResult:
    t0 = time.perf_counter()
    seg, depth, anom = backend.infer(preprocess(rgb))
    return InferenceResult(seg, depth, anom, (time.perf_counter() - t0) * 1e3, backend.name)


# ------------------------------------------------------------------ ROS 2 node
def spin_ros() -> None:
    import rclpy
    from rclpy.node import Node
    from rclpy.qos import qos_profile_sensor_data
    from sensor_msgs.msg import Image, PointCloud2
    from std_msgs.msg import String

    class VisionNode(Node):
        def __init__(self) -> None:
            super().__init__("vision_perception")
            self.backend = select_backend(Path(os.environ.get("NEXUS_MODEL_DIR", "/models")),
                                          os.environ.get("NEXUS_BACKEND", "auto"))
            self.anomaly_thresh = float(os.environ.get("NEXUS_SPOOF_THRESH", "0.85"))
            self.last_lidar_ts = 0.0
            self.det_pub = self.create_publisher(String, "/perception/detections", 10)
            self.anom_pub = self.create_publisher(String, "/perception/anomaly", 10)
            self.create_subscription(Image, "/camera/color/image_raw", self.on_image, qos_profile_sensor_data)
            self.create_subscription(PointCloud2, "/lidar/points", self.on_lidar, qos_profile_sensor_data)
            self.get_logger().info(f"vision node ready backend={self.backend.name}")

        def on_lidar(self, msg: PointCloud2) -> None:
            self.last_lidar_ts = time.time()

        def on_image(self, msg: Image) -> None:
            try:
                if msg.encoding not in ("rgb8", "bgr8"):
                    raise ValueError(f"unsupported encoding {msg.encoding}")
                frame = np.frombuffer(msg.data, np.uint8).reshape(msg.height, msg.width, 3)
                rgb = frame[..., ::-1] if msg.encoding == "bgr8" else frame
                res = run_inference(self.backend, np.ascontiguousarray(rgb))
                boxes = extract_boxes(res.seg, res.depth)
                self.det_pub.publish(String(data=json.dumps(
                    {"stamp": time.time(), "boxes": boxes, "latency_ms": res.latency_ms, "backend": res.backend})))
                # Cross-modal check: camera alive but LiDAR silent (or vice-versa) is itself suspicious.
                lidar_stale = (time.time() - self.last_lidar_ts) > 2.0
                if res.anomaly > self.anomaly_thresh or lidar_stale:
                    self.anom_pub.publish(String(data=json.dumps(
                        {"stamp": time.time(), "score": res.anomaly, "lidar_stale": lidar_stale,
                         "reason": "visual_spoofing" if res.anomaly > self.anomaly_thresh else "sensor_desync"})))
            except Exception as exc:  # noqa: BLE001
                self.get_logger().error(f"inference failure: {exc}")

    rclpy.init()
    node = VisionNode()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        rclpy.shutdown()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--export", action="store_true", help="export weights to ONNX and TensorRT")
    ap.add_argument("--precision", default="fp16", choices=["fp16", "int8"])
    ap.add_argument("--model-dir", default=os.environ.get("NEXUS_MODEL_DIR", "/models"))
    args = ap.parse_args()
    mdir = Path(args.model_dir)
    mdir.mkdir(parents=True, exist_ok=True)
    if args.export:
        model = NexusPerceptionNet()
        pt = mdir / "nexus.pt"
        if pt.exists():
            model.load_state_dict(torch.load(pt, map_location="cpu"))
        else:
            torch.save(model.state_dict(), pt)
        onnx_path = export_onnx(model, mdir / "nexus.onnx")
        try:
            build_tensorrt_engine(onnx_path, mdir / "nexus.engine", args.precision)
        except ImportError:
            log.warning("tensorrt not installed; ONNX only")
        return
    spin_ros()


if __name__ == "__main__":
    main()
