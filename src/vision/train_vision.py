"""Train NexusPerceptionNet on procedurally generated scenes (works offline, no dataset download).

Each scene has coloured ellipse "obstacles" with class labels, a ground-plane depth ramp with per-object depth,
and with 40% probability an adversarial noise patch / replay-style corruption labelled anomaly=1 so the
spoof-detection head learns something real. Swap SyntheticScenes for your own dataset for production use.

    python3 -m vision.train_vision --epochs 5 --out /models --export
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset

from common.logging_setup import get_logger
from vision.vision_node import INPUT_HW, NUM_CLASSES, NexusPerceptionNet, export_onnx

log = get_logger("nexus.train")
_MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32).reshape(3, 1, 1)
_STD = np.array([0.229, 0.224, 0.225], dtype=np.float32).reshape(3, 1, 1)


class SyntheticScenes(Dataset):  # type: ignore[type-arg]
    def __init__(self, n: int, seed: int = 0) -> None:
        self.n, self.seed = n, seed

    def __len__(self) -> int:
        return self.n

    def __getitem__(self, i: int) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        rng = np.random.default_rng(self.seed + i)
        h, w = INPUT_HW
        img = rng.uniform(0.15, 0.45, (3, h, w)).astype(np.float32)
        seg = np.zeros((h, w), dtype=np.int64)
        depth = np.repeat((10.0 - np.linspace(0.0, 6.0, h, dtype=np.float32))[:, None], w, axis=1)
        yy, xx = np.ogrid[:h, :w]
        for _ in range(int(rng.integers(1, 4))):
            cls = int(rng.integers(1, NUM_CLASSES))
            cx, cy = rng.uniform(0.15 * w, 0.85 * w), rng.uniform(0.3 * h, 0.9 * h)
            rx, ry = rng.uniform(12, 45), rng.uniform(12, 40)
            m = ((xx - cx) / rx) ** 2 + ((yy - cy) / ry) ** 2 <= 1
            img[:, m] = (0.4 + 0.5 * np.array([(cls * 37 % 10) / 10, (cls * 53 % 10) / 10, (cls * 71 % 10) / 10], dtype=np.float32))[:, None]
            seg[m] = cls
            depth[m] = rng.uniform(1.0, 6.0)
        anomaly = float(rng.random() < 0.4)
        if anomaly:  # adversarial patch or sensor-replay corruption
            px, py = int(rng.integers(0, w - 64)), int(rng.integers(0, h - 64))
            img[:, py:py + 64, px:px + 64] = rng.uniform(0.0, 1.0, (3, 64, 64)).astype(np.float32)
            img += rng.normal(0, 0.05, img.shape).astype(np.float32)
        img = np.clip(img, 0.0, 1.0)
        img = (img - _MEAN) / _STD
        return torch.from_numpy(img), torch.from_numpy(seg), torch.from_numpy(depth), torch.tensor([anomaly], dtype=torch.float32)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--samples", type=int, default=512)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-3)
    ap.add_argument("--out", default=os.environ.get("NEXUS_MODEL_DIR", "/models"))
    ap.add_argument("--export", action="store_true")
    a = ap.parse_args()
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = NexusPerceptionNet().to(dev)
    opt = torch.optim.AdamW(model.parameters(), lr=a.lr, weight_decay=1e-4)
    loader = DataLoader(SyntheticScenes(a.samples), batch_size=a.batch, shuffle=True, num_workers=0)
    for ep in range(a.epochs):
        model.train()
        tot = 0.0
        for img, seg, depth, anom in loader:
            img, seg, depth, anom = img.to(dev), seg.to(dev), depth.to(dev), anom.to(dev)
            p_seg, p_depth, p_anom = model(img)
            loss = F.cross_entropy(p_seg, seg) + 0.05 * F.l1_loss(p_depth[:, 0], depth) + F.binary_cross_entropy(p_anom, anom)
            opt.zero_grad()
            loss.backward()
            opt.step()
            tot += float(loss) * img.size(0)
        log.info("epoch done", extra={"fields": {"epoch": ep + 1, "loss": round(tot / len(loader.dataset), 4)}})  # type: ignore[arg-type]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), out / "nexus.pt")
    if a.export:
        export_onnx(model.cpu(), out / "nexus.onnx")
    log.info("saved", extra={"fields": {"path": str(out / "nexus.pt")}})


if __name__ == "__main__":
    main()
