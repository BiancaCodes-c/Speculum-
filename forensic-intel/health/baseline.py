"""Health baseline.

Learns what 'normal' is for THIS system — its own rhythms,
peaks, and quiet hours — so anomalies are measured against
reality, not averages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence
import json
from pathlib import Path

from .vitals import Vitals


@dataclass
class MetricBaseline:
    typical: float
    peak: float
    samples: int = 0


@dataclass
class SystemBaseline:
    """Learned normal for one system."""
    metrics: Dict[str, MetricBaseline] = field(default_factory=dict)

    def get(self, name: str) -> Optional[MetricBaseline]:
        return self.metrics.get(name)


class Baseline:
    """Learns and queries the system's normal operating envelope."""

    DEFAULT_METRICS = [
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "network_outbound_mbps",
    ]

    def __init__(self, path: Optional[Path | str] = None):
        self.path = Path(path) if path else None
        self.baseline = SystemBaseline()
        if self.path and self.path.exists():
            self._load()

    def learn(self, samples: Sequence[Vitals]) -> SystemBaseline:
        """Update the baseline from a sequence of vitals snapshots."""
        if not samples:
            return self.baseline

        values: Dict[str, List[float]] = {m: [] for m in self.DEFAULT_METRICS}

        for v in samples:
            d = v.as_dict()
            for m in self.DEFAULT_METRICS:
                if m in d:
                    values[m].append(float(d[m]))

        for name, nums in values.items():
            if not nums:
                continue
            nums_sorted = sorted(nums)
            typical = nums_sorted[len(nums_sorted) // 2]  # median
            # peak = 90th percentile-ish
            peak_idx = int(len(nums_sorted) * 0.9)
            peak = nums_sorted[min(peak_idx, len(nums_sorted) - 1)]
            self.baseline.metrics[name] = MetricBaseline(
                typical=round(typical, 2),
                peak=round(peak, 2),
                samples=len(nums),
            )

        if self.path:
            self._save()
        return self.baseline

    def is_anomalous(self, vitals: Vitals, tolerance: float = 1.35) -> Dict[str, bool]:
        """Return which metrics are outside the learned envelope.

        A metric is anomalous if it exceeds peak * tolerance.
        """
        result = {}
        current = vitals.as_dict()
        for name, mb in self.baseline.metrics.items():
            if name not in current:
                continue
            limit = mb.peak * tolerance
            result[name] = current[name] > limit
        return result

    def deviation_ratio(self, vitals: Vitals) -> Dict[str, float]:
        """How many times the typical value each metric currently is."""
        ratios = {}
        current = vitals.as_dict()
        for name, mb in self.baseline.metrics.items():
            if name not in current or mb.typical <= 0:
                continue
            ratios[name] = round(current[name] / mb.typical, 2)
        return ratios

    def _save(self) -> None:
        if not self.path:
            return
        data = {
            name: {
                "typical": mb.typical,
                "peak": mb.peak,
                "samples": mb.samples,
            }
            for name, mb in self.baseline.metrics.items()
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        raw = json.loads(self.path.read_text())
        for name, vals in raw.items():
            if name.startswith("_"):
                continue
            self.baseline.metrics[name] = MetricBaseline(
                typical=float(vals.get("typical") or 0),
                peak=float(vals.get("peak") or 0),
                samples=int(vals.get("samples") or 0),
            )


def learn_baseline(samples: Sequence[Vitals], path: Optional[Path | str] = None) -> SystemBaseline:
    """Convenience function."""
    b = Baseline(path)
    return b.learn(samples)


def is_anomalous(vitals: Vitals, baseline: Baseline, tolerance: float = 1.35) -> Dict[str, bool]:
    """Convenience function."""
    return baseline.is_anomalous(vitals, tolerance)
