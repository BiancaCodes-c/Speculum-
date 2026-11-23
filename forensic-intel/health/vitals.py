"""Live vitals.

The live vitals feed — a heart rate for the system: current
CPU, memory, disk, network, and service state, kept fresh.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional
import random


@dataclass
class Vitals:
    """A point-in-time snapshot of system health."""
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_outbound_mbps: float
    services_ok: bool = True
    timestamp: datetime = field(default_factory=datetime.utcnow)
    extra: Dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, float]:
        d = {
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "disk_percent": self.disk_percent,
            "network_outbound_mbps": self.network_outbound_mbps,
        }
        d.update(self.extra)
        return d


class VitalsMonitor:
    """Provides current vitals (real or simulated)."""

    def current(self) -> Vitals:
        """Placeholder for real sensors.

        Later this can pull from psutil, node exporters, etc.
        For now returns a mild synthetic sample.
        """
        return self.simulate(style="normal")

    def simulate(self, style: str = "normal") -> Vitals:
        """Generate realistic-looking vitals for demos and tests.

        style:
          - normal     → healthy range
          - stressed   → elevated but not critical
          - degraded   → clearly unhealthy
          - quiet      → very calm (useful for quiet-intrusion scenarios)
        """
        if style == "stressed":
            return Vitals(
                cpu_percent=random.uniform(55, 78),
                memory_percent=random.uniform(60, 82),
                disk_percent=random.uniform(50, 70),
                network_outbound_mbps=random.uniform(80, 180),
                services_ok=True,
            )
        if style == "degraded":
            return Vitals(
                cpu_percent=random.uniform(85, 98),
                memory_percent=random.uniform(88, 97),
                disk_percent=random.uniform(75, 95),
                network_outbound_mbps=random.uniform(200, 400),
                services_ok=random.random() > 0.3,
            )
        if style == "quiet":
            return Vitals(
                cpu_percent=random.uniform(4, 12),
                memory_percent=random.uniform(25, 40),
                disk_percent=random.uniform(30, 45),
                network_outbound_mbps=random.uniform(0.5, 4.0),
                services_ok=True,
            )
        # normal
        return Vitals(
            cpu_percent=random.uniform(8, 28),
            memory_percent=random.uniform(30, 55),
            disk_percent=random.uniform(35, 60),
            network_outbound_mbps=random.uniform(2, 25),
            services_ok=True,
        )


def current_vitals(style: Optional[str] = None) -> Vitals:
    """Convenience function."""
    monitor = VitalsMonitor()
    if style:
        return monitor.simulate(style)
    return monitor.current()
