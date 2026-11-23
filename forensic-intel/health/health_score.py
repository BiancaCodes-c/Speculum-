"""Health score.

Calculates the 0-100 Health Score from current vitals measured
against the learned baseline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .vitals import Vitals
from .baseline import Baseline


@dataclass
class HealthVerdict:
    """Full health assessment."""
    score: float                          # 0–100 (higher = healthier)
    status: str                           # healthy / elevated / degraded / critical
    reasons: List[str] = field(default_factory=list)
    deviations: Dict[str, float] = field(default_factory=dict)
    anomalous_metrics: List[str] = field(default_factory=list)
    vitals: Optional[Vitals] = None


class HealthScorer:
    """Turn vitals + baseline into a 0–100 Health Score."""

    def score(
        self,
        vitals: Vitals,
        baseline: Optional[Baseline] = None,
    ) -> HealthVerdict:
        reasons: List[str] = []
        deviations: Dict[str, float] = {}
        anomalous: List[str] = []

        # Start from a perfect score and subtract
        score = 100.0

        if baseline and baseline.baseline.metrics:
            deviations = baseline.deviation_ratio(vitals)
            anomalous_flags = baseline.is_anomalous(vitals)

            for metric, ratio in deviations.items():
                if ratio > 2.5:
                    penalty = min(30.0, (ratio - 1.0) * 12)
                    score -= penalty
                    anomalous.append(metric)
                    reasons.append(f"{metric} is {ratio:.1f}× typical (heavy load).")
                elif ratio > 1.6:
                    penalty = min(18.0, (ratio - 1.0) * 8)
                    score -= penalty
                    anomalous.append(metric)
                    reasons.append(f"{metric} is {ratio:.1f}× typical.")
                elif ratio > 1.25:
                    score -= 5.0
                    reasons.append(f"{metric} mildly elevated ({ratio:.1f}×).")

            for metric, is_bad in anomalous_flags.items():
                if is_bad and metric not in anomalous:
                    anomalous.append(metric)
                    score -= 12.0
                    reasons.append(f"{metric} exceeded learned peak envelope.")
        else:
            # No baseline yet — use absolute heuristics
            if vitals.cpu_percent > 90:
                score -= 25
                reasons.append(f"CPU very high ({vitals.cpu_percent:.0f}%).")
            elif vitals.cpu_percent > 70:
                score -= 12
                reasons.append(f"CPU elevated ({vitals.cpu_percent:.0f}%).")

            if vitals.memory_percent > 92:
                score -= 25
                reasons.append(f"Memory critically high ({vitals.memory_percent:.0f}%).")
            elif vitals.memory_percent > 75:
                score -= 10
                reasons.append(f"Memory elevated ({vitals.memory_percent:.0f}%).")

            if vitals.disk_percent > 90:
                score -= 15
                reasons.append(f"Disk nearly full ({vitals.disk_percent:.0f}%).")

            if vitals.network_outbound_mbps > 250:
                score -= 18
                reasons.append(f"Very high outbound traffic ({vitals.network_outbound_mbps:.0f} Mbps).")

        if not vitals.services_ok:
            score -= 20
            reasons.append("One or more critical services are down.")

        score = max(0.0, min(100.0, score))

        if score >= 85:
            status = "healthy"
        elif score >= 65:
            status = "elevated"
        elif score >= 40:
            status = "degraded"
        else:
            status = "critical"

        if not reasons:
            reasons.append("Vitals within expected range.")

        return HealthVerdict(
            score=round(score, 1),
            status=status,
            reasons=reasons,
            deviations=deviations,
            anomalous_metrics=anomalous,
            vitals=vitals,
        )


def calculate_health_score(
    vitals: Vitals,
    baseline: Optional[Baseline] = None,
) -> HealthVerdict:
    """Convenience function."""
    return HealthScorer().score(vitals, baseline)
