"""Health + threat correlation.

Connects the Health Score and the Threat Score to tell apart a
glitch, an attack, and a quiet intrusion — the same symptom can
be any of the three.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from .health_score import HealthVerdict
from analyzer.threat_score import ThreatVerdict, ThreatLevel  # type: ignore


class Judgment(str, Enum):
    HEALTHY = "HEALTHY"                 # both scores good
    GLITCH = "GLITCH"                   # health bad, threat low → probably not an attack
    ATTACK = "ATTACK"                   # health bad + threat high → active attack
    QUIET_INTRUSION = "QUIET_INTRUSION" # health still good + threat high → stealthy actor
    DEGRADED = "DEGRADED"               # health soft, threat moderate
    UNKNOWN = "UNKNOWN"


@dataclass
class CorrelationResult:
    """Final judgment that joins the two scores."""
    judgment: Judgment
    confidence: float
    summary: str
    reasons: List[str] = field(default_factory=list)
    health_score: float = 0.0
    threat_score: float = 0.0
    health_status: str = ""
    threat_level: str = ""


class Correlator:
    """Decide what the combination of Health + Threat actually means."""

    # Thresholds (aligned with config/thresholds.json philosophy)
    HEALTH_GOOD = 80
    HEALTH_OK = 65
    HEALTH_BAD = 40

    THREAT_LOW = 35
    THREAT_ELEVATED = 50
    THREAT_HIGH = 70

    def correlate(
        self,
        health: HealthVerdict,
        threat: ThreatVerdict,
    ) -> CorrelationResult:
        h = health.score
        t = threat.score

        reasons: List[str] = []
        reasons.extend(health.reasons[:2])
        reasons.extend(threat.reasons[:2])

        # --- Decision table ---
        if h >= self.HEALTH_GOOD and t <= self.THREAT_LOW:
            judgment = Judgment.HEALTHY
            confidence = 0.85
            summary = "System is healthy and threat level is low."

        elif h >= self.HEALTH_GOOD and t >= self.THREAT_HIGH:
            judgment = Judgment.QUIET_INTRUSION
            confidence = 0.80
            summary = (
                "Health remains good while threat is high — "
                "possible quiet / stealthy intrusion."
            )
            reasons.insert(0, "Classic quiet-intrusion signature: high threat, healthy vitals.")

        elif h < self.HEALTH_BAD and t >= self.THREAT_HIGH:
            judgment = Judgment.ATTACK
            confidence = 0.90
            summary = "Health is critical and threat is high — active attack likely."
            reasons.insert(0, "Both scores point to an active attack.")

        elif h < self.HEALTH_BAD and t <= self.THREAT_LOW:
            judgment = Judgment.GLITCH
            confidence = 0.75
            summary = (
                "Health is poor but threat is low — "
                "more likely a glitch, resource exhaustion, or misconfiguration."
            )
            reasons.insert(0, "Poor health without corresponding threat signal.")

        elif h < self.HEALTH_OK and t >= self.THREAT_ELEVATED:
            judgment = Judgment.ATTACK
            confidence = 0.70
            summary = "Health degraded and threat elevated — treat as potential attack."

        elif h < self.HEALTH_OK:
            judgment = Judgment.DEGRADED
            confidence = 0.60
            summary = "Health is degraded; threat is not yet decisive."

        else:
            judgment = Judgment.UNKNOWN
            confidence = 0.45
            summary = "Signals are mixed; more data needed for a firm judgment."

        return CorrelationResult(
            judgment=judgment,
            confidence=round(confidence, 3),
            summary=summary,
            reasons=reasons[:6],
            health_score=h,
            threat_score=t,
            health_status=health.status,
            threat_level=threat.level.value,
        )


def correlate(health: HealthVerdict, threat: ThreatVerdict) -> CorrelationResult:
    """Convenience function."""
    return Correlator().correlate(health, threat)
