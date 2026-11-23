"""Threat score.

Calculates the 0-100 Threat Score from entry, data flow, and
rhythm / profiler findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Union

from .profiler import ActorType, ProfileVerdict
from .rhythm_analyzer import RhythmReport


class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class EntrySignal:
    """Lightweight stand-in until EntryAnalyzer is fully built.

    severity: 0–100  (how serious the entry vector looks)
    vector:   short label (phishing, stolen_key, brute_force, …)
    evidence: free-form reasons
    """
    severity: float = 0.0
    vector: str = "unknown"
    evidence: List[str] = field(default_factory=list)


@dataclass
class DataFlowSignal:
    """Lightweight stand-in until DataFlowAnalyzer is fully built.

    volume_score:   0–100  (how much / how sensitive the data looks)
    speed_score:    0–100  (how fast it moved)
    method:         short label (exfil, lateral, encrypted_channel, …)
    evidence:       free-form reasons
    """
    volume_score: float = 0.0
    speed_score: float = 0.0
    method: str = "unknown"
    evidence: List[str] = field(default_factory=list)


@dataclass
class ThreatVerdict:
    """Full threat assessment — never just a bare number."""
    score: float                    # 0–100
    level: ThreatLevel
    confidence: float               # 0–1
    reasons: List[str]
    components: dict                # breakdown of what contributed
    actor: Optional[ActorType] = None
    entry: Optional[EntrySignal] = None
    data_flow: Optional[DataFlowSignal] = None
    rhythm: Optional[RhythmReport] = None


class ThreatScorer:
    """Combines available signals into a single Threat Score."""

    # Weights (must sum roughly to 1.0)
    W_PROFILER = 0.40       # AI vs human is a strong signal early on
    W_ENTRY = 0.30
    W_DATA_FLOW = 0.30

    def score(
        self,
        profile: Optional[ProfileVerdict] = None,
        entry: Optional[EntrySignal] = None,
        data_flow: Optional[DataFlowSignal] = None,
        rhythm: Optional[RhythmReport] = None,
    ) -> ThreatVerdict:
        """Produce a ThreatVerdict from whatever signals are available."""

        components = {}
        reasons: List[str] = []
        weighted_sum = 0.0
        weight_total = 0.0

        # ----- Profiler / actor signal -----
        if profile is not None:
            actor_score = self._actor_to_threat(profile)
            components["profiler"] = round(actor_score, 1)
            weighted_sum += actor_score * self.W_PROFILER
            weight_total += self.W_PROFILER

            if profile.actor == ActorType.AI:
                reasons.append(
                    f"Actor profile strongly AI-like (score {profile.score}, "
                    f"confidence {profile.confidence:.2f})."
                )
            elif profile.actor == ActorType.HUMAN:
                reasons.append(
                    f"Actor profile looks human (score {profile.score})."
                )
            else:
                reasons.append("Actor profile inconclusive.")

            # surface top profiler reasons
            for r in profile.reasons[:2]:
                if r not in reasons:
                    reasons.append(r)

        # ----- Entry signal -----
        if entry is not None:
            components["entry"] = round(entry.severity, 1)
            weighted_sum += entry.severity * self.W_ENTRY
            weight_total += self.W_ENTRY

            reasons.append(
                f"Entry vector '{entry.vector}' rated severity {entry.severity:.0f}."
            )
            reasons.extend(entry.evidence[:2])

        # ----- Data-flow signal -----
        if data_flow is not None:
            flow_score = (data_flow.volume_score * 0.6) + (data_flow.speed_score * 0.4)
            components["data_flow"] = round(flow_score, 1)
            weighted_sum += flow_score * self.W_DATA_FLOW
            weight_total += self.W_DATA_FLOW

            reasons.append(
                f"Data movement via '{data_flow.method}' "
                f"(volume {data_flow.volume_score:.0f}, speed {data_flow.speed_score:.0f})."
            )
            reasons.extend(data_flow.evidence[:2])

        # Normalize if some signals are missing
        if weight_total > 0:
            final_score = weighted_sum / weight_total
        else:
            final_score = 15.0  # very low baseline when nothing is known
            reasons.append("No strong signals available — defaulting to low threat.")

        final_score = max(0.0, min(100.0, final_score))

        level = self._score_to_level(final_score)
        confidence = self._estimate_confidence(profile, entry, data_flow)

        # Keep reasons readable
        unique_reasons = []
        for r in reasons:
            if r and r not in unique_reasons:
                unique_reasons.append(r)

        return ThreatVerdict(
            score=round(final_score, 1),
            level=level,
            confidence=round(confidence, 3),
            reasons=unique_reasons[:7],
            components=components,
            actor=profile.actor if profile else None,
            entry=entry,
            data_flow=data_flow,
            rhythm=rhythm or (profile.rhythm if profile else None),
        )

    def _actor_to_threat(self, profile: ProfileVerdict) -> float:
        """Map profiler score into a threat contribution.

        AI-like behavior is treated as higher threat in this context
        because Speculum is focused on detecting automated / AI-driven
        intrusion activity.
        """
        if profile.actor == ActorType.AI:
            # High AI score → high threat contribution
            return min(100.0, 55.0 + profile.score * 0.45)
        if profile.actor == ActorType.HUMAN:
            # Human can still be dangerous, but lower base
            return max(10.0, profile.score * 0.35)
        # Uncertain
        return 40.0 + (profile.score - 50) * 0.2

    def _score_to_level(self, score: float) -> ThreatLevel:
        if score >= 80:
            return ThreatLevel.CRITICAL
        if score >= 60:
            return ThreatLevel.HIGH
        if score >= 35:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW

    def _estimate_confidence(
        self,
        profile: Optional[ProfileVerdict],
        entry: Optional[EntrySignal],
        data_flow: Optional[DataFlowSignal],
    ) -> float:
        signals = 0
        conf = 0.0
        if profile is not None:
            signals += 1
            conf += profile.confidence
        if entry is not None:
            signals += 1
            conf += min(1.0, entry.severity / 100 + 0.3)
        if data_flow is not None:
            signals += 1
            conf += min(1.0, (data_flow.volume_score + data_flow.speed_score) / 200 + 0.25)

        if signals == 0:
            return 0.15
        return min(0.95, conf / signals)


def calculate_threat_score(
    profile: Optional[ProfileVerdict] = None,
    entry: Optional[EntrySignal] = None,
    data_flow: Optional[DataFlowSignal] = None,
    rhythm: Optional[RhythmReport] = None,
) -> ThreatVerdict:
    """Convenience function."""
    return ThreatScorer().score(profile=profile, entry=entry, data_flow=data_flow, rhythm=rhythm)
