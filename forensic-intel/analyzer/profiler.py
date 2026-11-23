"""Profiler.

Produces the AI vs HUMAN verdict: a score, a behavioral
fingerprint, and the reasons behind the call. Never a bare label.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Sequence, Union

from .rhythm_analyzer import RhythmAnalyzer, RhythmReport


class ActorType(str, Enum):
    HUMAN = "HUMAN"
    AI = "AI"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class ActionEvent:
    """A single observed action with timing."""
    timestamp: datetime
    action_type: str
    duration_ms: Optional[float] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class ProfileVerdict:
    """Full verdict — never just a bare label."""
    actor: ActorType
    confidence: float          # 0.0 – 1.0
    score: float               # 0–100  (higher = more AI-like)
    fingerprint: dict
    reasons: List[str]
    sample_size: int
    rhythm: Optional[RhythmReport] = None


class Profiler:
    """Behavioral profiler that decides AI vs HUMAN.

    Prefers a pre-computed RhythmReport when available.
    Falls back to analyzing raw ActionEvents via RhythmAnalyzer.
    """

    MIN_EVENTS = 5
    REGULARITY_AI_THRESHOLD = 0.18
    SPEED_AI_THRESHOLD = 0.12
    BURST_RATIO_AI = 0.65

    def __init__(self, rhythm_analyzer: Optional[RhythmAnalyzer] = None):
        self.rhythm_analyzer = rhythm_analyzer or RhythmAnalyzer()

    def profile(
        self,
        source: Union[Sequence[ActionEvent], RhythmReport],
    ) -> ProfileVerdict:
        """Produce a verdict from either raw events or a RhythmReport."""
        if isinstance(source, RhythmReport):
            report = source
        else:
            events = source
            if not events or len(events) < self.MIN_EVENTS:
                return ProfileVerdict(
                    actor=ActorType.UNCERTAIN,
                    confidence=0.0,
                    score=50.0,
                    fingerprint={},
                    reasons=["Insufficient events to form a reliable profile."],
                    sample_size=len(events) if events else 0,
                )
            report = self.rhythm_analyzer.analyze(events)

        return self._verdict_from_report(report)

    def _verdict_from_report(self, report: RhythmReport) -> ProfileVerdict:
        if report.sample_size < self.MIN_EVENTS:
            return ProfileVerdict(
                actor=ActorType.UNCERTAIN,
                confidence=0.0,
                score=50.0,
                fingerprint={},
                reasons=["Insufficient events to form a reliable profile."],
                sample_size=report.sample_size,
                rhythm=report,
            )

        score = 0.0
        reasons: List[str] = []

        # 1. Timing regularity (strongest signal)
        cv = report.inter_arrival_cv
        if cv is not None:
            if cv < self.REGULARITY_AI_THRESHOLD:
                score += 35.0
                reasons.append(
                    f"Extremely regular inter-arrival times (CV={cv:.3f}) — machine-like cadence."
                )
            elif cv < 0.35:
                score += 18.0
                reasons.append(f"Moderately regular timing (CV={cv:.3f}).")
            else:
                reasons.append(f"Irregular timing (CV={cv:.3f}) — more human-like.")

        # 2. Action duration consistency
        dcv = report.duration_cv
        if dcv is not None:
            if dcv < self.SPEED_AI_THRESHOLD:
                score += 25.0
                reasons.append(
                    f"Near-constant action durations (CV={dcv:.3f}) — scripted or automated."
                )
            elif dcv < 0.30:
                score += 12.0
                reasons.append(f"Low variance in action duration (CV={dcv:.3f}).")

        # 3. Burst pattern
        if report.burst_score > self.BURST_RATIO_AI:
            score += 15.0
            reasons.append(
                f"High burst concentration ({report.burst_score:.0%} of activity in short windows)."
            )

        # 4. Correction / backtrack behavior
        if report.correction_rate < 0.05 and report.sample_size > 12:
            score += 10.0
            reasons.append("Very low self-correction / backtrack rate.")
        elif report.correction_rate > 0.18:
            reasons.append(
                f"Noticeable correction rate ({report.correction_rate:.0%}) — human signal."
            )

        # 5. Time-of-day spread
        if report.hour_spread <= 3:
            score += 8.0
            reasons.append(f"Activity tightly clustered in only {report.hour_spread} hour(s).")

        score = max(0.0, min(100.0, score))

        # Map score → verdict
        if score >= 70:
            actor = ActorType.AI
            confidence = min(0.95, 0.55 + (score - 70) / 60)
        elif score <= 35:
            actor = ActorType.HUMAN
            confidence = min(0.95, 0.55 + (35 - score) / 60)
        else:
            actor = ActorType.UNCERTAIN
            confidence = max(0.2, 0.45 - abs(score - 50) / 100)

        fingerprint = {
            "inter_arrival_cv": round(cv, 4) if cv is not None else None,
            "duration_cv": round(dcv, 4) if dcv is not None else None,
            "burst_score": round(report.burst_score, 3),
            "correction_rate": round(report.correction_rate, 3),
            "hour_spread": report.hour_spread,
            "working_hours_ratio": round(report.working_hours_ratio, 3),
            "pause_count": report.pause_count,
            "event_count": report.sample_size,
        }

        # Prefer the rich notes from the rhythm analyzer, then fall back
        if report.notes:
            # Keep the strongest reasons we just generated + any extra notes
            combined = reasons + [n for n in report.notes if n not in reasons]
            reasons = combined[:6]  # keep it readable

        if not reasons:
            reasons.append("No strong AI or human signals detected.")

        return ProfileVerdict(
            actor=actor,
            confidence=round(confidence, 3),
            score=round(score, 1),
            fingerprint=fingerprint,
            reasons=reasons,
            sample_size=report.sample_size,
            rhythm=report,
        )


def profile_actor(
    source: Union[Sequence[ActionEvent], RhythmReport],
) -> ProfileVerdict:
    """Convenience function — create a Profiler and run it."""
    return Profiler().profile(source)
