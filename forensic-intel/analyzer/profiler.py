"""Profiler.

Produces the AI vs HUMAN verdict: a score, a behavioral
fingerprint, and the reasons behind the call. Never a bare label.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Sequence
import statistics


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


class Profiler:
    """Behavioral profiler that decides AI vs HUMAN."""

    # Thresholds (tunable)
    MIN_EVENTS = 5
    REGULARITY_AI_THRESHOLD = 0.18      # coefficient of variation below this → highly regular
    SPEED_AI_THRESHOLD = 0.12           # very low duration variance
    BURST_RATIO_AI = 0.65               # high proportion of activity in short windows

    def profile(self, events: Sequence[ActionEvent]) -> ProfileVerdict:
        if not events or len(events) < self.MIN_EVENTS:
            return ProfileVerdict(
                actor=ActorType.UNCERTAIN,
                confidence=0.0,
                score=50.0,
                fingerprint={},
                reasons=["Insufficient events to form a reliable profile."],
                sample_size=len(events) if events else 0,
            )

        # Sort by time just in case
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        inter_arrival_cv = self._inter_arrival_regularity(sorted_events)
        duration_cv = self._duration_regularity(sorted_events)
        burst_score = self._burstiness(sorted_events)
        correction_rate = self._correction_rate(sorted_events)
        hour_spread = self._hour_spread(sorted_events)

        # Weighted AI-likeness score (0–100)
        score = 0.0
        reasons: List[str] = []

        # 1. Timing regularity (strongest signal)
        if inter_arrival_cv is not None:
            if inter_arrival_cv < self.REGULARITY_AI_THRESHOLD:
                contribution = 35.0
                score += contribution
                reasons.append(
                    f"Extremely regular inter-arrival times (CV={inter_arrival_cv:.3f}) — "
                    f"machine-like cadence."
                )
            elif inter_arrival_cv < 0.35:
                contribution = 18.0
                score += contribution
                reasons.append(
                    f"Moderately regular timing (CV={inter_arrival_cv:.3f})."
                )
            else:
                reasons.append(
                    f"Irregular timing (CV={inter_arrival_cv:.3f}) — more human-like."
                )

        # 2. Action duration consistency
        if duration_cv is not None:
            if duration_cv < self.SPEED_AI_THRESHOLD:
                contribution = 25.0
                score += contribution
                reasons.append(
                    f"Near-constant action durations (CV={duration_cv:.3f}) — "
                    f"scripted or automated."
                )
            elif duration_cv < 0.30:
                contribution = 12.0
                score += contribution
                reasons.append(f"Low variance in action duration (CV={duration_cv:.3f}).")

        # 3. Burst pattern
        if burst_score > self.BURST_RATIO_AI:
            contribution = 15.0
            score += contribution
            reasons.append(
                f"High burst concentration ({burst_score:.0%} of activity in short windows)."
            )

        # 4. Correction / backtrack behavior (humans do this more)
        if correction_rate < 0.05 and len(sorted_events) > 12:
            contribution = 10.0
            score += contribution
            reasons.append("Very low self-correction / backtrack rate.")
        elif correction_rate > 0.18:
            reasons.append(f"Noticeable correction rate ({correction_rate:.0%}) — human signal.")

        # 5. Time-of-day spread
        if hour_spread is not None and hour_spread <= 3:
            contribution = 8.0
            score += contribution
            reasons.append(f"Activity tightly clustered in only {hour_spread} hour(s).")

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
            confidence = 0.45 - abs(score - 50) / 100

        fingerprint = {
            "inter_arrival_cv": round(inter_arrival_cv, 4) if inter_arrival_cv is not None else None,
            "duration_cv": round(duration_cv, 4) if duration_cv is not None else None,
            "burst_score": round(burst_score, 3),
            "correction_rate": round(correction_rate, 3),
            "hour_spread": hour_spread,
            "event_count": len(sorted_events),
        }

        if not reasons:
            reasons.append("No strong AI or human signals detected.")

        return ProfileVerdict(
            actor=actor,
            confidence=round(confidence, 3),
            score=round(score, 1),
            fingerprint=fingerprint,
            reasons=reasons,
            sample_size=len(sorted_events),
        )

    # ------------------------------------------------------------------
    # Signal extractors
    # ------------------------------------------------------------------

    def _inter_arrival_regularity(self, events: Sequence[ActionEvent]) -> Optional[float]:
        if len(events) < 3:
            return None
        deltas = []
        for i in range(1, len(events)):
            delta = (events[i].timestamp - events[i - 1].timestamp).total_seconds()
            if delta > 0:
                deltas.append(delta)
        if len(deltas) < 2:
            return None
        mean = statistics.mean(deltas)
        if mean == 0:
            return 0.0
        return statistics.stdev(deltas) / mean  # coefficient of variation

    def _duration_regularity(self, events: Sequence[ActionEvent]) -> Optional[float]:
        durations = [e.duration_ms for e in events if e.duration_ms is not None and e.duration_ms > 0]
        if len(durations) < 3:
            return None
        mean = statistics.mean(durations)
        if mean == 0:
            return 0.0
        return statistics.stdev(durations) / mean

    def _burstiness(self, events: Sequence[ActionEvent]) -> float:
        """Fraction of events that fall inside the densest 20% time window."""
        if len(events) < 6:
            return 0.0
        timestamps = [e.timestamp.timestamp() for e in events]
        total_span = max(timestamps) - min(timestamps)
        if total_span <= 0:
            return 1.0

        window = total_span * 0.20
        max_in_window = 0
        for t in timestamps:
            count = sum(1 for other in timestamps if t <= other <= t + window)
            if count > max_in_window:
                max_in_window = count
        return max_in_window / len(events)

    def _correction_rate(self, events: Sequence[ActionEvent]) -> float:
        """Heuristic: actions that look like corrections or backtracks."""
        if not events:
            return 0.0
        correction_keywords = {"undo", "back", "retry", "correct", "fix", "revert", "cancel"}
        count = 0
        for e in events:
            at = e.action_type.lower()
            if any(k in at for k in correction_keywords):
                count += 1
            # also check metadata
            if e.metadata.get("is_correction") or e.metadata.get("is_backtrack"):
                count += 1
        return count / len(events)

    def _hour_spread(self, events: Sequence[ActionEvent]) -> Optional[int]:
        hours = {e.timestamp.hour for e in events}
        return len(hours)


def profile_actor(events: Sequence[ActionEvent]) -> ProfileVerdict:
    """Convenience function — create a Profiler and run it."""
    return Profiler().profile(events)
