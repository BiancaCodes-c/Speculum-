"""Rhythm analyzer.

Reads the timing of the actor: pauses, backtracks, working
hours, bursts. Human rhythm is uneven; AI speed is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time
from typing import List, Optional, Sequence
import statistics



@dataclass
class ActionEvent:
    """A single observed action with timing."""
    timestamp: datetime
    action_type: str
    duration_ms: Optional[float] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class RhythmReport:
    """Structured timing analysis of an actor's behavior."""
    inter_arrival_cv: Optional[float] = None      # coefficient of variation of gaps
    mean_gap_seconds: Optional[float] = None
    median_gap_seconds: Optional[float] = None
    duration_cv: Optional[float] = None
    mean_duration_ms: Optional[float] = None
    burst_score: float = 0.0                      # 0–1, higher = more bursty
    longest_pause_seconds: Optional[float] = None
    pause_count: int = 0                          # gaps > threshold
    active_hours: List[int] = field(default_factory=list)
    hour_spread: int = 0
    working_hours_ratio: float = 0.0              # fraction of events in 09–18
    correction_rate: float = 0.0
    sample_size: int = 0
    notes: List[str] = field(default_factory=list)


class RhythmAnalyzer:
    """Extracts rhythm / timing features from a sequence of actions."""

    PAUSE_THRESHOLD_SECONDS = 8.0          # gap longer than this counts as a pause
    BURST_WINDOW_FRACTION = 0.20           # densest 20% of the time span
    WORKING_HOURS = (time(9, 0), time(18, 0))

    def analyze(self, events: Sequence[ActionEvent]) -> RhythmReport:
        if not events:
            return RhythmReport(notes=["No events provided."])

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        report = RhythmReport(sample_size=len(sorted_events))

        # --- Inter-arrival gaps ---
        gaps = []
        for i in range(1, len(sorted_events)):
            delta = (sorted_events[i].timestamp - sorted_events[i - 1].timestamp).total_seconds()
            if delta >= 0:
                gaps.append(delta)

        if gaps:
            report.mean_gap_seconds = statistics.mean(gaps)
            report.median_gap_seconds = statistics.median(gaps)
            report.longest_pause_seconds = max(gaps)
            report.pause_count = sum(1 for g in gaps if g > self.PAUSE_THRESHOLD_SECONDS)

            if len(gaps) >= 2 and report.mean_gap_seconds > 0:
                report.inter_arrival_cv = statistics.stdev(gaps) / report.mean_gap_seconds

        # --- Action durations ---
        durations = [
            e.duration_ms for e in sorted_events
            if e.duration_ms is not None and e.duration_ms > 0
        ]
        if durations:
            report.mean_duration_ms = statistics.mean(durations)
            if len(durations) >= 2 and report.mean_duration_ms > 0:
                report.duration_cv = statistics.stdev(durations) / report.mean_duration_ms

        # --- Burstiness ---
        report.burst_score = self._burst_score(sorted_events)

        # --- Time-of-day ---
        hours = sorted({e.timestamp.hour for e in sorted_events})
        report.active_hours = hours
        report.hour_spread = len(hours)

        working_count = 0
        start, end = self.WORKING_HOURS
        for e in sorted_events:
            t = e.timestamp.time()
            if start <= t <= end:
                working_count += 1
        report.working_hours_ratio = working_count / len(sorted_events)

        # --- Corrections / backtracks ---
        report.correction_rate = self._correction_rate(sorted_events)

        # --- Human-readable notes ---
        report.notes = self._generate_notes(report)

        return report

    def _burst_score(self, events: Sequence[ActionEvent]) -> float:
        if len(events) < 6:
            return 0.0
        timestamps = [e.timestamp.timestamp() for e in events]
        total_span = max(timestamps) - min(timestamps)
        if total_span <= 0:
            return 1.0

        window = total_span * self.BURST_WINDOW_FRACTION
        max_in_window = 0
        for t in timestamps:
            count = sum(1 for other in timestamps if t <= other <= t + window)
            if count > max_in_window:
                max_in_window = count
        return max_in_window / len(events)

    def _correction_rate(self, events: Sequence[ActionEvent]) -> float:
        if not events:
            return 0.0
        keywords = {"undo", "back", "retry", "correct", "fix", "revert", "cancel"}
        count = 0
        for e in events:
            at = e.action_type.lower()
            if any(k in at for k in keywords):
                count += 1
            if e.metadata.get("is_correction") or e.metadata.get("is_backtrack"):
                count += 1
        return count / len(events)

    def _generate_notes(self, report: RhythmReport) -> List[str]:
        notes = []
        if report.inter_arrival_cv is not None:
            if report.inter_arrival_cv < 0.18:
                notes.append("Extremely regular inter-arrival times (machine-like).")
            elif report.inter_arrival_cv > 0.55:
                notes.append("Highly irregular timing (human-like).")

        if report.duration_cv is not None and report.duration_cv < 0.12:
            notes.append("Near-constant action durations.")

        if report.burst_score > 0.65:
            notes.append(f"Strong burst pattern ({report.burst_score:.0%} of activity concentrated).")

        if report.pause_count > 0 and report.longest_pause_seconds:
            notes.append(
                f"{report.pause_count} significant pause(s); longest {report.longest_pause_seconds:.1f}s."
            )

        if report.hour_spread <= 2:
            notes.append(f"Activity confined to only {report.hour_spread} hour(s).")
        elif report.working_hours_ratio > 0.9:
            notes.append("Almost entirely within standard working hours.")
        elif report.working_hours_ratio < 0.2:
            notes.append("Mostly outside standard working hours.")

        if report.correction_rate > 0.15:
            notes.append(f"Elevated correction/backtrack rate ({report.correction_rate:.0%}).")
        elif report.correction_rate < 0.03 and report.sample_size > 15:
            notes.append("Very low self-correction rate.")

        if not notes:
            notes.append("No strong rhythm signals detected.")
        return notes


def analyze_rhythm(events: Sequence[ActionEvent]) -> RhythmReport:
    """Convenience function."""
    return RhythmAnalyzer().analyze(events)
