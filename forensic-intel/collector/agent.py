"""Security event collector.

Collects security events from each machine Speculum watches and
forwards them to the immutable log.

Also provides a simulator so the Profiler and RhythmAnalyzer
can be exercised with realistic human-like and AI-like sessions
before real sensors are wired in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Sequence
import random
import uuid

from analyzer.profiler import ActionEvent  # type: ignore


@dataclass
class CollectionResult:
    """What the collector produced in one run."""
    events: List[ActionEvent]
    source: str
    session_id: str
    collected_at: datetime = field(default_factory=datetime.utcnow)


class SecurityEventCollector:
    """Collects (or simulates) security-relevant actions."""

    def __init__(self, source_name: str = "local"):
        self.source_name = source_name

    def collect(self) -> CollectionResult:
        """Placeholder for real collection.

        In a later iteration this will pull from OS audit logs,
        process monitors, etc. For now it returns an empty result
        so callers know the interface.
        """
        return CollectionResult(
            events=[],
            source=self.source_name,
            session_id=str(uuid.uuid4()),
        )

    # ------------------------------------------------------------------
    # Simulator — useful right now
    # ------------------------------------------------------------------

    def simulate_session(
        self,
        style: str = "human",
        event_count: int = 18,
        start: Optional[datetime] = None,
    ) -> CollectionResult:
        """Generate a realistic session of ActionEvents.

        style:
          - "human"   → irregular gaps, variable duration, some corrections
          - "ai"      → tight regular timing, almost constant duration
          - "mixed"   → mostly regular with occasional human-like pauses
        """
        if start is None:
            start = datetime.utcnow().replace(hour=14, minute=0, second=0, microsecond=0)

        if style == "ai":
            events = self._simulate_ai(start, event_count)
        elif style == "mixed":
            events = self._simulate_mixed(start, event_count)
        else:
            events = self._simulate_human(start, event_count)

        return CollectionResult(
            events=events,
            source=f"simulator:{style}",
            session_id=str(uuid.uuid4()),
        )

    def _simulate_human(self, start: datetime, count: int) -> List[ActionEvent]:
        events: List[ActionEvent] = []
        t = start
        action_pool = [
            "command",
            "file_read",
            "file_write",
            "network",
            "login",
            "process_start",
            "undo",
            "retry",
        ]

        for i in range(count):
            # Human gaps: mostly 0.4–3s with occasional longer pauses
            if random.random() < 0.12:
                gap = random.uniform(6.0, 14.0)          # thinking pause
            else:
                gap = random.uniform(0.35, 3.2)

            t = t + timedelta(seconds=gap)
            action = random.choice(action_pool)

            # Humans have more variable action duration
            duration = random.uniform(45.0, 280.0)

            meta = {}
            if action in {"undo", "retry"}:
                meta["is_correction"] = True

            events.append(
                ActionEvent(
                    timestamp=t,
                    action_type=action,
                    duration_ms=duration,
                    metadata=meta,
                )
            )
        return events

    def _simulate_ai(self, start: datetime, count: int) -> List[ActionEvent]:
        events: List[ActionEvent] = []
        t = start
        # Very regular interval with tiny jitter
        base_interval = 0.48

        for i in range(count):
            jitter = random.uniform(-0.015, 0.015)
            t = t + timedelta(seconds=base_interval + jitter)

            # Almost constant duration
            duration = 41.0 + random.uniform(-1.5, 1.5)

            events.append(
                ActionEvent(
                    timestamp=t,
                    action_type="command",
                    duration_ms=duration,
                    metadata={"scripted": True},
                )
            )
        return events

    def _simulate_mixed(self, start: datetime, count: int) -> List[ActionEvent]:
        events: List[ActionEvent] = []
        t = start
        base_interval = 0.55

        for i in range(count):
            if random.random() < 0.18:
                # occasional human-like pause
                gap = random.uniform(4.0, 9.0)
            else:
                gap = base_interval + random.uniform(-0.04, 0.04)

            t = t + timedelta(seconds=gap)
            duration = 52.0 + random.uniform(-4.0, 8.0)

            events.append(
                ActionEvent(
                    timestamp=t,
                    action_type="command",
                    duration_ms=duration,
                )
            )
        return events


def collect_events(source_name: str = "local") -> CollectionResult:
    """Convenience wrapper."""
    return SecurityEventCollector(source_name).collect()


def simulate_session(
    style: str = "human",
    event_count: int = 18,
    start: Optional[datetime] = None,
) -> CollectionResult:
    """Convenience wrapper for the simulator."""
    return SecurityEventCollector().simulate_session(style, event_count, start)
