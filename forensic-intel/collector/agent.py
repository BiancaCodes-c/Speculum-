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
from typing import List, Optional, Union
from pathlib import Path
import random
import uuid

from analyzer.profiler import ActionEvent  # type: ignore
from storage.immutable_log import ImmutableLog, LogEntry  # type: ignore


@dataclass
class CollectionResult:
    """What the collector produced in one run."""
    events: List[ActionEvent]
    source: str
    session_id: str
    collected_at: datetime = field(default_factory=datetime.utcnow)
    log_entries: List[LogEntry] = field(default_factory=list)
    persisted: bool = False


class SecurityEventCollector:
    """Collects (or simulates) security-relevant actions.

    When an ImmutableLog is supplied (or a path is given), every
    collected / simulated event is appended to the log so the
    evidence chain is built automatically.
    """

    def __init__(
        self,
        source_name: str = "local",
        log: Optional[ImmutableLog] = None,
        log_path: Optional[Union[str, Path]] = None,
    ):
        self.source_name = source_name
        if log is not None:
            self.log = log
        elif log_path is not None:
            self.log = ImmutableLog(log_path)
        else:
            self.log = None

    def collect(self) -> CollectionResult:
        """Placeholder for real collection.

        In a later iteration this will pull from OS audit logs,
        process monitors, etc. For now it returns an empty result
        so callers know the interface.
        """
        result = CollectionResult(
            events=[],
            source=self.source_name,
            session_id=str(uuid.uuid4()),
        )
        return self._maybe_persist(result)

    # ------------------------------------------------------------------
    # Simulator
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

        result = CollectionResult(
            events=events,
            source=f"simulator:{style}",
            session_id=str(uuid.uuid4()),
        )
        return self._maybe_persist(result)

    def _maybe_persist(self, result: CollectionResult) -> CollectionResult:
        """If a log is configured, write every event + a session summary."""
        if self.log is None:
            return result

        written: List[LogEntry] = []

        for ev in result.events:
            payload = {
                "session_id": result.session_id,
                "source": result.source,
                "timestamp": ev.timestamp.isoformat(),
                "action_type": ev.action_type,
                "duration_ms": ev.duration_ms,
                "metadata": ev.metadata,
            }
            entry = self.log.append("security_event", payload)
            written.append(entry)

        summary_payload = {
            "session_id": result.session_id,
            "source": result.source,
            "event_count": len(result.events),
            "collected_at": result.collected_at.isoformat() + "Z",
            "first_event": result.events[0].timestamp.isoformat() if result.events else None,
            "last_event": result.events[-1].timestamp.isoformat() if result.events else None,
        }
        summary_entry = self.log.append("session_summary", summary_payload)
        written.append(summary_entry)

        result.log_entries = written
        result.persisted = True
        return result

    # ------------------------------------------------------------------
    # Simulation helpers
    # ------------------------------------------------------------------

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
            if random.random() < 0.12:
                gap = random.uniform(6.0, 14.0)
            else:
                gap = random.uniform(0.35, 3.2)

            t = t + timedelta(seconds=gap)
            action = random.choice(action_pool)
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
        base_interval = 0.48

        for i in range(count):
            jitter = random.uniform(-0.015, 0.015)
            t = t + timedelta(seconds=base_interval + jitter)
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


def collect_events(
    source_name: str = "local",
    log: Optional[ImmutableLog] = None,
    log_path: Optional[Union[str, Path]] = None,
) -> CollectionResult:
    """Convenience wrapper."""
    return SecurityEventCollector(source_name, log=log, log_path=log_path).collect()


def simulate_session(
    style: str = "human",
    event_count: int = 18,
    start: Optional[datetime] = None,
    log: Optional[ImmutableLog] = None,
    log_path: Optional[Union[str, Path]] = None,
) -> CollectionResult:
    """Convenience wrapper for the simulator."""
    return SecurityEventCollector(log=log, log_path=log_path).simulate_session(
        style, event_count, start
    )
