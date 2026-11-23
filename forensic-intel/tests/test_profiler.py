"""Profiler returns a verdict with a fingerprint and reasons."""

from datetime import datetime, timedelta
import sys
from pathlib import Path

# Allow running tests from repo root even with hyphenated folder name
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from analyzer.profiler import (  # type: ignore
    ActionEvent,
    ActorType,
    Profiler,
    profile_actor,
)


def _make_events(count: int, interval_seconds: float = 1.2, jitter: float = 0.0):
    """Helper to generate timed events."""
    base = datetime(2026, 11, 22, 14, 0, 0)
    events = []
    for i in range(count):
        offset = interval_seconds * i + (jitter * (i % 3 - 1))
        ts = base + timedelta(seconds=offset)
        events.append(
            ActionEvent(
                timestamp=ts,
                action_type="command",
                duration_ms=80.0 + (i % 5) * 2,
            )
        )
    return events


def test_insufficient_data():
    verdict = profile_actor([])
    assert verdict.actor == ActorType.UNCERTAIN
    assert verdict.sample_size == 0
    assert "Insufficient" in verdict.reasons[0]


def test_human_like_irregular():
    """Human-like: irregular gaps and some corrections."""
    base = datetime(2026, 11, 22, 10, 0, 0)
    gaps = [0.8, 2.1, 0.4, 3.7, 1.1, 0.9, 4.2, 1.5, 0.6, 2.8, 1.0, 3.1]
    events = []
    t = base
    for i, g in enumerate(gaps):
        t = t + timedelta(seconds=g)
        action = "command" if i % 4 != 0 else "undo"
        events.append(
            ActionEvent(
                timestamp=t,
                action_type=action,
                duration_ms=120 + (i * 17) % 90,
            )
        )

    verdict = profile_actor(events)
    assert verdict.actor in (ActorType.HUMAN, ActorType.UNCERTAIN)
    assert verdict.sample_size == len(events)
    assert isinstance(verdict.fingerprint, dict)
    assert len(verdict.reasons) >= 1


def test_ai_like_regular():
    """AI-like: very regular timing, almost constant duration."""
    events = _make_events(20, interval_seconds=0.5, jitter=0.01)
    for e in events:
        e.duration_ms = 42.0

    verdict = profile_actor(events)
    assert verdict.actor == ActorType.AI
    assert verdict.score >= 70
    assert verdict.confidence > 0.5
    reasons_text = " ".join(verdict.reasons).lower()
    assert "regular" in reasons_text or "machine" in reasons_text


def test_verdict_always_has_fingerprint_and_reasons():
    events = _make_events(10)
    verdict = Profiler().profile(events)
    assert hasattr(verdict, "fingerprint")
    assert hasattr(verdict, "reasons")
    assert isinstance(verdict.reasons, list)
    assert len(verdict.reasons) > 0
