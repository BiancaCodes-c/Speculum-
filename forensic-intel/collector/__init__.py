"""Collectors: security events, health, network tap."""

from .agent import (
    CollectionResult,
    SecurityEventCollector,
    collect_events,
    simulate_session,
)

__all__ = [
    "CollectionResult",
    "SecurityEventCollector",
    "collect_events",
    "simulate_session",
]
