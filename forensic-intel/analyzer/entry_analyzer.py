"""Entry analyzer.

Answers HOW they got in: phishing, vendor compromise, stolen
key, brute force, or another vector — with the evidence for the call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .threat_score import EntrySignal
from .profiler import ActionEvent


@dataclass
class EntryFinding:
    """Detailed result from the entry analyzer."""
    signal: EntrySignal
    matched_indicators: List[str] = field(default_factory=list)
    raw_events_examined: int = 0


class EntryAnalyzer:
    """Classify the most likely entry vector from observed events."""

    # Simple indicator → (vector, severity contribution)
    INDICATORS = {
        "phishing": {
            "keywords": ["phish", "credential_harvest", "fake_login", "spear"],
            "severity": 70.0,
        },
        "stolen_key": {
            "keywords": ["stolen_key", "key_reuse", "anomalous_key", "ssh_key", "api_key"],
            "severity": 75.0,
        },
        "brute_force": {
            "keywords": ["brute", "password_spray", "failed_login", "auth_fail"],
            "severity": 55.0,
        },
        "vendor_compromise": {
            "keywords": ["vendor", "supply_chain", "third_party", "sso_federation"],
            "severity": 80.0,
        },
        "exploit": {
            "keywords": ["exploit", "cve", "rce", "privilege_escalation"],
            "severity": 85.0,
        },
        "insider": {
            "keywords": ["insider", "lateral_from_internal", "privilege_abuse"],
            "severity": 65.0,
        },
    }

    def analyze(
        self,
        events: Sequence[ActionEvent] | None = None,
        hints: Optional[Dict[str, Any]] = None,
    ) -> EntryFinding:
        """Produce an EntrySignal from events and optional external hints."""
        events = events or []
        hints = hints or {}

        scores: Dict[str, float] = {k: 0.0 for k in self.INDICATORS}
        matched: List[str] = []

        # 1. Scan event action types + metadata
        for ev in events:
            text = (ev.action_type + " " + str(ev.metadata)).lower()
            for vector, cfg in self.INDICATORS.items():
                for kw in cfg["keywords"]:
                    if kw in text:
                        scores[vector] += cfg["severity"] * 0.35
                        matched.append(f"{vector}:{kw}")

        # 2. Honor explicit hints (e.g. from an upstream alert system)
        if "vector" in hints:
            v = str(hints["vector"]).lower()
            if v in scores:
                scores[v] += float(hints.get("severity", 60.0))
                matched.append(f"hint:{v}")

        if "indicators" in hints and isinstance(hints["indicators"], list):
            for ind in hints["indicators"]:
                ind_l = str(ind).lower()
                for vector, cfg in self.INDICATORS.items():
                    if any(kw in ind_l for kw in cfg["keywords"]):
                        scores[vector] += cfg["severity"] * 0.5
                        matched.append(f"hint-indicator:{ind}")

        # Choose the strongest vector
        if not any(scores.values()):
            signal = EntrySignal(
                severity=15.0,
                vector="unknown",
                evidence=["No clear entry indicators observed."],
            )
            return EntryFinding(signal=signal, matched_indicators=[], raw_events_examined=len(events))

        best_vector = max(scores, key=scores.get)
        raw_severity = min(100.0, scores[best_vector])

        evidence = [
            f"Primary indicators point to '{best_vector}'.",
            f"Matched: {', '.join(matched[:5])}" if matched else "No keyword matches.",
        ]
        if hints:
            evidence.append(f"External hints were supplied: {list(hints.keys())}")

        signal = EntrySignal(
            severity=round(raw_severity, 1),
            vector=best_vector,
            evidence=evidence,
        )
        return EntryFinding(
            signal=signal,
            matched_indicators=matched,
            raw_events_examined=len(events),
        )


def analyze_entry(
    events: Sequence[ActionEvent] | None = None,
    hints: Optional[Dict[str, Any]] = None,
) -> EntryFinding:
    """Convenience function."""
    return EntryAnalyzer().analyze(events=events, hints=hints)
