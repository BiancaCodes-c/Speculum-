"""Quick demo of the full analysis pipeline.

collector → rhythm → profiler → threat score

Run from the forensic-intel directory:

    python -m examples.run_profiler_demo
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.agent import SecurityEventCollector  # type: ignore
from analyzer.rhythm_analyzer import RhythmAnalyzer  # type: ignore
from analyzer.profiler import Profiler  # type: ignore
from analyzer.threat_score import (  # type: ignore
    ThreatScorer,
    EntrySignal,
    DataFlowSignal,
)


def run_one(style: str) -> None:
    print(f"\n{'='*60}")
    print(f"  Session style: {style.upper()}")
    print(f"{'='*60}")

    collector = SecurityEventCollector()
    result = collector.simulate_session(style=style, event_count=20)

    print(f"Collected {len(result.events)} events  |  source={result.source}")

    rhythm = RhythmAnalyzer().analyze(result.events)
    print("\n--- Rhythm Report ---")
    print(f"  inter_arrival_cv : {rhythm.inter_arrival_cv}")
    print(f"  duration_cv      : {rhythm.duration_cv}")
    print(f"  burst_score      : {rhythm.burst_score:.3f}")
    print(f"  correction_rate  : {rhythm.correction_rate:.3f}")
    print(f"  notes            : {rhythm.notes}")

    profile = Profiler().profile(rhythm)
    print("\n--- Profiler Verdict ---")
    print(f"  actor       : {profile.actor.value}")
    print(f"  score       : {profile.score}")
    print(f"  confidence  : {profile.confidence}")
    for r in profile.reasons:
        print(f"    • {r}")

    # Optional example signals (will be replaced by real analyzers later)
    entry = None
    data_flow = None
    if style == "ai":
        entry = EntrySignal(
            severity=72.0,
            vector="stolen_key",
            evidence=["Key used from unusual geolocation", "No MFA challenge observed"],
        )
        data_flow = DataFlowSignal(
            volume_score=65.0,
            speed_score=80.0,
            method="encrypted_channel",
            evidence=["Large outbound transfer in short window"],
        )

    threat = ThreatScorer().score(
        profile=profile,
        entry=entry,
        data_flow=data_flow,
        rhythm=rhythm,
    )

    print("\n--- Threat Score ---")
    print(f"  score       : {threat.score}")
    print(f"  level       : {threat.level.value}")
    print(f"  confidence  : {threat.confidence}")
    print(f"  components  : {threat.components}")
    for r in threat.reasons:
        print(f"    • {r}")


def main() -> None:
    for style in ("human", "ai", "mixed"):
        run_one(style)
    print()


if __name__ == "__main__":
    main()
