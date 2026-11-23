"""Quick demo of the collector → rhythm → profiler pipeline.

Run from the forensic-intel directory (or adjust PYTHONPATH):

    python -m examples.run_profiler_demo
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the package importable when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.agent import SecurityEventCollector  # type: ignore
from analyzer.rhythm_analyzer import RhythmAnalyzer  # type: ignore
from analyzer.profiler import Profiler  # type: ignore


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
    print(f"  hour_spread      : {rhythm.hour_spread}")
    print(f"  notes            : {rhythm.notes}")

    verdict = Profiler().profile(rhythm)   # or profile(result.events)
    print("\n--- Profiler Verdict ---")
    print(f"  actor       : {verdict.actor.value}")
    print(f"  score       : {verdict.score}")
    print(f"  confidence  : {verdict.confidence}")
    print(f"  reasons     :")
    for r in verdict.reasons:
        print(f"    • {r}")


def main() -> None:
    for style in ("human", "ai", "mixed"):
        run_one(style)
    print()


if __name__ == "__main__":
    main()
