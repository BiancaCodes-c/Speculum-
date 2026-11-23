"""Full pipeline demo with evidence persistence.

collector → ImmutableLog → rhythm → profiler → entry/data-flow → threat score

Run from the forensic-intel directory:

    python -m examples.run_profiler_demo
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.agent import SecurityEventCollector  # type: ignore
from storage.immutable_log import ImmutableLog  # type: ignore
from analyzer.rhythm_analyzer import RhythmAnalyzer  # type: ignore
from analyzer.profiler import Profiler  # type: ignore
from analyzer.entry_analyzer import EntryAnalyzer  # type: ignore
from analyzer.data_flow_analyzer import DataFlowAnalyzer  # type: ignore
from analyzer.threat_score import ThreatScorer  # type: ignore


def run_one(style: str, log: ImmutableLog) -> None:
    print(f"\n{'='*60}")
    print(f"  Session style: {style.upper()}")
    print(f"{'='*60}")

    collector = SecurityEventCollector(log=log)
    result = collector.simulate_session(style=style, event_count=16)

    print(f"Collected {len(result.events)} events  |  source={result.source}")
    print(f"Persisted to log : {result.persisted}  ({len(result.log_entries)} log entries)")
    print(f"Log chain valid  : {log.verify()}  |  total entries now: {len(log)}")

    rhythm = RhythmAnalyzer().analyze(result.events)
    profile = Profiler().profile(rhythm)

    entry = EntryAnalyzer().analyze(result.events)
    flow = DataFlowAnalyzer().analyze(result.events)

    threat = ThreatScorer().score(
        profile=profile,
        entry=entry.signal,
        data_flow=flow.signal,
        rhythm=rhythm,
    )

    print("\n--- Profiler ---")
    print(f"  actor={profile.actor.value}  score={profile.score}  conf={profile.confidence}")

    print("\n--- Entry ---")
    print(f"  vector={entry.signal.vector}  severity={entry.signal.severity}")

    print("\n--- Data Flow ---")
    print(f"  method={flow.signal.method}  volume={flow.signal.volume_score}  speed={flow.signal.speed_score}")

    print("\n--- Threat ---")
    print(f"  score={threat.score}  level={threat.level.value}  conf={threat.confidence}")
    for r in threat.reasons[:4]:
        print(f"    • {r}")


def main() -> None:
    log_path = Path("demo_evidence.jsonl")
    if log_path.exists():
        log_path.unlink()  # start clean for the demo

    log = ImmutableLog(log_path)

    for style in ("human", "ai", "mixed"):
        run_one(style, log)

    print(f"\n{'='*60}")
    print(f"  Final log status")
    print(f"{'='*60}")
    print(f"  Total entries : {len(log)}")
    print(f"  Chain valid   : {log.verify()}")
    print(f"  Written to    : {log_path.resolve()}")
    print()


if __name__ == "__main__":
    main()
