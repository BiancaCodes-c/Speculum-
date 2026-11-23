"""Full Speculum pipeline demo.

collector → ImmutableLog → rhythm → profiler → entry/data-flow
         → threat score → health score → correlation judgment

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
from health.vitals import VitalsMonitor  # type: ignore
from health.baseline import Baseline  # type: ignore
from health.health_score import HealthScorer  # type: ignore
from health.correlation import Correlator  # type: ignore


def run_one(style: str, log: ImmutableLog, baseline: Baseline) -> None:
    print(f"\n{'='*64}")
    print(f"  Session: {style.upper()}")
    print(f"{'='*64}")

    collector = SecurityEventCollector(log=log)
    result = collector.simulate_session(style=style, event_count=16)

    print(f"Events: {len(result.events)}  |  Persisted: {result.persisted}  |  Log size: {len(log)}")

    # --- Threat side ---
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

    # --- Health side ---
    # Pick vitals style that pairs interestingly with the actor style
    vitals_style = {
        "human": "normal",
        "ai": "quiet",       # quiet vitals + AI actor → quiet intrusion signature
        "mixed": "stressed",
    }.get(style, "normal")

    vitals = VitalsMonitor().simulate(vitals_style)
    health = HealthScorer().score(vitals, baseline)

    # --- Correlation ---
    judgment = Correlator().correlate(health, threat)

    print(f"\n  Profiler     : {profile.actor.value} (score {profile.score})")
    print(f"  Threat       : {threat.score} [{threat.level.value}]")
    print(f"  Health       : {health.score} [{health.status}]  (vitals={vitals_style})")
    print(f"  Judgment     : {judgment.judgment.value}  (conf {judgment.confidence})")
    print(f"  Summary      : {judgment.summary}")
    for r in judgment.reasons[:3]:
        print(f"    • {r}")


def main() -> None:
    log_path = Path("demo_evidence.jsonl")
    if log_path.exists():
        log_path.unlink()

    log = ImmutableLog(log_path)

    # Learn a quick baseline from "normal" samples
    monitor = VitalsMonitor()
    samples = [monitor.simulate("normal") for _ in range(12)]
    baseline = Baseline()
    baseline.learn(samples)

    for style in ("human", "ai", "mixed"):
        run_one(style, log, baseline)

    print(f"\n{'='*64}")
    print(f"  Log entries: {len(log)}  |  Chain valid: {log.verify()}")
    print(f"  Evidence file: {log_path.resolve()}")
    print()


if __name__ == "__main__":
    main()
