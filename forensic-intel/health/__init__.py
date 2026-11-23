"""Health subsystem: vitals, baseline, score, and correlation with threat."""

from .vitals import Vitals, VitalsMonitor, current_vitals
from .baseline import Baseline, SystemBaseline, MetricBaseline, learn_baseline
from .health_score import HealthScorer, HealthVerdict, calculate_health_score
from .correlation import Correlator, CorrelationResult, Judgment, correlate

__all__ = [
    "Vitals",
    "VitalsMonitor",
    "current_vitals",
    "Baseline",
    "SystemBaseline",
    "MetricBaseline",
    "learn_baseline",
    "HealthScorer",
    "HealthVerdict",
    "calculate_health_score",
    "Correlator",
    "CorrelationResult",
    "Judgment",
    "correlate",
]
