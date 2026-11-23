"""Data flow analyzer.

Answers WHAT they took and HOW they took it: which data, how
much, how fast, and by what method.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .threat_score import DataFlowSignal
from .profiler import ActionEvent


@dataclass
class DataFlowFinding:
    """Detailed result from the data-flow analyzer."""
    signal: DataFlowSignal
    total_bytes: int = 0
    event_count: int = 0
    methods_seen: List[str] = field(default_factory=list)


class DataFlowAnalyzer:
    """Estimate volume, speed, and method of data movement."""

    # Heuristic mapping from action_type / metadata → method + weight
    METHOD_HINTS = {
        "exfil": ["exfil", "upload", "outbound", "s3_put", "scp", "rsync"],
        "encrypted_channel": ["encrypted", "tls", "https", "ssh", "wireguard", "vpn"],
        "lateral": ["lateral", "smb", "rdp", "winrm", "psexec"],
        "dns_tunnel": ["dns_tunnel", "dns_exfil"],
        "cloud_sync": ["dropbox", "gdrive", "onedrive", "box", "sync"],
    }

    def analyze(
        self,
        events: Sequence[ActionEvent] | None = None,
        hints: Optional[Dict[str, Any]] = None,
    ) -> DataFlowFinding:
        events = events or []
        hints = hints or {}

        total_bytes = 0
        method_scores: Dict[str, float] = {m: 0.0 for m in self.METHOD_HINTS}
        methods_seen: List[str] = []

        for ev in events:
            # Volume from metadata if present
            bytes_moved = 0
            if "bytes" in ev.metadata:
                try:
                    bytes_moved = int(ev.metadata["bytes"])
                except (TypeError, ValueError):
                    pass
            elif "size" in ev.metadata:
                try:
                    bytes_moved = int(ev.metadata["size"])
                except (TypeError, ValueError):
                    pass
            total_bytes += bytes_moved

            text = (ev.action_type + " " + str(ev.metadata)).lower()
            for method, keywords in self.METHOD_HINTS.items():
                if any(kw in text for kw in keywords):
                    method_scores[method] += 1.0
                    if method not in methods_seen:
                        methods_seen.append(method)

        # External hints can override / boost
        if "bytes" in hints:
            try:
                total_bytes = max(total_bytes, int(hints["bytes"]))
            except (TypeError, ValueError):
                pass
        if "method" in hints:
            m = str(hints["method"]).lower()
            if m in method_scores:
                method_scores[m] += 5.0
                if m not in methods_seen:
                    methods_seen.append(m)

        # Choose dominant method
        if any(method_scores.values()):
            dominant = max(method_scores, key=method_scores.get)
        else:
            dominant = "unknown"

        # Volume score (very rough log-ish scale)
        # 0 bytes → 0, 1 MB → ~30, 100 MB → ~60, 1 GB+ → 85+
        if total_bytes <= 0:
            volume_score = 10.0 if dominant != "unknown" else 5.0
        else:
            import math
            volume_score = min(95.0, 12.0 * math.log10(total_bytes + 1))

        # Speed score – currently a simple proxy from event density
        # (real implementation will use actual transfer rates later)
        speed_score = 20.0
        if len(events) > 8 and dominant != "unknown":
            speed_score = min(90.0, 25.0 + len(events) * 2.5)
        if "speed_score" in hints:
            try:
                speed_score = float(hints["speed_score"])
            except (TypeError, ValueError):
                pass

        evidence = []
        if total_bytes > 0:
            evidence.append(f"Observed ~{total_bytes:,} bytes moved.")
        if methods_seen:
            evidence.append(f"Methods indicated: {', '.join(methods_seen)}.")
        else:
            evidence.append("No strong data-movement method indicators.")

        signal = DataFlowSignal(
            volume_score=round(volume_score, 1),
            speed_score=round(speed_score, 1),
            method=dominant,
            evidence=evidence,
        )

        return DataFlowFinding(
            signal=signal,
            total_bytes=total_bytes,
            event_count=len(events),
            methods_seen=methods_seen,
        )


def analyze_flow(
    events: Sequence[ActionEvent] | None = None,
    hints: Optional[Dict[str, Any]] = None,
) -> DataFlowFinding:
    """Convenience function."""
    return DataFlowAnalyzer().analyze(events=events, hints=hints)
