# Speculum — Forensic Intel

Speculum is a forensic intelligence system. It watches a machine the way a
mirror watches a room: it records what happened, rewinds it, and tells the
story of an intrusion — how they got in, what they took, and whether the
hands on the keyboard were human or AI.

## The two numbers

Everything in Speculum answers to two scores, shown side by side:

- **Health Score (0–100)** — how well the system itself is doing: CPU,
  memory, disk, network, services, measured against a baseline learned
  from *this* system, not a generic one.
- **Threat Score (0–100)** — how dangerous the observed behavior is,
  built from the entry point, the data flow, and the rhythm of the actor.

The correlation layer reads the two together, because the same symptom
can be a glitch, an attack, or a quiet intrusion — and the response is
different for each.

## How it runs

1. **Collectors** gather security events (`collector/agent.py`), health
   events (`collector/health_agent.py`), and outbound data movement
   (`collector/network_tap.py`) from each machine.
2. Everything lands in **append-only, hash-chained logs**
   (`storage/`) — entries can be added but never edited or deleted
   without breaking the chain.
3. The **timeline** layer links events into one attack story: a
   who → what → where graph, a rewind to the first anomaly, and the
   access point it came through.
4. The **analyzer** answers three questions: *how* did they get in
   (entry), *what* did they take and how (data flow), and *who* was it —
   human rhythm or AI speed (rhythm + profiler, producing an AI vs
   HUMAN verdict with a fingerprint and reasons).
5. The **health** layer keeps its own continuous read — baseline,
   vitals, score, alerts — and the **correlation** layer joins health
   and threat into one judgment.
6. **Repair** acts narrowly and reversibly: isolate only the affected
   account or machine, roll back only changed files from a known-good
   snapshot, revoke only compromised keys and sessions — then write the
   forensic report: entry, timeline, what was taken, what was fixed.
7. The **dashboard** shows it all live: health and threat scores big
   and clear, both lines moving together over time, and the profiler
   verdict with its reasons.

Start the dashboard with:

```bash
python -m forensic-intel.dashboard.main
```

## Layout

| Folder       | Job |
|--------------|-----|
| `collector/` | Pull security events, health events, and outbound traffic from each machine |
| `storage/`   | Append-only, hash-chained logs — the evidence, tamper-evident |
| `timeline/`  | Graph, rewind, and event chains — events linked into one attack story |
| `analyzer/`  | Entry, data flow, rhythm, profiler, threat score |
| `health/`    | Baseline, vitals, health score, alerts, health↔threat correlation |
| `repair/`    | Isolate, roll back, revoke, report |
| `dashboard/` | Health panel, threat panel, timeline view, profiler view |
| `config/`    | `baselines.json` (what normal is) and `thresholds.json` (when to alert, when to isolate) |
| `tests/`     | Health score, correlation, and profiler tests |

## Design rules

- **Evidence is immutable.** Logs are append-only and hash-chained.
- **Repair is surgical.** Never take down a whole system to fix one
  account, one machine, or a handful of files.
- **Every verdict shows its reasons.** The profiler never returns a bare
  label — it returns a score, a fingerprint, and why.
