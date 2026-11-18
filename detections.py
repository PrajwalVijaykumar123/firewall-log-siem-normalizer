"""
5 SOC-style correlation detections over the normalized, multi-vendor
event stream - the point of normalizing in the first place is that
these all run identically whether the underlying log came from a
FortiGate or a Sophos XG box.

The time-window logic here is a simple forward scan over events already
sorted by timestamp, grouping by source IP within a fixed window from
each source's FIRST seen event - the same kind of explicitly-scoped
simplification this portfolio's soc-alert-triage-engine documents for
its own clustering (not a true sliding window), stated here for the
same reason: honest about what it does rather than implying something
more sophisticated.
"""
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

WINDOW_MINUTES_DEFAULT = 5
PORT_SCAN_DISTINCT_PORTS_THRESHOLD = 5
HIGH_VOLUME_DENY_THRESHOLD = 10
NETWORK_SWEEP_DISTINCT_HOSTS_THRESHOLD = 4

RISKY_PORTS = {
    22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP", 3306: "MySQL",
    5432: "PostgreSQL", 1433: "MSSQL", 21: "FTP",
}


@dataclass
class Finding:
    detection_id: str
    severity: str
    src_ip: str
    message: str


def _group_by_src(events: list) -> dict:
    grouped = defaultdict(list)
    for e in events:
        grouped[e.src_ip].append(e)
    return grouped


def _within_window(events_for_src: list, window_minutes: int):
    """Yields successive windows: each window starts at an event's
    timestamp and includes every later event from the same source
    within window_minutes of it - a simple forward scan, not a true
    sliding window (see module docstring)."""
    for i, start_event in enumerate(events_for_src):
        window_end = start_event.timestamp + timedelta(minutes=window_minutes)
        window = [e for e in events_for_src[i:] if e.timestamp <= window_end]
        yield start_event, window


def detect_port_scan(events: list, window_minutes: int = WINDOW_MINUTES_DEFAULT,
                      threshold: int = PORT_SCAN_DISTINCT_PORTS_THRESHOLD) -> list:
    findings = []
    seen_src = set()
    for src_ip, src_events in _group_by_src(events).items():
        denied = [e for e in src_events if e.action == "deny"]
        for _, window in _within_window(denied, window_minutes):
            distinct_ports = {e.dst_port for e in window}
            if len(distinct_ports) >= threshold and src_ip not in seen_src:
                seen_src.add(src_ip)
                findings.append(Finding(
                    "DET-1", "high", src_ip,
                    f"{src_ip} was denied against {len(distinct_ports)} distinct "
                    f"destination ports within {window_minutes} minutes - port scan pattern.",
                ))
    return findings


def detect_high_volume_deny(events: list, window_minutes: int = WINDOW_MINUTES_DEFAULT,
                             threshold: int = HIGH_VOLUME_DENY_THRESHOLD) -> list:
    findings = []
    seen_src = set()
    for src_ip, src_events in _group_by_src(events).items():
        denied = [e for e in src_events if e.action == "deny"]
        for _, window in _within_window(denied, window_minutes):
            if len(window) >= threshold and src_ip not in seen_src:
                seen_src.add(src_ip)
                findings.append(Finding(
                    "DET-2", "medium", src_ip,
                    f"{src_ip} generated {len(window)} denied connection attempts "
                    f"within {window_minutes} minutes - volume consistent with an "
                    f"automated scanning tool rather than manual activity.",
                ))
    return findings


def detect_risky_port_exposure_attempt(events: list) -> list:
    findings = []
    for e in events:
        if e.action == "deny" and e.dst_port in RISKY_PORTS:
            findings.append(Finding(
                "DET-3", "medium", e.src_ip,
                f"{e.src_ip} was denied attempting to reach {e.dst_ip}:{e.dst_port} "
                f"({RISKY_PORTS[e.dst_port]}) via {e.vendor} - the service is being probed, "
                f"even though the attempt was blocked.",
            ))
    return findings


def detect_allow_after_deny(events: list) -> list:
    findings = []
    seen_pairs = set()
    pair_history = defaultdict(list)
    for e in sorted(events, key=lambda e: e.timestamp):
        pair = (e.src_ip, e.dst_ip)
        pair_history[pair].append(e)
    for pair, history in pair_history.items():
        had_deny = False
        for e in history:
            if e.action == "deny":
                had_deny = True
            elif e.action == "allow" and had_deny and pair not in seen_pairs:
                seen_pairs.add(pair)
                findings.append(Finding(
                    "DET-4", "high", pair[0],
                    f"{pair[0]} -> {pair[1]} was previously DENIED and was later "
                    f"ALLOWED - review for a policy change or misconfiguration that "
                    f"opened a path that was deliberately blocked.",
                ))
    return findings


def detect_network_sweep(events: list, window_minutes: int = WINDOW_MINUTES_DEFAULT,
                          threshold: int = NETWORK_SWEEP_DISTINCT_HOSTS_THRESHOLD) -> list:
    findings = []
    seen_src = set()
    for src_ip, src_events in _group_by_src(events).items():
        denied = [e for e in src_events if e.action == "deny"]
        for _, window in _within_window(denied, window_minutes):
            distinct_hosts = {e.dst_ip for e in window}
            if len(distinct_hosts) >= threshold and src_ip not in seen_src:
                seen_src.add(src_ip)
                findings.append(Finding(
                    "DET-5", "high", src_ip,
                    f"{src_ip} was denied against {len(distinct_hosts)} distinct "
                    f"destination hosts within {window_minutes} minutes - network "
                    f"sweep pattern (scanning for live hosts), not a single-target probe.",
                ))
    return findings


def run_all(events: list, window_minutes: int = WINDOW_MINUTES_DEFAULT) -> list:
    findings = []
    findings += detect_port_scan(events, window_minutes)
    findings += detect_network_sweep(events, window_minutes)
    findings += detect_high_volume_deny(events, window_minutes)
    findings += detect_risky_port_exposure_attempt(events)
    findings += detect_allow_after_deny(events)
    return findings
