#!/usr/bin/env python3
"""
firewall-log-siem-normalizer: parses real FortiGate and Sophos XG
key=value syslog lines into one normalized event schema, then runs 5
SOC-style correlation detections across both vendors at once.
"""
import argparse
import json
import sys

from parsers import load_log_file
from detections import run_all, WINDOW_MINUTES_DEFAULT

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def render_console(events, findings):
    lines = [f"Parsed {len(events)} event(s) from {len({e.vendor for e in events})} vendor(s)."]
    lines.append("")
    if not findings:
        lines.append("No correlation findings.")
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity), reverse=True):
        lines.append(f"[{f.severity.upper():<6}] {f.detection_id} src={f.src_ip}: {f.message}")
    return "\n".join(lines)


def to_json(findings):
    return [
        {"detection_id": f.detection_id, "severity": f.severity, "src_ip": f.src_ip, "message": f.message}
        for f in findings
    ]


def main():
    ap = argparse.ArgumentParser(description="Normalize and correlate multi-vendor firewall logs")
    ap.add_argument("log_files", nargs="+", help="One or more firewall syslog files (FortiGate and/or Sophos XG)")
    ap.add_argument("--window-minutes", type=int, default=WINDOW_MINUTES_DEFAULT)
    ap.add_argument("--json", metavar="PATH")
    ap.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "any"], default=None)
    args = ap.parse_args()

    events = []
    for path in args.log_files:
        events.extend(load_log_file(path))
    events.sort(key=lambda e: e.timestamp)

    findings = run_all(events, args.window_minutes)

    print(render_console(events, findings))

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(to_json(findings), fh, indent=2)

    if args.fail_on:
        trigger_idx = 0 if args.fail_on == "any" else SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) >= trigger_idx for f in findings):
            sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
