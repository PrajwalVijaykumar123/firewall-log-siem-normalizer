# Firewall Log SIEM Normalizer

Parses real **FortiGate** and **Sophos XG** key=value firewall syslog lines into one normalized event schema, then runs **5 SOC-style correlation detections** across both vendors at once - the same normalize-then-correlate pattern a real SIEM pipeline uses to make multi-vendor log ingestion useful instead of just a pile of differently-shaped text.

## Why Normalizing Two Vendors' Logs Is the Real Problem

FortiGate and Sophos XG both emit firewall logs as `key=value` syslog lines, but they use **completely different field names** for the same concepts:

| Concept | FortiGate | Sophos XG |
|---|---|---|
| Device name | `devname` | `device_name` |
| Timestamp | `date` + `time` (two fields) | `timestamp` (one ISO8601 field) |
| Source IP/port | `srcip` / `srcport` | `src_ip` / `src_port` |
| Dest IP/port | `dstip` / `dstport` | `dst_ip` / `dst_port` |
| Protocol | `proto` (numeric: `6`, `17`, `1`) | `protocol` (string: `"TCP"`) |
| Allow/deny | `action` (`"accept"`/`"deny"`) | `log_subtype` (`"Allow"`/`"Deny"`) |
| Rule reference | `policyid` | `fw_rule_id` |

A security team running both vendors (common after an acquisition, or across different sites) can't write one detection rule against two different field layouts - someone has to normalize first. That's the actual engineering content of this project: `parsers.py` collapses both real schemas into one `NormalizedEvent`, and every detection in `detections.py` then runs identically regardless of which vendor produced the underlying log line. The test suite specifically proves a detection (`DET-4`) sourced entirely from a Sophos log and another (`DET-1`) sourced entirely from a FortiGate log both come out of the exact same `run_all()` call against the combined stream.

**Scope note:** no live FortiGate or Sophos appliance is reachable from this sandbox, so the fixtures are built directly from each vendor's own published log-field reference rather than captured from a real device - the parser targets the documented field names and syntax, not a guessed format.

## What This Project Detects

| ID | Detection | Severity |
|---|---|---|
| DET-1 | A source IP was denied against ≥5 distinct destination ports within the time window (port scan) | High |
| DET-2 | A source IP generated ≥10 denied connection attempts within the time window (automated-tool volume) | Medium |
| DET-3 | A denied connection attempt targeted a well-known risky port (SSH, Telnet, SMB, RDP, MySQL, PostgreSQL, MSSQL, FTP) | Medium |
| DET-4 | A source->destination pair was previously **denied** and later **allowed** - a policy-change or misconfiguration anomaly | High |
| DET-5 | A source IP was denied against ≥4 distinct destination hosts within the time window (network sweep, not a single-target probe) | High |

The time-window logic is an explicitly simple forward scan grouped per source IP (documented in `detections.py`'s module docstring) - the same kind of stated scope limitation this portfolio's `soc-alert-triage-engine` already carries for its own clustering, rather than implying a more sophisticated sliding-window or graph-based correlation engine than what's actually implemented.

## Relationship to This Portfolio's Other Firewall/VPN Tools

- **`firewall-rule-auditor`** and **`vpn-config-auditor`** audit static **configuration** (rule files, VPN configs) for misconfigurations before or independent of any traffic.
- **This tool** audits **live traffic logs** after the fact - it answers "what actually happened on the wire," which a config auditor structurally cannot (a perfectly-configured firewall can still log a port scan against it). The three tools cover three different moments: before deployment (config), and after deployment (this tool, from logs).

## Tech Stack

- Python 3.11, standard library only (`re`, `dataclasses`, `argparse`, `json`, `datetime`, `collections`) - no third-party dependencies

## Setup

```bash
python3 scanner.py fortigate.log
python3 scanner.py fortigate.log sophos.log --window-minutes 10 --json report.json --fail-on high
```

Multiple log files (any mix of vendors) can be passed at once - they're parsed, normalized, merged, and sorted by timestamp before any detection runs.

## Testing

`test_fixtures/` has a benign pair (one FortiGate log, one Sophos log, ordinary allowed traffic, zero risky activity) and a malicious pair exercising all 5 detections: a FortiGate-logged attacker port-scanning and network-sweeping one source IP, and a Sophos-logged source IP that gets denied and then allowed to the same destination 15 minutes later. `run_test.sh` runs the real scanner against both:

```bash
sh test_fixtures/run_test.sh
```

9 assertions, all passing - including one that specifically confirms `DET-1` (FortiGate-sourced) and `DET-4` (Sophos-sourced) both fire correctly out of the same combined, cross-vendor run.

## Architecture

```
scanner.py (CLI: console + JSON report, --fail-on exit codes)
        |
        v
parsers.py: real key=value tokenizer + per-vendor field mapping
    -> one shared NormalizedEvent, sorted by timestamp
        |
        v
detections.py: 5 correlation detections, vendor-agnostic from this point on
        |
        v
Console report (grouped by severity) + optional JSON; exit code reflects --fail-on
```

## Project Structure

```
firewall-log-siem-normalizer/
├── scanner.py                            # CLI
├── parsers.py                            # Real FortiGate + Sophos XG kv parsers -> NormalizedEvent
├── detections.py                         # 5 cross-vendor correlation detections
└── test_fixtures/
    ├── fortigate_benign.log
    ├── sophos_benign.log
    ├── fortigate_malicious.log
    ├── sophos_malicious.log
    └── run_test.sh                       # Runs scanner.py against both pairs
```

## What I Learned

- The schema drift between two vendors doing the exact same job (a stateful firewall logging allow/deny decisions) is larger than it looks from the outside - even the allow/deny concept itself is spelled as a dedicated `action` field on one vendor and overloaded onto a `log_subtype` field (which also carries non-allow/deny values in Sophos's real schema) on the other. Normalizing that correctly, rather than assuming "every vendor basically has an action field," was the actual point of this project, the same lesson `bsi-compliance-aggregator` already learned the hard way with `iso27001_ref` vs `iso_ref` across this portfolio's own tools.
- Writing `DET-4` (allow-after-deny) required thinking about state across the *whole* event history per source/destination pair, not a time window - unlike the other four detections, which are all time-boxed, a policy change that un-blocks something could legitimately happen hours or days after the original deny, so this detection deliberately has no window parameter at all.
- Designing one malicious fixture pair to trip all 5 detections simultaneously (rather than 5 separate fixture files) meant working out the exact overlap up front: the FortiGate side's single scanning attacker needed to hit risky ports AND enough distinct ports AND enough distinct hosts AND enough total volume all within the same event set, while the Sophos side's allow-after-deny anomaly needed to be a genuinely separate, unrelated source IP so it wouldn't accidentally get folded into the FortiGate attacker's own counts.

## Next Steps

- Add Palo Alto and Cisco ASA as additional vendor parsers - both also use real, documented key=value or CEF-style formats, and the `NormalizedEvent` schema this project already defines wouldn't need to change at all, only `parsers.py`'s per-vendor mapping.
- A real sliding-window implementation (a deque-based or interval-tree approach) to replace the current documented simplification, so overlapping windows don't ever double-count or under-count a borderline burst of activity at a window boundary.
- Feed this tool's findings into `bsi-compliance-aggregator` as a sixth adapter - live traffic-based intrusion indicators map naturally onto BSI's `NET.3.2` Baustein, already used by two other tools in this portfolio for firewall-related findings.
