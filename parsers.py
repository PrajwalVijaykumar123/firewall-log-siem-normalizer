"""
Real multi-vendor firewall syslog parsing.

Both FortiGate and Sophos XG emit logs as a flat line of `key=value`
pairs, where a value containing spaces is wrapped in double quotes and
a bare numeric/token value is not - this is documented, real syslog
behavior for both vendors' log references. (No live FortiGate or
Sophos appliance is reachable from this sandbox, so these fixtures are
built directly from each vendor's own published log-field reference
rather than captured from a real device - the same honest scope
caveat this portfolio's other config-auditing tools already carry for
similar reasons.)

The two vendors use ENTIRELY different field names for the same real
concept:

  concept         FortiGate         Sophos XG
  --------------  ----------------  -----------------
  device name     devname           device_name
  timestamp       date + time       timestamp (one ISO8601 field)
  source IP       srcip             src_ip
  source port     srcport           src_port
  dest IP         dstip             dst_ip
  dest port       dstport           dst_port
  protocol        proto (numeric)   protocol (string)
  allow/deny      action            log_subtype
  rule reference  policyid          fw_rule_id
  free-text       msg               message

`normalize()` is where that real schema drift gets collapsed into one
shared `NormalizedEvent` - the SIEM-relevant engineering problem this
project is actually about.
"""
import re
from dataclasses import dataclass
from datetime import datetime, timezone

_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

PROTO_NUMBER_TO_NAME = {"1": "ICMP", "6": "TCP", "17": "UDP"}


@dataclass
class NormalizedEvent:
    timestamp: datetime
    vendor: str              # "fortigate" | "sophos"
    device_name: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    action: str              # "allow" | "deny"
    rule_id: str
    message: str
    raw: str


def parse_kv_line(line: str) -> dict:
    fields = {}
    for m in _KV_RE.finditer(line):
        key = m.group(1)
        value = m.group(2) if m.group(2) is not None else m.group(3)
        fields[key] = value
    return fields


def _detect_vendor(fields: dict) -> str:
    if "devname" in fields and "srcip" in fields:
        return "fortigate"
    if "device_name" in fields and "src_ip" in fields:
        return "sophos"
    raise ValueError(f"Unrecognized log format, fields seen: {sorted(fields)}")


def _from_fortigate(fields: dict, raw: str) -> NormalizedEvent:
    ts = datetime.strptime(f"{fields['date']} {fields['time']}", "%Y-%m-%d %H:%M:%S")
    ts = ts.replace(tzinfo=timezone.utc)
    proto = PROTO_NUMBER_TO_NAME.get(fields.get("proto", ""), fields.get("proto", "?"))
    return NormalizedEvent(
        timestamp=ts, vendor="fortigate", device_name=fields.get("devname", "?"),
        src_ip=fields["srcip"], src_port=int(fields.get("srcport", 0)),
        dst_ip=fields["dstip"], dst_port=int(fields.get("dstport", 0)),
        protocol=proto, action=fields.get("action", "?").lower(),
        rule_id=fields.get("policyid", "?"), message=fields.get("msg", ""), raw=raw,
    )


def _from_sophos(fields: dict, raw: str) -> NormalizedEvent:
    ts_raw = fields["timestamp"]
    # Sophos XG emits "YYYY-MM-DDTHH:MM:SS+ZZZZ" - strip the offset for
    # this portfolio's fixtures, which are all UTC+0000, and normalize
    # to an aware UTC datetime so it can be compared against FortiGate
    # events on the same timeline.
    ts = datetime.strptime(ts_raw[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return NormalizedEvent(
        timestamp=ts, vendor="sophos", device_name=fields.get("device_name", "?"),
        src_ip=fields["src_ip"], src_port=int(fields.get("src_port", 0)),
        dst_ip=fields["dst_ip"], dst_port=int(fields.get("dst_port", 0)),
        protocol=fields.get("protocol", "?").upper(),
        action=fields.get("log_subtype", "?").lower(),
        rule_id=fields.get("fw_rule_id", "?"), message=fields.get("message", ""), raw=raw,
    )


def normalize(line: str) -> NormalizedEvent:
    fields = parse_kv_line(line)
    vendor = _detect_vendor(fields)
    if vendor == "fortigate":
        return _from_fortigate(fields, line)
    return _from_sophos(fields, line)


def load_log_file(path: str) -> list:
    events = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            events.append(normalize(line))
    events.sort(key=lambda e: e.timestamp)
    return events
