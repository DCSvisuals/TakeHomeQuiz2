#!/usr/bin/env python3
"""Parse an iptables kernel log and describe the attack profiles in it.

The script reads every line, keeps the fields a firewall log actually has,
and groups the lines by source IP. The group label comes from the destination
ports and the gaps between timestamps. Run it from a terminal, or start
server.py to open the same report in a browser.

    python3 parse_iptables.py iptables.log
"""

import sys
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_LOG = HERE / "iptables.log"

MONTHS = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
}
TCP_FLAGS = {"SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"}
PORT_NAMES = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}
WEB_PORTS = {80, 443, 8080, 8443}
XEN_OUI = "00:16:3e"

USAGE = """\
Usage: python3 parse_iptables.py [log-file]

With no file, the script reads iptables.log in this folder.
"""


def unique(items):
    """Keep the first copy of each value, in the order it arrived."""
    seen = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def show(value):
    if value is None or value == "":
        return "-"
    return str(value)


def join_and(parts):
    parts = [part for part in parts if part]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return f"{parts[0]} and {parts[1]}"
    return ", ".join(parts[:-1]) + ", and " + parts[-1]


def count_word(count, singular):
    if count == 1:
        return f"1 {singular}"
    if singular.endswith("address"):
        return f"{count} {singular}es"
    return f"{count} {singular}s"


def port_label(port):
    if port is None:
        return "(none)"
    name = PORT_NAMES.get(port)
    if name:
        return f"{port} ({name})"
    return str(port)


def to_int(value):
    if value is None or value == "":
        return None
    try:
        return int(value, 10)
    except ValueError:
        return None


def ipv4_parts(ip):
    parts = str(ip).split(".")
    if len(parts) != 4:
        return None
    numbers = []
    for part in parts:
        if not part.isdigit():
            return None
        number = int(part)
        if number > 255:
            return None
        numbers.append(number)
    return numbers


def is_private(ip):
    parts = ipv4_parts(ip)
    if parts is None:
        return False
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    return False


def is_documentation(ip):
    """RFC 5737 ranges, used in examples and not assigned on the public internet."""
    parts = ipv4_parts(ip)
    if parts is None:
        return False
    if parts[:3] == [192, 0, 2]:
        return True
    if parts[:3] == [198, 51, 100]:
        return True
    if parts[:3] == [203, 0, 113]:
        return True
    return False


def action_from_prefix(prefix):
    upper = prefix.upper()
    for word in ("REJECT", "DROP", "ACCEPT", "ALLOW"):
        if word in upper:
            return word
    cleaned = prefix.strip()
    return cleaned or "LOG"


def parse_body(body):
    fields = {}
    tcp_flags = []
    df = False
    for token in body.split():
        if "=" in token:
            key, value = token.split("=", 1)
            fields[key] = value
            continue
        if token == "DF":
            df = True
            continue
        if token in TCP_FLAGS:
            tcp_flags.append(token)
    return fields, tcp_flags, df


def parse_line(line):
    """Return one normalized event, or None when the line is not an iptables log."""
    parts = line.split(None, 5)
    # month, day, time, host, program-with-colon, remainder
    if len(parts) < 6:
        return None
    month, day_text, time_text, host, program, body = parts
    if month not in MONTHS or not day_text.isdigit():
        return None
    if len(time_text) != 8 or time_text[2] != ":" or time_text[5] != ":":
        return None
    if not program.endswith(":"):
        return None
    bracket_start = body.find("[")
    bracket_end = body.find("]")
    if bracket_start == -1 or bracket_end <= bracket_start:
        return None
    prefix = body[bracket_start + 1:bracket_end].strip()
    fields, tcp_flags, df = parse_body(body[bracket_end + 1:])
    if "SRC" not in fields and "DST" not in fields and "PROTO" not in fields:
        return None
    day = int(day_text)
    date_text = f"{month} {day:02d}"
    dpt = to_int(fields.get("DPT"))
    return {
        "timestamp": f"{date_text} {time_text}",
        "date": date_text,
        "time": time_text,
        "host": host,
        "program": program[:-1],
        "prefix": prefix,
        "action": action_from_prefix(prefix),
        "in_iface": fields.get("IN", ""),
        "out_iface": fields.get("OUT", ""),
        "mac": fields.get("MAC", ""),
        "src": fields.get("SRC", ""),
        "dst": fields.get("DST", ""),
        "length": to_int(fields.get("LEN")),
        "tos": fields.get("TOS", ""),
        "prec": fields.get("PREC", ""),
        "ttl": to_int(fields.get("TTL")),
        "ip_id": to_int(fields.get("ID")),
        "df": df,
        "proto": fields.get("PROTO", ""),
        "spt": to_int(fields.get("SPT")),
        "dpt": dpt,
        "dpt_label": port_label(dpt) if dpt is not None else "",
        "window": to_int(fields.get("WINDOW")),
        "res": fields.get("RES", ""),
        "flags": tcp_flags,
        "flags_label": ", ".join(tcp_flags),
        "urgp": to_int(fields.get("URGP")),
    }


def parse_text(text):
    events = []
    skipped = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        event = parse_line(line)
        if event is None:
            skipped.append({"line_no": line_no, "text": line})
            continue
        event["line_no"] = line_no
        events.append(event)
    return events, skipped


def clock_seconds(time_text):
    hour, minute, second = time_text.split(":")
    return int(hour) * 3600 + int(minute) * 60 + int(second)


def gap_seconds(earlier, later):
    delta = clock_seconds(later) - clock_seconds(earlier)
    if delta < 0:
        delta += 24 * 3600
    return delta


def gaps(events):
    result = []
    for index in range(len(events) - 1):
        result.append(gap_seconds(events[index]["time"], events[index + 1]["time"]))
    return result


def one_value(values):
    found = unique(value for value in values if value is not None and value != "")
    if len(found) == 1:
        return found[0]
    return None


def sequential_ends(values):
    if len(values) < 2 or any(value is None for value in values):
        return None
    for index in range(len(values) - 1):
        if values[index + 1] - values[index] != 1:
            return None
    return values[0], values[-1]


def all_tcp_syn(events):
    for event in events:
        if event["proto"] != "TCP":
            return False
        flags = set(event["flags"])
        if "SYN" not in flags:
            return False
        if flags & {"ACK", "FIN", "RST"}:
            return False
    return True


def time_buckets(events):
    order = []
    counts = {}
    for event in events:
        stamp = event["time"]
        if stamp not in counts:
            order.append(stamp)
            counts[stamp] = 0
        counts[stamp] += 1
    return [(stamp, counts[stamp]) for stamp in order]


def format_gaps(deltas):
    return ", ".join(f"{delta}s" for delta in deltas)


def alternates_one_and_two(deltas):
    if len(deltas) < 2 or set(deltas) != {1, 2}:
        return False
    for index in range(len(deltas) - 1):
        if deltas[index] == deltas[index + 1]:
            return False
    return True


def attempts_phrase(count):
    if count == 1:
        return "1 connection attempt"
    return f"{count} connection attempts"


def burst_sentence(events):
    buckets = time_buckets(events)
    if len(buckets) < 2:
        return ""
    rest_counts = [count for _stamp, count in buckets[1:]]
    if len(set(rest_counts)) != 1:
        return ""
    first_count = buckets[0][1]
    rest_count = rest_counts[0]
    if first_count == rest_count:
        return (
            f"{attempts_phrase(first_count)} in each second "
            f"from {buckets[0][0]} to {buckets[-1][0]}"
        )
    return (
        f"{attempts_phrase(first_count)} at {buckets[0][0]}, then "
        f"{attempts_phrase(rest_count)} in each of the next {len(rest_counts)} seconds"
    )


def sequence_sentence(events):
    spt = sequential_ends([event["spt"] for event in events])
    ip_id = sequential_ends([event["ip_id"] for event in events])
    if spt and ip_id:
        return (
            f"Source ports {spt[0]}-{spt[1]} and IP IDs {ip_id[0]}-{ip_id[1]} "
            "both increase by 1."
        )
    if spt:
        return f"Source ports {spt[0]}-{spt[1]} increase by 1."
    if ip_id:
        return f"IP IDs {ip_id[0]}-{ip_id[1]} increase by 1."
    return ""


def shape_sentence(events):
    bits = []
    spt = one_value([event["spt"] for event in events])
    window = one_value([event["window"] for event in events])
    length = one_value([event["length"] for event in events])
    ttl = one_value([event["ttl"] for event in events])
    if spt is not None:
        bits.append(f"source port {spt}")
    if window is not None:
        bits.append(f"window {window}")
    if length is not None:
        bits.append(f"length {length}")
    if ttl is not None:
        bits.append(f"TTL {ttl}")
    if not bits:
        return ""
    return "Every probe uses " + join_and(bits) + "."


def stack_hint(events):
    ttl = one_value([event["ttl"] for event in events])
    length = one_value([event["length"] for event in events])
    window = one_value([event["window"] for event in events])
    if ttl == 128 and length == 52:
        return "TTL 128 and length 52 are consistent with a Windows host."
    if window == 29200 and length == 60 and ttl == 64:
        return "Window 29200, length 60, and TTL 64 are consistent with a Linux host."
    if window == 29200 and length == 60 and ttl is not None and ttl < 64:
        hops = 64 - ttl
        return (
            "Window 29200 and length 60 are consistent with a Linux host that started at TTL 64. "
            f"The logged TTL is {ttl}, which leaves {hops} hops between that host and this firewall."
        )
    if length == 40 and window == 1024:
        return "Length 40 and window 1024 are the packet shape used by a SYN scan tool."
    return ""


def private_note(src, dst):
    if not (ipv4_parts(src) and ipv4_parts(dst)):
        return ""
    if is_private(src) and is_private(dst) and src.split(".")[:2] != dst.split(".")[:2]:
        return (
            f"{src} is a private address. {dst} is on a different private network, "
            "so this traffic came from inside routed private address space."
        )
    if is_private(src):
        return f"{src} is a private address."
    return ""


def rule_sentence(events):
    prefixes = unique(event["prefix"] for event in events)
    actions = unique(event["action"] for event in events)
    prefix_text = join_and(prefixes)
    action_text = join_and(actions)
    return f"The firewall recorded {prefix_text}, action {action_text}."


def base_profile(events, timing, intent, kind, finding, traits, indicator_detail):
    ports = unique(event["dpt"] for event in events if event["dpt"] is not None)
    actions = unique(event["action"] for event in events)
    prefixes = unique(event["prefix"] for event in events)
    return {
        "src": events[0]["src"] or "(missing SRC)",
        "ports": ports,
        "ports_label": ", ".join(port_label(port) for port in ports) if ports else "(none)",
        "action": " / ".join(actions) if actions else "-",
        "prefixes": prefixes,
        "prefix_label": ", ".join(prefixes) if prefixes else "-",
        "timing": timing,
        "intent": intent,
        "kind": kind,
        "count": len(events),
        "first": events[0]["timestamp"],
        "last": events[-1]["timestamp"],
        "first_time": events[0]["time"],
        "last_time": events[-1]["time"],
        "finding": finding,
        "traits": traits,
        "indicator_detail": indicator_detail,
    }


def profile_scan(events, ports, deltas):
    span = sum(deltas) if deltas else 0
    bucket_text = ", ".join(
        f"{count} at {stamp}" for stamp, count in time_buckets(events)
    )
    timing = (
        f"{count_word(len(events), 'SYN probe')} to {count_word(len(ports), 'port')}, "
        f"from {events[0]['time']} to {events[-1]['time']} ({bucket_text})."
    )
    shape = shape_sentence(events)
    if shape:
        timing = f"{timing} {shape}"
    ip_ids = sequential_ends([event["ip_id"] for event in events])
    id_sentence = ""
    traits = []
    spt = one_value([event["spt"] for event in events])
    window = one_value([event["window"] for event in events])
    length = one_value([event["length"] for event in events])
    if spt is not None and window is not None and length is not None:
        traits.append({
            "type": "Packet trait",
            "value": f"SPT {spt}, WIN {window}, LEN {length}",
            "detail": f"Same fields on every probe from {events[0]['src']}.",
        })
    if ip_ids:
        id_sentence = f" IP IDs {ip_ids[0]}-{ip_ids[1]} increase by 1."
        traits.append({
            "type": "Packet trait",
            "value": f"IP ID {ip_ids[0]}-{ip_ids[1]}",
            "detail": "The identification numbers increase by 1, which fits one sender.",
        })
    intent = "Vertical TCP SYN Port Scan (Automated service discovery)"
    note = private_note(events[0]["src"], events[0]["dst"])
    if length == 40 and window == 1024 and spt is not None:
        shape_explain = (
            f"A 40-byte length and window 1024, with source port {spt} reused on every probe, "
            "is the packet shape used by a SYN scan tool."
        )
    elif shape:
        shape_explain = shape
    else:
        shape_explain = "The probes are TCP SYN packets sent to several ports in a short burst."
    finding = (
        f"{events[0]['src']} swept {count_word(len(ports), 'service port')} with TCP SYN probes "
        f"from {events[0]['time']} to {events[-1]['time']}. {rule_sentence(events)} "
        f"{shape_explain}{id_sentence}"
    )
    if note:
        finding = f"{finding} {note}"
    if span <= 1:
        span_text = "within 1 second" if span == 1 else "in the same second"
    else:
        span_text = f"across {span} seconds"
    detail = (
        f"{len(events)} SYN probes across {len(ports)} ports, action {events[0]['action']}, {span_text}."
    )
    return base_profile(events, timing, intent, "scan", finding, traits, detail)


def profile_ssh(events, deltas):
    timing = (
        f"{len(events)} continuous connections targeted strictly at the auth daemon, "
        f"spaced exactly 1-2 seconds apart ({events[0]['time']} to {events[-1]['time']})."
    )
    traits = [{
        "type": "Timing",
        "value": "Gaps of 1-2 seconds",
        "detail": f"SSH connections from {events[0]['src']}, {events[0]['time']} to {events[-1]['time']}.",
    }]
    if alternates_one_and_two(deltas):
        timing += f" The gaps alternate {format_gaps(deltas)}."
        traits[0]["value"] = "Alternating 1s and 2s"
    source_ports = [event["spt"] for event in events]
    if all(port is not None for port in source_ports) and len(set(source_ports)) == len(source_ports):
        timing += " Each line is a new SYN from a new source port."
    hint = stack_hint(events)
    ttl = one_value([event["ttl"] for event in events])
    window = one_value([event["window"] for event in events])
    length = one_value([event["length"] for event in events])
    if ttl is not None and window is not None and length is not None:
        traits.append({
            "type": "Packet trait",
            "value": f"WIN {window}, LEN {length}, TTL {ttl}",
            "detail": hint or "Packet shape of the SSH attempts.",
        })
    intent = "SSH Brute Force Attempt (Automated password spray script)"
    finding = (
        f"{events[0]['src']} opened {len(events)} new connections to TCP port 22 only, "
        f"from {events[0]['time']} to {events[-1]['time']}. {rule_sentence(events)} "
        "The spacing of 1 and 2 seconds fits an automated password-spray script."
    )
    if hint:
        finding = f"{finding} {hint}"
    finding += (
        " This iptables log does not record usernames or passwords. "
        "The SSH authentication log is the next file to check."
    )
    detail = (
        f"{len(events)} connections to port 22 (SSH), action {events[0]['action']}, "
        "gaps of 1-2 seconds."
    )
    return base_profile(events, timing, intent, "ssh_brute", finding, traits, detail)


def profile_slow(events, ports, deltas):
    port = ports[0]
    timing = (
        f"{len(events)} new connection attempts to port {port_label(port)} only. "
        f"The pause between them grows by one second each time ({format_gaps(deltas)}), "
        f"from {events[0]['time']} to {events[-1]['time']}."
    )
    traits = [{
        "type": "Timing",
        "value": format_gaps(deltas),
        "detail": f"Each pause from {events[0]['src']} is 1 second longer than the one before it.",
    }]
    hint = stack_hint(events)
    ttl = one_value([event["ttl"] for event in events])
    window = one_value([event["window"] for event in events])
    length = one_value([event["length"] for event in events])
    if hint and ttl is not None:
        traits.append({
            "type": "Packet trait",
            "value": ", ".join(
                part for part in (
                    f"TTL {ttl}" if ttl is not None else "",
                    f"LEN {length}" if length is not None else "",
                    f"WIN {window}" if window is not None else "",
                ) if part
            ),
            "detail": hint,
        })
    if port in WEB_PORTS:
        intent = "Low-and-Slow HTTP Attack (Scripted increasing delay)"
    else:
        intent = "Low-and-Slow Connection Attempt (Scripted increasing delay)"
    service = f"TCP port {port_label(port)}"
    finding = (
        f"{events[0]['src']} opened {len(events)} connections to {service}. "
        f"Each gap is one second longer than the gap before it, "
        f"from {events[0]['time']} to {events[-1]['time']}. {rule_sentence(events)}"
    )
    if hint:
        finding = f"{finding} {hint}"
    finding += (
        " The growing delay is the delivery strategy. "
        "It stays under a rate limit that only counts a steady burst."
    )
    detail = (
        f"{len(events)} connections to port {port_label(port)}, action {events[0]['action']}, "
        "gaps grow by 1 second each time."
    )
    return base_profile(events, timing, intent, "slow", finding, traits, detail)


def profile_flood(events, ports):
    port = ports[0]
    burst = burst_sentence(events)
    sequence = sequence_sentence(events)
    timing = (
        f"{len(events)} new connection attempts to port {port_label(port)} only, "
        f"from {events[0]['time']} to {events[-1]['time']}."
    )
    if burst:
        timing = f"{timing} {burst[0].upper()}{burst[1:]}."
    if sequence:
        timing = f"{timing} {sequence}"
    traits = []
    if burst:
        traits.append({
            "type": "Timing",
            "value": "Fast repeated connections",
            "detail": (
                f"{burst[0].upper()}{burst[1:]} "
                f"from {events[0]['src']}, {events[0]['time']} to {events[-1]['time']}."
            ),
        })
    spt = sequential_ends([event["spt"] for event in events])
    ip_id = sequential_ends([event["ip_id"] for event in events])
    if spt or ip_id:
        value_bits = []
        if spt:
            value_bits.append(f"SPT {spt[0]}-{spt[1]}")
        if ip_id:
            value_bits.append(f"IP ID {ip_id[0]}-{ip_id[1]}")
        traits.append({
            "type": "Packet trait",
            "value": ", ".join(value_bits),
            "detail": "The numbers increase by 1, which fits one program on one host.",
        })
    hint = stack_hint(events)
    ttl = one_value([event["ttl"] for event in events])
    window = one_value([event["window"] for event in events])
    length = one_value([event["length"] for event in events])
    if hint:
        short_bits = []
        if window is not None:
            short_bits.append(f"WIN {window}")
        if length is not None:
            short_bits.append(f"LEN {length}")
        if ttl is not None:
            short_bits.append(f"TTL {ttl}")
        traits.append({
            "type": "Packet trait",
            "value": ", ".join(short_bits) if short_bits else "Packet shape",
            "detail": hint,
        })
    intent = "HTTP Connection Flood (Automated rapid connection script)"
    finding = (
        f"{events[0]['src']} opened {len(events)} connections to TCP port {port_label(port)} "
        f"from {events[0]['time']} to {events[-1]['time']}."
    )
    if burst:
        finding = f"{finding} {burst[0].upper()}{burst[1:]}."
    if sequence:
        finding = f"{finding} {sequence}"
    finding = f"{finding} {rule_sentence(events)}"
    if hint:
        finding = f"{finding} {hint}"
    finding += " This is the pattern that lines up with a short spike in web server load."
    if burst:
        detail = (
            f"{len(events)} connections to port {port_label(port)}, action {events[0]['action']}. "
            f"{burst[0].upper()}{burst[1:]}."
        )
    else:
        detail = (
            f"{len(events)} connections to port {port_label(port)}, action {events[0]['action']}, "
            "a fast repeated rate."
        )
    return base_profile(events, timing, intent, "flood", finding, traits, detail)


def profile_other(events, ports, deltas):
    port_text = join_and(port_label(port) for port in ports) if ports else "an unknown port"
    if not deltas:
        timing = f"1 connection to {port_text} at {events[0]['time']}."
    else:
        timing = (
            f"{len(events)} connections to {port_text}, "
            f"from {events[0]['time']} to {events[-1]['time']}. "
            f"Gaps in seconds: {format_gaps(deltas)}."
        )
    intent = "Repeated activity (Ports and timing do not match a named pattern in this script)"
    finding = (
        f"{events[0]['src']} produced {count_word(len(events), 'event')} involving {port_text}. "
        f"{rule_sentence(events)} {timing} "
        "The script left this group unnamed so the row can be read from the ports and the gaps."
    )
    detail = f"{len(events)} events, action {events[0]['action']}, ports {port_text}."
    return base_profile(events, timing, intent, "other", finding, [], detail)


def classify(events):
    """Label one source address from its ports and its timestamp gaps."""
    ports = unique(event["dpt"] for event in events if event["dpt"] is not None)
    deltas = gaps(events)
    span = sum(deltas) if deltas else 0
    syn_only = all_tcp_syn(events)

    # Several ports in a short SYN burst is a vertical scan.
    if syn_only and len(ports) >= 3 and len(events) >= 3 and span <= 5:
        return profile_scan(events, ports, deltas)

    # Port 22 only, with a steady 1 or 2 second gap, is the SSH pattern.
    if syn_only and ports == [22] and len(events) >= 4 and deltas and all(delta in (1, 2) for delta in deltas):
        return profile_ssh(events, deltas)

    # A gap that grows by exactly one second each step is the slow pattern.
    grows = (
        len(deltas) >= 3
        and all(deltas[index + 1] - deltas[index] == 1 for index in range(len(deltas) - 1))
    )
    if syn_only and len(ports) == 1 and grows:
        return profile_slow(events, ports, deltas)

    # One web port, with at least one new attempt per second, is the fast pattern.
    if syn_only and len(ports) == 1 and ports[0] in WEB_PORTS and len(events) >= 8 and deltas:
        average = sum(deltas) / len(deltas)
        if average <= 1:
            return profile_flood(events, ports)

    return profile_other(events, ports, deltas)


def group_events(events):
    order = []
    groups = {}
    for event in events:
        src = event["src"] or "(missing SRC)"
        if src not in groups:
            groups[src] = []
            order.append(src)
        groups[src].append(event)
    return [groups[src] for src in order]


def split_mac(mac):
    parts = mac.split(":")
    if len(parts) < 14:
        return None
    if any(len(part) != 2 for part in parts[:14]):
        return None
    return {
        "dest": ":".join(parts[0:6]),
        "src": ":".join(parts[6:12]),
        "ethertype": "".join(parts[12:14]).upper(),
    }


def build_indicators(events, profiles):
    rows = []
    for profile in profiles:
        rows.append({
            "type": "Source IP",
            "value": profile["src"],
            "detail": profile["indicator_detail"],
        })
        rows.extend(profile["traits"])

    victims = unique(event["dst"] for event in events if event["dst"])
    hosts = unique(event["host"] for event in events if event["host"])
    for victim in victims:
        host_text = hosts[0] if len(hosts) == 1 else "the logged host"
        rows.append({
            "type": "Victim IP",
            "value": victim,
            "detail": f"Destination on the parsed events. Host name: {host_text}.",
        })

    macs = unique(event["mac"] for event in events if event["mac"])
    if len(macs) == 1:
        parsed = split_mac(macs[0])
        if parsed:
            detail = (
                f"Destination MAC {parsed['dest']} is the server. "
                f"Source MAC {parsed['src']} is the same on every line, so it is the neighboring gateway "
                "and does not identify one attacker."
            )
            if parsed["dest"].lower().startswith(XEN_OUI) or parsed["src"].lower().startswith(XEN_OUI):
                detail += " The OUI 00:16:3e is used by Xen virtual machines."
            if parsed["ethertype"] == "0800":
                detail += " EtherType 0800 means IPv4."
            rows.append({
                "type": "Ethernet",
                "value": parsed["src"],
                "detail": detail,
            })

    doc_sources = [profile["src"] for profile in profiles if is_documentation(profile["src"])]
    if doc_sources:
        rows.append({
            "type": "Address range",
            "value": ", ".join(doc_sources),
            "detail": (
                "These addresses sit in the RFC 5737 documentation ranges "
                "(198.51.100.0/24 and 203.0.113.0/24). In this sample they are the external sources. "
                "On a live network those ranges are not assigned to an organization."
            ),
        })

    port_order = unique(event["dpt"] for event in events if event["dpt"] is not None)
    for port in port_order:
        users = []
        for profile in profiles:
            subset = [
                event for event in events
                if event["src"] == profile["src"] and event["dpt"] == port
            ]
            if not subset:
                continue
            actions = unique(event["action"] for event in subset)
            users.append(f"{profile['src']} ({join_and(actions)}, {len(subset)})")
        name = PORT_NAMES.get(port, "")
        label = f"{port}/tcp ({name})" if name else f"{port}/tcp"
        rows.append({
            "type": "Destination port",
            "value": label,
            "detail": "; ".join(users),
        })

    prefixes = unique((event["prefix"], event["action"]) for event in events)
    for prefix, action in prefixes:
        count = sum(1 for event in events if event["prefix"] == prefix)
        rows.append({
            "type": "Firewall rule",
            "value": prefix,
            "detail": f"Action {action} on {count_word(count, 'event')}.",
        })
    return rows


def next_evidence(profiles):
    steps = []
    for profile in profiles:
        if profile["kind"] == "ssh_brute":
            steps.append(f"the SSH authentication log for {profile['src']}")
        elif profile["kind"] in {"slow", "flood"}:
            steps.append(f"the web access log for {profile['src']}")
        elif profile["kind"] == "scan":
            steps.append(f"whether {profile['src']} is an approved internal scanner")
    if not steps:
        return ""
    return "Next evidence to pull: " + join_and(steps) + "."


def build_findings(events, profiles, skipped):
    findings = []
    if not events:
        findings.append("No iptables events were found in this file.")
        if skipped:
            listed = ", ".join(f"line {item['line_no']}" for item in skipped[:8])
            findings.append(f"Lines that were not iptables events: {listed}.")
        return findings

    sources = join_and(profile["src"] for profile in profiles)
    victims = unique(event["dst"] for event in events if event["dst"])
    hosts = unique(event["host"] for event in events if event["host"])
    victim_text = join_and(victims) if victims else "an unknown destination"
    host_text = hosts[0] if len(hosts) == 1 else join_and(hosts)
    findings.append(
        f"{count_word(len(events), 'iptables event')} were parsed, "
        f"from {events[0]['timestamp']} to {events[-1]['timestamp']}. "
        f"They come from {count_word(len(profiles), 'source address')}: {sources}. "
        f"Every parsed event is addressed to {victim_text} on {host_text}."
    )
    for profile in profiles:
        findings.append(profile["finding"])

    macs = unique(event["mac"] for event in events if event["mac"])
    if len(macs) == 1:
        parsed = split_mac(macs[0])
        if parsed:
            mac_finding = (
                "The Ethernet header is the same on every line. "
                f"Destination MAC {parsed['dest']} is the server interface. "
                f"Source MAC {parsed['src']} is the next device upstream. "
                "Every source shares that MAC, so it does not identify the attacker."
            )
            if parsed["dest"].lower().startswith(XEN_OUI):
                mac_finding += " Both addresses use the Xen OUI 00:16:3e."
            if parsed["ethertype"] == "0800":
                mac_finding += " EtherType 0800 is IPv4."
            findings.append(mac_finding)

    doc_sources = [profile["src"] for profile in profiles if is_documentation(profile["src"])]
    if doc_sources:
        findings.append(
            f"{join_and(doc_sources)} sit in ranges reserved for documentation by RFC 5737. "
            "In this sample they are the external source addresses. "
            "On a production network, packets from 192.0.2.0/24, 198.51.100.0/24, or 203.0.113.0/24 "
            "are worth a second look, because those ranges are not given to real organizations."
        )

    limit = (
        "The firewall sees layers 3 and 4. These lines show the time, the source, the destination port, "
        "and the rule that matched. They do not show SSH passwords, HTTP URLs, or exploit strings."
    )
    evidence = next_evidence(profiles)
    findings.append(f"{limit} {evidence}".strip())

    if skipped:
        pieces = []
        for item in skipped[:6]:
            snippet = item["text"].strip().rstrip(".")
            if len(snippet) > 80:
                snippet = snippet[:80].rstrip() + "..."
            pieces.append(f"line {item['line_no']} ({snippet})")
        listed = "; ".join(pieces)
        extra = ""
        if (
            len(events) == 42
            and len(skipped) == 1
            and skipped[0]["text"].lower().startswith("use code with caution")
        ):
            extra = " The quiz describes a 42-line sample. This skipped line is the extra line in the file."
        findings.append(
            f"{count_word(len(skipped), 'line')} in the file did not parse as an iptables event: {listed}.{extra}"
        )
    return findings


def build_summary(events):
    if not events:
        return {
            "host": "",
            "victim": "",
            "first": "",
            "last": "",
            "iface": "",
            "date": "",
        }
    ifaces = unique(event["in_iface"] for event in events if event["in_iface"])
    hosts = unique(event["host"] for event in events if event["host"])
    victims = unique(event["dst"] for event in events if event["dst"])
    dates = unique(event["date"] for event in events if event["date"])
    return {
        "host": hosts[0] if len(hosts) == 1 else "",
        "victim": victims[0] if len(victims) == 1 else "",
        "first": events[0]["timestamp"],
        "last": events[-1]["timestamp"],
        "iface": ifaces[0] if len(ifaces) == 1 else "",
        "date": dates[0] if len(dates) == 1 else "",
    }


def analyze(text, source_name):
    events, skipped = parse_text(text)
    profiles = [classify(group) for group in group_events(events)]
    return {
        "source_name": source_name,
        "parsed_count": len(events),
        "skipped": skipped,
        "events": events,
        "profiles": profiles,
        "indicators": build_indicators(events, profiles),
        "findings": build_findings(events, profiles, skipped),
        "summary": build_summary(events),
    }


def wrap(text, indent="  "):
    lines = []
    for paragraph in text.split("\n"):
        filled = textwrap.fill(
            paragraph,
            width=78,
            initial_indent=indent,
            subsequent_indent=indent,
            break_on_hyphens=False,
        )
        lines.append(filled if filled else indent.rstrip())
    return "\n".join(lines)


def render_text(report):
    summary = report["summary"]
    lines = [
        "CST8808 Quiz 2",
        "iptables log parser",
        "",
        f"Source: {report['source_name']}",
        f"Parsed events: {report['parsed_count']}",
    ]
    if report["skipped"]:
        for item in report["skipped"]:
            lines.append(f"Skipped line {item['line_no']}: {item['text']}")
    else:
        lines.append("Skipped lines: 0")
    if summary.get("host"):
        lines.append(f"Host: {summary['host']}")
    if summary.get("victim"):
        lines.append(f"Victim: {summary['victim']}")
    if summary.get("iface"):
        lines.append(f"Interface: {summary['iface']}")
    if summary.get("first"):
        lines.append(f"Time span: {summary['first']} to {summary['last']}")
    lines.append("")
    lines.append("ATTACK PROFILES")
    lines.append("The handout columns are Attacker IP, Target Port(s), Firewall Status,")
    lines.append("Traffic Sequence & Timing Metrics, and Diagnosed Attack Intent / Method.")
    lines.append("")
    if not report["profiles"]:
        lines.append("No profiles. The file had no iptables events.")
    for index, profile in enumerate(report["profiles"], start=1):
        lines.append(f"{index}. Attacker IP Address: {profile['src']}")
        lines.append(f"   Target Port(s) (DPT): {profile['ports_label']}")
        lines.append(f"   Firewall Status (Action): {profile['action']}")
        lines.append(f"   Rule prefix: {profile['prefix_label']}")
        lines.append("   Traffic Sequence & Timing Metrics:")
        lines.append(wrap(profile["timing"], "     "))
        lines.append("   Diagnosed Attack Intent / Method:")
        lines.append(wrap(profile["intent"], "     "))
        lines.append("")
    lines.append("INDICATORS OF COMPROMISE")
    if not report["indicators"]:
        lines.append("None.")
    for index, row in enumerate(report["indicators"], start=1):
        lines.append(f"{index}. [{row['type']}] {row['value']}")
        lines.append(wrap(row["detail"]))
    lines.append("")
    lines.append("ANALYSIS")
    for index, finding in enumerate(report["findings"], start=1):
        lines.append(f"{index}.")
        lines.append(wrap(finding))
        lines.append("")
    lines.append("NORMALIZED LOG")
    lines.append(
        "Line  Time      Action  Source           Dest port          SPT    Flags  TTL  LEN   WIN  IP ID  Prefix"
    )
    for event in report["events"]:
        lines.append(
            f"{event['line_no']:>4}  "
            f"{event['time']:<8}  "
            f"{show(event['action']):<6}  "
            f"{show(event['src']):<15}  "
            f"{show(event['dpt_label']):<17}  "
            f"{show(event['spt']):>5}  "
            f"{show(event['flags_label']):<5}  "
            f"{show(event['ttl']):>3}  "
            f"{show(event['length']):>4}  "
            f"{show(event['window']):>5}  "
            f"{show(event['ip_id']):>6}  "
            f"{event['prefix']}"
        )
    lines.append("")
    lines.append("Action is read from the log prefix.")
    lines.append("IPTABLES_SCAN_DROP is DROP. IPTABLES_ACCEPT is ACCEPT. IPTABLES_HTTP_ALLOW is ALLOW.")
    lines.append("")
    return "\n".join(lines)


def configure_stdio():
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def main(argv):
    configure_stdio()
    if len(argv) > 2 or (len(argv) == 2 and argv[1] in {"-h", "--help"}):
        print(USAGE, end="")
        return 0 if len(argv) == 2 else 1
    path = Path(argv[1]) if len(argv) == 2 else DEFAULT_LOG
    if not path.is_file():
        print(f"Log file not found: {path}", file=sys.stderr)
        print(USAGE, end="", file=sys.stderr)
        return 1
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"Could not read {path}: {exc}", file=sys.stderr)
        return 1
    report = analyze(text, path.name)
    sys.stdout.write(render_text(report))
    if report["parsed_count"] == 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
