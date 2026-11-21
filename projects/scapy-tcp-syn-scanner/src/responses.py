"""Match and interpret TCP and ICMP replies to scanner probes."""

from scapy.layers.inet import ICMP, IP, TCP


def matches_tcp_reply(probe, reply):
    """Accept only TCP replies matching this probe's addresses, ports, and ACK."""
    if not probe.haslayer(IP) or not probe.haslayer(TCP):
        return False

    if not reply.haslayer(IP) or not reply.haslayer(TCP):
        return False

    if reply[IP].src != probe[IP].dst:
        return False

    if reply[IP].dst != probe[IP].src:
        return False

    if reply[TCP].sport != probe[TCP].dport:
        return False

    if reply[TCP].dport != probe[TCP].sport:
        return False

    flags = int(reply[TCP].flags)
    ack_flag_is_set = bool(flags & 0x10)

    if ack_flag_is_set:
        expected_ack = (int(probe[TCP].seq) + 1) & 0xFFFFFFFF
        if int(reply[TCP].ack) != expected_ack:
            return False

    return True


def classify_tcp_reply(reply):
    """Classify a TCP reply as open, closed, or unclassified."""
    if not reply.haslayer(TCP):
        return "not-tcp"

    flags = int(reply[TCP].flags)

    # A SYN/ACK response indicates that the port accepted the SYN probe.
    if (flags & 0x12) == 0x12:
        return "open"

    # A reset response indicates that the port is closed.
    if flags & 0x04:
        return "closed"

    return "unclassified"


def no_response_action(attempts_sent, maximum_attempts):
    """Return whether to retry or report that no response was received."""
    if attempts_sent < maximum_attempts:
        return "retry"

    return "filtered-or-no-response"


def matches_icmp_unreachable(probe, reply):
    """Check whether an ICMP unreachable message quotes this SYN probe."""
    if not probe.haslayer(IP) or not probe.haslayer(TCP):
        return False

    if not reply.haslayer(IP) or not reply.haslayer(ICMP):
        return False

    if reply[ICMP].type != 3:
        return False

    quoted_ip = reply[ICMP].payload.getlayer(IP)
    if quoted_ip is None or not quoted_ip.haslayer(TCP):
        return False

    quoted_tcp = quoted_ip[TCP]

    return (
        quoted_ip.src == probe[IP].src
        and quoted_ip.dst == probe[IP].dst
        and quoted_tcp.sport == probe[TCP].sport
        and quoted_tcp.dport == probe[TCP].dport
    )


def interpret_reply(probe, reply):
    """Return a normalized event for a matching reply, or None if unrelated."""
    if matches_tcp_reply(probe, reply):
        return {
            "kind": "tcp",
            "status": classify_tcp_reply(reply),
            "flags": str(reply[TCP].flags),
        }

    if matches_icmp_unreachable(probe, reply):
        icmp = reply[ICMP]
        return {
            "kind": "icmp",
            "status": "icmp-unreachable",
            "icmp_type": int(icmp.type),
            "icmp_code": int(icmp.code),
            "responder_ip": reply[IP].src,
        }

    return None