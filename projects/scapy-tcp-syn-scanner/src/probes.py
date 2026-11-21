"""Construct TCP SYN probe packets for the scanner."""

from scapy.layers.inet import IP, TCP


def build_syn_probe(target, source_port, destination_port, source_ip=None):
    """Build, but do not send, an IPv4 TCP SYN packet."""
    if source_ip is None:
        ip_layer = IP(dst=target)
    else:
        ip_layer = IP(src=source_ip, dst=target)

    return ip_layer / TCP(
        sport=source_port,
        dport=destination_port,
        flags="S",
    )