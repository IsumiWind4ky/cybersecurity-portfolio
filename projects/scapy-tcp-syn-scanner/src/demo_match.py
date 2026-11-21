"""Demonstrate TCP and ICMP reply matching without sending packets."""

from scapy.layers.inet import ICMP, IP, TCP

from probes import build_syn_probe
from responses import (
    classify_tcp_reply,
    interpret_reply,
    matches_icmp_unreachable,
    matches_tcp_reply,
    no_response_action,
)


TARGET_IP = "172.28.70.10"
SOURCE_IP = "172.28.70.2"


def main():
    """Build sample packets and print how the scanner interprets them."""
    probe = build_syn_probe(
        TARGET_IP,
        source_port=40000,
        destination_port=22,
        source_ip=SOURCE_IP,
    )
    expected_ack = (int(probe[TCP].seq) + 1) & 0xFFFFFFFF

    matching_reply = (
        IP(src=TARGET_IP, dst=SOURCE_IP)
        / TCP(
            sport=22,
            dport=40000,
            flags="SA",
            ack=expected_ack,
        )
    )

    unrelated_reply = (
        IP(src=TARGET_IP, dst=SOURCE_IP)
        / TCP(
            sport=22,
            dport=40001,
            flags="SA",
            ack=expected_ack,
        )
    )

    closed_reply = (
        IP(src=TARGET_IP, dst=SOURCE_IP)
        / TCP(
            sport=22,
            dport=40000,
            flags="RA",
            ack=expected_ack,
        )
    )

    print("Matching TCP reply:", matches_tcp_reply(probe, matching_reply))
    print("Unrelated TCP reply:", matches_tcp_reply(probe, unrelated_reply))
    print("SYN/ACK classification:", classify_tcp_reply(matching_reply))
    print("RST classification:", classify_tcp_reply(closed_reply))
    print("Action after the first unanswered attempt:", no_response_action(1, 2))
    print("Action after the second unanswered attempt:", no_response_action(2, 2))

    icmp_reply = (
        IP(src=TARGET_IP, dst=SOURCE_IP)
        / ICMP(type=3, code=3)
        / probe.copy()
    )

    other_probe = build_syn_probe(
        TARGET_IP,
        source_port=40001,
        destination_port=80,
        source_ip=SOURCE_IP,
    )
    unrelated_icmp = (
        IP(src=TARGET_IP, dst=SOURCE_IP)
        / ICMP(type=3, code=3)
        / other_probe
    )

    print(
        "ICMP quoting this probe:",
        matches_icmp_unreachable(probe, icmp_reply),
    )
    print(
        "ICMP quoting a different probe:",
        matches_icmp_unreachable(probe, unrelated_icmp),
    )

    print("Interpretation of SYN/ACK:", interpret_reply(probe, matching_reply))
    print("Interpretation of unrelated reply:", interpret_reply(probe, unrelated_reply))
    print("Interpretation of ICMP reply:", interpret_reply(probe, icmp_reply))


if __name__ == "__main__":
    main()