"""Execute rate-limited SYN probes within the validated scope."""

import json
import time

from scapy.all import conf, get_if_list
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send, sr

from probes import build_syn_probe
from responses import interpret_reply, no_response_action


def get_source_ip(interface, target):
    """Verify the route uses the assigned interface and return its source IP."""
    if interface not in get_if_list():
        raise RuntimeError(
            f"The scope interface {interface!r} does not exist; no packets were sent."
        )

    try:
        route_interface, source_ip, _gateway = conf.route.route(target)
    except Exception as exc:
        raise RuntimeError(
            f"Could not look up a route to {target!r}; no packets were sent: {exc}"
        ) from exc

    route_interface_name = getattr(
        route_interface,
        "name",
        str(route_interface),
    )

    if route_interface_name != interface:
        raise RuntimeError(
            f"The route to {target} uses {route_interface_name!r}, which does not "
            f"match the scope interface {interface!r}; no packets were sent."
        )

    if not source_ip or source_ip == "0.0.0.0":
        raise RuntimeError(
            f"The route through {interface!r} has no valid source IP; "
            "no packets were sent."
        )

    return source_ip


class ProbeRateLimiter:
    """Keep probe sends within the configured probes-per-second limit."""

    def __init__(self, maximum_rate_pps):
        if maximum_rate_pps < 1 or maximum_rate_pps > 20:
            raise ValueError("The probe rate must be between 1 and 20 probes per second.")

        self.minimum_interval = 1.0 / maximum_rate_pps
        self.last_probe_time = None

    def wait(self):
        """Wait until the minimum interval since the previous probe has elapsed."""
        if self.last_probe_time is not None:
            elapsed = time.monotonic() - self.last_probe_time
            remaining = self.minimum_interval - elapsed

            if remaining > 0:
                time.sleep(remaining)

        self.last_probe_time = time.monotonic()


def send_one_attempt(probe, timeout, rate_limiter):
    """Send one SYN probe, collect matching replies, and reset an open connection."""
    rate_limiter.wait()

    answered, _unanswered = sr(
        probe,
        timeout=timeout,
        retry=0,
        multi=True,
        verbose=False,
    )

    events = []
    seen_events = set()
    reset_sent = False

    for _sent_packet, reply in answered:
        event = interpret_reply(probe, reply)
        if event is None:
            continue

        # Ignore duplicate copies of the same response.
        event_key = json.dumps(event, sort_keys=True)
        if event_key in seen_events:
            continue

        seen_events.add(event_key)
        events.append(event)

        if event["status"] == "open" and not reset_sent:
            rate_limiter.wait()

            reset_packet = (
                IP(src=probe[IP].src, dst=probe[IP].dst)
                / TCP(
                    sport=probe[TCP].sport,
                    dport=probe[TCP].dport,
                    flags="R",
                    seq=reply[TCP].ack,
                )
            )

            send(reset_packet, verbose=False)
            reset_sent = True

    return events


def scan_one_port(scope, port, source_ip, rate_limiter):
    """Scan one allowed port, retrying only when the probe receives no reply."""
    if port not in scope["ports"]:
        raise ValueError(f"Port {port} is not in the scope allow-list.")

    maximum_attempts = scope["maximum_attempts"]
    if type(maximum_attempts) is not int or not 1 <= maximum_attempts <= 2:
        raise ValueError("The scope must allow either one or two attempts.")

    port_index = scope["ports"].index(port)
    source_port = 40000 + port_index

    probe = build_syn_probe(
        scope["target"],
        source_port,
        port,
        source_ip,
    )

    all_events = []
    attempts_used = 0

    for attempt_number in range(1, maximum_attempts + 1):
        attempts_used = attempt_number
        events = send_one_attempt(
            probe,
            scope["timeout_seconds"],
            rate_limiter,
        )
        all_events.extend(events)

        if events:
            break

        action = no_response_action(attempt_number, maximum_attempts)
        if action != "retry":
            break

    statuses = {event["status"] for event in all_events}

    if not statuses:
        status = "filtered-or-no-response"
    elif len(statuses) == 1:
        status = next(iter(statuses))
    else:
        status = "conflicting-responses"

    return {
        "port": port,
        "status": status,
        "attempts": attempts_used,
        "responses": all_events,
    }


def scan_scope(scope):
    """Scan every port listed in the validated scope, in listed order."""
    interface = scope["interface"]
    source_ip = get_source_ip(interface, scope["target"])
    rate_limiter = ProbeRateLimiter(scope["maximum_rate_pps"])

    return [
        scan_one_port(scope, port, source_ip, rate_limiter)
        for port in scope["ports"]
    ]