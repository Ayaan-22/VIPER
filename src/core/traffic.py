"""Address-family independent packet context shared by capture and detectors."""
from __future__ import annotations

import math
import time
from contextvars import ContextVar
from dataclasses import dataclass
from decimal import Decimal
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, _ICMPv6

current_event = ContextVar("viper_event", default=None)


def network_layer(packet):
    if packet.haslayer(IP):
        return packet[IP]
    if packet.haslayer(IPv6):
        return packet[IPv6]
    return None


def syn_attempt(packet):
    if not packet.haslayer(TCP):
        return False
    flags = int(packet[TCP].flags)
    return bool(flags & 0x02) and not flags & 0x3D


def protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(IPv6) and packet.haslayer(_ICMPv6, _subclass=True):
        return "ICMPV6"
    if packet.haslayer("ARP"):
        return "ARP"
    return "OTHER"


def packet_timestamp(packet):
    value = getattr(packet, "time", None)
    if isinstance(value, (int, float, Decimal)):
        value = float(value)
        if math.isfinite(value) and value >= 0:
            return value
    return None


def event_time(packet):
    event = current_event.get()
    if event is not None:
        return event.timestamp
    captured = packet_timestamp(packet)
    return time.monotonic() if captured is None else captured


def evidence(packet):
    net = network_layer(packet)
    port = None
    if packet.haslayer(TCP):
        port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        port = int(packet[UDP].dport)
    return {"dst_ip": net.dst if net is not None else None, "dst_port": port,
            "protocol": protocol(packet), "address_family": 6 if packet.haslayer(IPv6) else 4}


@dataclass(frozen=True)
class PacketEvent:
    packet: object
    timestamp: float
    received_at: float
    sequence: int
