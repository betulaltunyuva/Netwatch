from collections import Counter, deque
from datetime import datetime


def get_sample_summary():
    return {
        "last_updated": "2026-03-26 14:35:12",
        "total_packets": 128,
        "tcp_packets": 74,
        "udp_packets": 38,
        "icmp_packets": 16,
        "alerts": [
            "High TCP traffic detected from 192.168.1.10",
            "Multiple UDP packets observed on port 53",
            "ICMP activity is within normal range",
        ],
        "top_sources": [
            {"ip": "192.168.1.10", "packets": 42},
            {"ip": "192.168.1.15", "packets": 31},
            {"ip": "192.168.1.22", "packets": 24},
            {"ip": "192.168.1.8", "packets": 18},
            {"ip": "192.168.1.100", "packets": 13},
        ],
        "top_ports": [
            {"port": 80, "packets": 35},
            {"port": 443, "packets": 29},
            {"port": 53, "packets": 21},
            {"port": 22, "packets": 12},
            {"port": 8080, "packets": 9},
        ],
        "recent_packets": [
            {
                "time": "14:32:01",
                "source": "192.168.1.10",
                "destination": "192.168.1.1",
                "protocol": "TCP",
                "length": 60,
            },
            {
                "time": "14:32:03",
                "source": "192.168.1.15",
                "destination": "8.8.8.8",
                "protocol": "UDP",
                "length": 74,
            },
            {
                "time": "14:32:05",
                "source": "192.168.1.22",
                "destination": "192.168.1.1",
                "protocol": "ICMP",
                "length": 98,
            },
            {
                "time": "14:32:08",
                "source": "192.168.1.8",
                "destination": "142.250.185.14",
                "protocol": "TCP",
                "length": 52,
            },
            {
                "time": "14:32:11",
                "source": "192.168.1.100",
                "destination": "192.168.1.1",
                "protocol": "UDP",
                "length": 67,
            },
        ],
    }


def get_live_summary(packet_count=50):
    """
    Capture live packets with Scapy and build dashboard summary data.
    """
    try:
        from scapy.all import ICMP, IP, TCP, UDP, sniff
    except ImportError:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "alerts": ["Scapy is not installed. Live capture is unavailable."],
            "top_sources": [],
            "top_ports": [],
            "recent_packets": [],
            "last_updated": now,
        }

    captured_packets = sniff(count=packet_count, store=True)

    source_counter = Counter()
    port_counter = Counter()
    recent_buffer = deque(maxlen=10)

    tcp_packets = 0
    udp_packets = 0
    icmp_packets = 0
    udp_53_detected = False
    total_ip_packets = 0

    for packet in captured_packets:
        if not packet.haslayer(IP):
            continue

        total_ip_packets += 1
        ip_layer = packet[IP]

        protocol = "OTHER"
        destination_port = None

        if packet.haslayer(TCP):
            tcp_packets += 1
            protocol = "TCP"
            destination_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            udp_packets += 1
            protocol = "UDP"
            destination_port = int(packet[UDP].dport)
            if destination_port == 53:
                udp_53_detected = True
        elif packet.haslayer(ICMP):
            icmp_packets += 1
            protocol = "ICMP"

        source_counter[ip_layer.src] += 1
        if destination_port is not None:
            port_counter[destination_port] += 1

        recent_buffer.append(
            {
                "time": datetime.now().strftime("%H:%M:%S"),
                "source": ip_layer.src,
                "destination": ip_layer.dst,
                "protocol": protocol,
                "length": len(packet),
            }
        )

    top_sources = [
        {"ip": ip, "packets": count}
        for ip, count in source_counter.most_common(5)
    ]
    top_ports = [
        {"port": port, "packets": count}
        for port, count in port_counter.most_common(5)
    ]

    alerts = []
    if total_ip_packets > 0 and tcp_packets / total_ip_packets >= 0.6:
        alerts.append("High TCP traffic detected on the monitored interface.")

    if udp_53_detected:
        alerts.append("Multiple UDP packets observed on port 53.")

    if icmp_packets == 0:
        alerts.append("No ICMP activity observed in the current capture window.")
    else:
        alerts.append("ICMP activity is within normal range.")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "total_packets": total_ip_packets,
        "tcp_packets": tcp_packets,
        "udp_packets": udp_packets,
        "icmp_packets": icmp_packets,
        "alerts": alerts,
        "top_sources": top_sources,
        "top_ports": top_ports,
        "recent_packets": list(recent_buffer),
        "last_updated": now,
    }
