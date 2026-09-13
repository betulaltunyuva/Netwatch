from collections import defaultdict, deque
from datetime import datetime
from time import time


class ThreatDetector:
    """
    Ağ paketlerini inceleyerek şüpheli etkinlikleri tespit eder.
    """

    # Port taraması ayarları.
    PORT_SCAN_WINDOW = 10
    PORT_SCAN_PORT_LIMIT = 15

    # SYN Flood ayarları.
    SYN_FLOOD_WINDOW = 5
    SYN_FLOOD_PACKET_LIMIT = 100

    # ICMP Flood ayarları.
    ICMP_FLOOD_WINDOW = 10
    ICMP_FLOOD_PACKET_LIMIT = 50

    # Yoğun DNS trafiği ayarları.
    DNS_TRAFFIC_WINDOW = 10
    DNS_PACKET_LIMIT = 100

    # Aynı uyarının tekrar oluşturulması için
    # geçmesi gereken süre.
    ALERT_COOLDOWN = 30

    def __init__(self):
        # Kaynak IP adresinin bağlanmaya çalıştığı
        # hedef portları tutar.
        self.port_attempts = defaultdict(deque)

        # Kaynak IP adreslerinin gönderdiği
        # SYN paketlerinin zamanlarını tutar.
        self.syn_packets = defaultdict(deque)

        # Kaynak IP adreslerinin gönderdiği
        # ICMP paketlerinin zamanlarını tutar.
        self.icmp_packets = defaultdict(deque)

        # Kaynak IP adreslerinin gönderdiği
        # DNS paketlerinin zamanlarını tutar.
        self.dns_packets = defaultdict(deque)

        # En son oluşturulan uyarıların zamanlarını tutar.
        self.last_alert_times = {}

    def remove_old_times(self, event_queue, current_time, window):
        """
        Belirlenen zaman aralığının dışında kalan
        eski olayları listeden siler.
        """

        minimum_time = current_time - window

        while event_queue and event_queue[0] < minimum_time:
            event_queue.popleft()

    def remove_old_port_attempts(
        self,
        event_queue,
        current_time,
        window
    ):
        """
        Eski port bağlantı denemelerini listeden siler.
        """

        minimum_time = current_time - window

        while (
            event_queue
            and event_queue[0][0] < minimum_time
        ):
            event_queue.popleft()

    def can_create_alert(
        self,
        alert_type,
        source_ip,
        current_time
    ):
        """
        Aynı uyarının çok kısa sürede tekrar tekrar
        oluşturulmasını engeller.
        """

        alert_key = (
            alert_type,
            source_ip
        )

        last_alert_time = self.last_alert_times.get(
            alert_key
        )

        if last_alert_time is not None:
            passed_time = (
                current_time - last_alert_time
            )

            if passed_time < self.ALERT_COOLDOWN:
                return False

        self.last_alert_times[alert_key] = current_time

        return True

    def create_alert(
        self,
        alert_type,
        severity,
        message,
        source_ip
    ):
        """
        Standart uyarı sözlüğü oluşturur.
        """

        return {
            "alert_type": alert_type,
            "severity": severity,
            "message": message,
            "source_ip": source_ip,
            "created_at": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        }

    def detect_port_scan(
        self,
        source_ip,
        destination_port,
        tcp_flags,
        current_time
    ):
        """
        Bir IP adresinin kısa sürede çok sayıda
        farklı porta SYN paketi gönderip göndermediğini kontrol eder.
        """

        if destination_port is None:
            return None

        # Yalnızca SYN içeren ancak ACK içermeyen
        # TCP paketlerini kontrol eder.
        is_syn_packet = (
            "S" in tcp_flags
            and "A" not in tcp_flags
        )

        if not is_syn_packet:
            return None

        attempts = self.port_attempts[source_ip]

        attempts.append(
            (
                current_time,
                destination_port
            )
        )

        self.remove_old_port_attempts(
            attempts,
            current_time,
            self.PORT_SCAN_WINDOW
        )

        unique_ports = {
            port
            for _, port in attempts
        }

        if (
            len(unique_ports)
            >= self.PORT_SCAN_PORT_LIMIT
        ):
            if self.can_create_alert(
                "PORT_SCAN",
                source_ip,
                current_time
            ):
                return self.create_alert(
                    alert_type="PORT_SCAN",
                    severity="HIGH",
                    message=(
                        "Possible port scan detected from "
                        f"{source_ip}. "
                        f"{len(unique_ports)} different ports "
                        f"were targeted within "
                        f"{self.PORT_SCAN_WINDOW} seconds."
                    ),
                    source_ip=source_ip
                )

        return None

    def detect_syn_flood(
        self,
        source_ip,
        tcp_flags,
        current_time
    ):
        """
        Bir IP adresinden kısa sürede çok fazla
        SYN paketi gelip gelmediğini kontrol eder.
        """

        is_syn_packet = (
            "S" in tcp_flags
            and "A" not in tcp_flags
        )

        if not is_syn_packet:
            return None

        syn_events = self.syn_packets[source_ip]

        syn_events.append(current_time)

        self.remove_old_times(
            syn_events,
            current_time,
            self.SYN_FLOOD_WINDOW
        )

        if (
            len(syn_events)
            >= self.SYN_FLOOD_PACKET_LIMIT
        ):
            if self.can_create_alert(
                "SYN_FLOOD",
                source_ip,
                current_time
            ):
                return self.create_alert(
                    alert_type="SYN_FLOOD",
                    severity="CRITICAL",
                    message=(
                        "Possible SYN Flood detected from "
                        f"{source_ip}. "
                        f"{len(syn_events)} SYN packets "
                        f"were observed within "
                        f"{self.SYN_FLOOD_WINDOW} seconds."
                    ),
                    source_ip=source_ip
                )

        return None

    def detect_icmp_flood(
        self,
        source_ip,
        current_time
    ):
        """
        Bir IP adresinden kısa sürede çok fazla
        ICMP paketi gelip gelmediğini kontrol eder.
        """

        icmp_events = self.icmp_packets[source_ip]

        icmp_events.append(current_time)

        self.remove_old_times(
            icmp_events,
            current_time,
            self.ICMP_FLOOD_WINDOW
        )

        if (
            len(icmp_events)
            >= self.ICMP_FLOOD_PACKET_LIMIT
        ):
            if self.can_create_alert(
                "ICMP_FLOOD",
                source_ip,
                current_time
            ):
                return self.create_alert(
                    alert_type="ICMP_FLOOD",
                    severity="HIGH",
                    message=(
                        "Possible ICMP Flood detected from "
                        f"{source_ip}. "
                        f"{len(icmp_events)} ICMP packets "
                        f"were observed within "
                        f"{self.ICMP_FLOOD_WINDOW} seconds."
                    ),
                    source_ip=source_ip
                )

        return None

    def detect_dns_traffic(
        self,
        source_ip,
        destination_port,
        current_time
    ):
        """
        Bir IP adresinin kısa sürede çok fazla
        DNS paketi gönderip göndermediğini kontrol eder.
        """

        if destination_port != 53:
            return None

        dns_events = self.dns_packets[source_ip]

        dns_events.append(current_time)

        self.remove_old_times(
            dns_events,
            current_time,
            self.DNS_TRAFFIC_WINDOW
        )

        if (
            len(dns_events)
            >= self.DNS_PACKET_LIMIT
        ):
            if self.can_create_alert(
                "HIGH_DNS_TRAFFIC",
                source_ip,
                current_time
            ):
                return self.create_alert(
                    alert_type="HIGH_DNS_TRAFFIC",
                    severity="MEDIUM",
                    message=(
                        "Unusually high DNS traffic detected from "
                        f"{source_ip}. "
                        f"{len(dns_events)} DNS packets "
                        f"were observed within "
                        f"{self.DNS_TRAFFIC_WINDOW} seconds."
                    ),
                    source_ip=source_ip
                )

        return None

    def analyze_packet(
        self,
        source_ip,
        protocol,
        destination_port=None,
        tcp_flags=""
    ):
        """
        Bir paketi bütün saldırı kurallarına göre analiz eder.

        Bulunan uyarıları liste olarak döndürür.
        """

        current_time = time()
        detected_alerts = []

        if protocol == "TCP":
            port_scan_alert = self.detect_port_scan(
                source_ip=source_ip,
                destination_port=destination_port,
                tcp_flags=tcp_flags,
                current_time=current_time
            )

            if port_scan_alert is not None:
                detected_alerts.append(
                    port_scan_alert
                )

            syn_flood_alert = self.detect_syn_flood(
                source_ip=source_ip,
                tcp_flags=tcp_flags,
                current_time=current_time
            )

            if syn_flood_alert is not None:
                detected_alerts.append(
                    syn_flood_alert
                )

        elif protocol == "ICMP":
            icmp_flood_alert = self.detect_icmp_flood(
                source_ip=source_ip,
                current_time=current_time
            )

            if icmp_flood_alert is not None:
                detected_alerts.append(
                    icmp_flood_alert
                )

        elif protocol == "UDP":
            dns_alert = self.detect_dns_traffic(
                source_ip=source_ip,
                destination_port=destination_port,
                current_time=current_time
            )

            if dns_alert is not None:
                detected_alerts.append(
                    dns_alert
                )

        return detected_alerts


# Uygulama boyunca kullanılacak tek saldırı tespit nesnesi.
threat_detector = ThreatDetector()