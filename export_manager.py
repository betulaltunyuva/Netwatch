import csv
from datetime import datetime
from io import BytesIO, StringIO
from pathlib import Path
from uuid import uuid4

from database import get_connection

from packet_search import build_packet_filters


# CSV dosyasına en fazla kaç paket
# yazılabileceğini belirler.
MAX_CSV_PACKETS = 50000

# CSV dosyasına en fazla kaç güvenlik
# uyarısı yazılabileceğini belirler.
MAX_CSV_ALERTS = 10000


def normalize_export_limit(
    value,
    default_value,
    maximum_value
):
    """
    Dışa aktarılacak kayıt sayısını kontrol eder.
    """

    try:
        limit = int(value)

    except (TypeError, ValueError):
        limit = default_value

    return max(
        1,
        min(limit, maximum_value)
    )


def create_packet_csv(
    source_ip="",
    destination_ip="",
    protocol="",
    port=None,
    start_time=None,
    end_time=None,
    limit=50000
):
    """
    Seçilen filtrelere uyan paketleri
    CSV dosyası olarak hazırlar.
    """

    export_limit = normalize_export_limit(
        value=limit,
        default_value=50000,
        maximum_value=MAX_CSV_PACKETS
    )

    (
        where_sql,
        parameters,
        normalized_filters
    ) = build_packet_filters(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        port=port,
        start_time=start_time,
        end_time=end_time
    )

    query = f"""
        SELECT
            id,
            captured_at,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol,
            packet_length

        FROM packets

        {where_sql}

        ORDER BY id DESC

        LIMIT ?
    """

    with get_connection() as connection:
        rows = connection.execute(
            query,
            parameters + [export_limit]
        ).fetchall()

    # CSV metninin geçici olarak tutulacağı alan.
    text_buffer = StringIO(
        newline=""
    )

    csv_writer = csv.writer(
        text_buffer
    )

    # CSV sütun başlıkları.
    csv_writer.writerow(
        [
            "ID",
            "Captured At",
            "Source IP",
            "Source Port",
            "Destination IP",
            "Destination Port",
            "Protocol",
            "Packet Length"
        ]
    )

    # Paketleri CSV dosyasına ekler.
    for row in rows:
        csv_writer.writerow(
            [
                row["id"],
                row["captured_at"],
                row["source_ip"],
                row["source_port"],
                row["destination_ip"],
                row["destination_port"],
                row["protocol"],
                row["packet_length"]
            ]
        )

    # UTF-8 BOM, CSV dosyasındaki Türkçe ve
    # özel karakterlerin Excel'de düzgün
    # görünmesini sağlar.
    csv_bytes = text_buffer.getvalue().encode(
        "utf-8-sig"
    )

    file_buffer = BytesIO(
        csv_bytes
    )

    file_buffer.seek(0)

    file_name = (
        "netwatch_packets_" +
        datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        ) +
        ".csv"
    )

    return {
        "buffer": file_buffer,
        "filename": file_name,
        "record_count": len(rows),
        "filters": normalized_filters,
    }


def create_alert_csv(limit=10000):
    """
    Güvenlik uyarılarını CSV dosyası
    olarak hazırlar.
    """

    export_limit = normalize_export_limit(
        value=limit,
        default_value=10000,
        maximum_value=MAX_CSV_ALERTS
    )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                created_at,
                alert_type,
                severity,
                source_ip,
                message

            FROM alerts

            ORDER BY id DESC

            LIMIT ?
            """,
            (export_limit,)
        ).fetchall()

    text_buffer = StringIO(
        newline=""
    )

    csv_writer = csv.writer(
        text_buffer
    )

    csv_writer.writerow(
        [
            "ID",
            "Created At",
            "Alert Type",
            "Severity",
            "Source IP",
            "Message"
        ]
    )

    for row in rows:
        csv_writer.writerow(
            [
                row["id"],
                row["created_at"],
                row["alert_type"],
                row["severity"],
                row["source_ip"],
                row["message"]
            ]
        )

    csv_bytes = text_buffer.getvalue().encode(
        "utf-8-sig"
    )

    file_buffer = BytesIO(
        csv_bytes
    )

    file_buffer.seek(0)

    file_name = (
        "netwatch_alerts_" +
        datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        ) +
        ".csv"
    )

    return {
        "buffer": file_buffer,
        "filename": file_name,
        "record_count": len(rows),
    }


def create_pcap_export(packets):
    """
    Bellekte tutulan ham ağ paketlerini
    PCAP dosyasına dönüştürür.
    """

    if not packets:
        return None

    try:
        from scapy.utils import wrpcap

    except ImportError:
        return None

    # Geçici PCAP dosyasının oluşturulacağı konum.
    temporary_directory = (
        Path(__file__).resolve().parent /
        "exports"
    )

    temporary_directory.mkdir(
        exist_ok=True
    )

    temporary_file = (
        temporary_directory /
        f"temporary_{uuid4().hex}.pcap"
    )

    try:
        # Scapy paketlerini geçici PCAP dosyasına yazar.
        wrpcap(
            str(temporary_file),
            packets
        )

        # Oluşan dosyanın bütün baytlarını okur.
        pcap_bytes = temporary_file.read_bytes()

    finally:
        # Geçici dosyayı işlem bittikten sonra siler.
        if temporary_file.exists():
            temporary_file.unlink()

    file_buffer = BytesIO(
        pcap_bytes
    )

    file_buffer.seek(0)

    file_name = (
        "netwatch_capture_" +
        datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        ) +
        ".pcap"
    )

    return {
        "buffer": file_buffer,
        "filename": file_name,
        "record_count": len(packets),
    }


def get_export_information():
    """
    Dışa aktarma sayfasında gösterilecek
    veritabanı kayıt sayılarını döndürür.
    """

    with get_connection() as connection:
        packet_result = connection.execute(
            """
            SELECT COUNT(*) AS record_count
            FROM packets
            """
        ).fetchone()

        alert_result = connection.execute(
            """
            SELECT COUNT(*) AS record_count
            FROM alerts
            """
        ).fetchone()

    return {
        "saved_packets": packet_result["record_count"],
        "saved_alerts": alert_result["record_count"],
        "maximum_packet_csv": MAX_CSV_PACKETS,
        "maximum_alert_csv": MAX_CSV_ALERTS,
    }