from datetime import datetime

from database import get_connection


ALLOWED_PROTOCOLS = {
    "TCP",
    "UDP",
    "ICMP",
    "OTHER"
}


def normalize_ip_search(value):
    """
    IP arama değerini temizler.

    Tam IP adresinin yanında 192.168 gibi
    kısmi değerlerle de arama yapılabilir.
    """

    if value is None:
        return ""

    return str(value).strip()[:45]


def normalize_protocol(value):
    """
    Protokol değerini kontrol eder.
    """

    if value is None:
        return ""

    protocol = str(value).strip().upper()

    if protocol not in ALLOWED_PROTOCOLS:
        return ""

    return protocol


def normalize_port(value):
    """
    Port değerinin 1 ile 65535 arasında
    geçerli bir sayı olmasını sağlar.
    """

    if value in (
        None,
        ""
    ):
        return None

    try:
        port = int(value)

    except (TypeError, ValueError):
        return None

    if 1 <= port <= 65535:
        return port

    return None


def normalize_limit(value):
    """
    Gösterilecek paket sayısını sınırlar.
    """

    try:
        limit = int(value)

    except (TypeError, ValueError):
        limit = 100

    return max(
        10,
        min(limit, 500)
    )


def normalize_datetime(value, is_end=False):
    """
    HTML datetime-local değerini SQLite tarih
    biçimine dönüştürür.

    Örnek:
    2026-07-14T16:30
    2026-07-14 16:30:00
    """

    if not value:
        return None

    date_value = str(value).strip()

    date_value = date_value.replace(
        "T",
        " "
    )

    # Saniye yazılmadıysa başlangıç için 00,
    # bitiş için 59 ekler.
    if len(date_value) == 16:

        if is_end:
            date_value += ":59"

        else:
            date_value += ":00"

    try:
        parsed_date = datetime.strptime(
            date_value,
            "%Y-%m-%d %H:%M:%S"
        )

        return parsed_date.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except ValueError:
        return None


def build_packet_filters(
    source_ip="",
    destination_ip="",
    protocol="",
    port=None,
    start_time=None,
    end_time=None
):
    """
    Filtrelere göre güvenli SQL koşulları oluşturur.
    """

    conditions = []
    parameters = []

    normalized_source_ip = normalize_ip_search(
        source_ip
    )

    normalized_destination_ip = normalize_ip_search(
        destination_ip
    )

    normalized_protocol = normalize_protocol(
        protocol
    )

    normalized_port = normalize_port(
        port
    )

    normalized_start_time = normalize_datetime(
        start_time,
        is_end=False
    )

    normalized_end_time = normalize_datetime(
        end_time,
        is_end=True
    )

    # Kaynak IP filtresi.
    if normalized_source_ip:
        conditions.append(
            "source_ip LIKE ?"
        )

        parameters.append(
            f"%{normalized_source_ip}%"
        )

    # Hedef IP filtresi.
    if normalized_destination_ip:
        conditions.append(
            "destination_ip LIKE ?"
        )

        parameters.append(
            f"%{normalized_destination_ip}%"
        )

    # Protokol filtresi.
    if normalized_protocol:
        conditions.append(
            "protocol = ?"
        )

        parameters.append(
            normalized_protocol
        )

    # Kaynak veya hedef port filtresi.
    if normalized_port is not None:
        conditions.append(
            """
            (
                source_port = ?
                OR destination_port = ?
            )
            """
        )

        parameters.extend(
            [
                normalized_port,
                normalized_port
            ]
        )

    # Başlangıç tarihi filtresi.
    if normalized_start_time:
        conditions.append(
            "captured_at >= ?"
        )

        parameters.append(
            normalized_start_time
        )

    # Bitiş tarihi filtresi.
    if normalized_end_time:
        conditions.append(
            "captured_at <= ?"
        )

        parameters.append(
            normalized_end_time
        )

    if conditions:
        where_sql = (
            "WHERE " +
            " AND ".join(conditions)
        )

    else:
        where_sql = ""

    normalized_filters = {
        "source_ip": normalized_source_ip,
        "destination_ip": normalized_destination_ip,
        "protocol": normalized_protocol,
        "port": normalized_port,
        "start_time": normalized_start_time,
        "end_time": normalized_end_time,
    }

    return (
        where_sql,
        parameters,
        normalized_filters
    )


def search_packets(
    source_ip="",
    destination_ip="",
    protocol="",
    port=None,
    start_time=None,
    end_time=None,
    limit=100
):
    """
    Girilen filtrelere göre paketleri arar.

    Sonuçlarla birlikte paket özetini de döndürür.
    """

    normalized_limit = normalize_limit(
        limit
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

    summary_query = f"""
        SELECT
            COUNT(*) AS total_packets,

            COALESCE(
                SUM(
                    CASE
                        WHEN protocol = 'TCP' THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS tcp_packets,

            COALESCE(
                SUM(
                    CASE
                        WHEN protocol = 'UDP' THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS udp_packets,

            COALESCE(
                SUM(
                    CASE
                        WHEN protocol = 'ICMP' THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS icmp_packets,

            COALESCE(
                SUM(packet_length),
                0
            ) AS total_bytes

        FROM packets

        {where_sql}
    """

    packets_query = f"""
        SELECT
            id,
            captured_at,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_length

        FROM packets

        {where_sql}

        ORDER BY id DESC

        LIMIT ?
    """

    with get_connection() as connection:
        summary_row = connection.execute(
            summary_query,
            parameters
        ).fetchone()

        packet_rows = connection.execute(
            packets_query,
            parameters + [normalized_limit]
        ).fetchall()

    return {
        "filters": normalized_filters,

        "limit": normalized_limit,

        "summary": dict(
            summary_row
        ),

        "packets": [
            dict(row)
            for row in packet_rows
        ],
    }