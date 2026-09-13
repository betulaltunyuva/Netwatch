import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "netwatch.db"


def get_connection():
    """SQLite veritabanına bağlantı oluşturur."""

    DATA_DIR.mkdir(exist_ok=True)

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA busy_timeout = 10000"
    )

    return connection


def init_database():
    """NetWatch için gerekli tabloları ve indeksleri oluşturur."""

    with get_connection() as connection:
        connection.execute(
            "PRAGMA journal_mode = WAL"
        )

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                captured_at TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                packet_length INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL
                    CHECK (
                        severity IN (
                            'LOW',
                            'MEDIUM',
                            'HIGH',
                            'CRITICAL'
                        )
                    ),
                message TEXT NOT NULL,
                source_ip TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                mac_address TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_packets_captured_at
                ON packets(captured_at);

            CREATE INDEX IF NOT EXISTS idx_packets_source_ip
                ON packets(source_ip);

            CREATE INDEX IF NOT EXISTS idx_packets_destination_ip
                ON packets(destination_ip);

            CREATE INDEX IF NOT EXISTS idx_packets_protocol
                ON packets(protocol);

            CREATE INDEX IF NOT EXISTS idx_alerts_created_at
                ON alerts(created_at);

            CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
                ON alerts(source_ip);

            CREATE INDEX IF NOT EXISTS idx_alerts_type
                ON alerts(alert_type);
            """
        )


def save_packets(packets):
    """Yakalanan paketleri packets tablosuna kaydeder."""

    if not packets:
        return

    with get_connection() as connection:
        connection.executemany(
            """
            INSERT INTO packets (
                captured_at,
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                packet_length
            )
            VALUES (
                :captured_at,
                :source_ip,
                :destination_ip,
                :protocol,
                :source_port,
                :destination_port,
                :packet_length
            )
            """,
            packets
        )


def save_alerts(alerts):
    """Güvenlik uyarılarını alerts tablosuna kaydeder."""

    if not alerts:
        return

    with get_connection() as connection:
        connection.executemany(
            """
            INSERT INTO alerts (
                alert_type,
                severity,
                message,
                source_ip,
                created_at
            )
            VALUES (
                :alert_type,
                :severity,
                :message,
                :source_ip,
                :created_at
            )
            """,
            alerts
        )


def get_packet_count():
    """Veritabanındaki toplam paket sayısını döndürür."""

    with get_connection() as connection:
        result = connection.execute(
            """
            SELECT COUNT(*) AS packet_count
            FROM packets
            """
        ).fetchone()

        return result["packet_count"]


def get_alert_count():
    """Veritabanındaki toplam güvenlik uyarısı sayısını döndürür."""

    with get_connection() as connection:
        result = connection.execute(
            """
            SELECT COUNT(*) AS alert_count
            FROM alerts
            """
        ).fetchone()

        return result["alert_count"]


def normalize_minutes(minutes):
    """
    Dakika değerini 1 ile 1440 dakika
    arasında sınırlar.
    """

    try:
        minutes = int(minutes)

    except (TypeError, ValueError):
        minutes = 60

    return max(
        1,
        min(minutes, 1440)
    )


def get_traffic_history(minutes=60):
    """
    Belirlenen zaman aralığındaki paket sayılarını
    dakika dakika döndürür.
    """

    minutes = normalize_minutes(minutes)
    time_modifier = f"-{minutes} minutes"

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                substr(captured_at, 1, 16) AS time_label,
                COUNT(*) AS total_packets,

                SUM(
                    CASE
                        WHEN protocol = 'TCP' THEN 1
                        ELSE 0
                    END
                ) AS tcp_packets,

                SUM(
                    CASE
                        WHEN protocol = 'UDP' THEN 1
                        ELSE 0
                    END
                ) AS udp_packets,

                SUM(
                    CASE
                        WHEN protocol = 'ICMP' THEN 1
                        ELSE 0
                    END
                ) AS icmp_packets

            FROM packets

            WHERE captured_at >= datetime(
                'now',
                'localtime',
                ?
            )

            GROUP BY substr(captured_at, 1, 16)

            ORDER BY time_label ASC
            """,
            (time_modifier,)
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]


def get_history_summary(minutes=60):
    """
    Seçilen zaman aralığındaki genel
    paket istatistiklerini döndürür.
    """

    minutes = normalize_minutes(minutes)
    time_modifier = f"-{minutes} minutes"

    with get_connection() as connection:
        row = connection.execute(
            """
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

            WHERE captured_at >= datetime(
                'now',
                'localtime',
                ?
            )
            """,
            (time_modifier,)
        ).fetchone()

        return dict(row)


def get_recent_packets(minutes=60, limit=100):
    """Seçilen zaman aralığındaki son paketleri döndürür."""

    minutes = normalize_minutes(minutes)

    try:
        limit = int(limit)

    except (TypeError, ValueError):
        limit = 100

    limit = max(
        1,
        min(limit, 500)
    )

    time_modifier = f"-{minutes} minutes"

    with get_connection() as connection:
        rows = connection.execute(
            """
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

            WHERE captured_at >= datetime(
                'now',
                'localtime',
                ?
            )

            ORDER BY id DESC

            LIMIT ?
            """,
            (
                time_modifier,
                limit
            )
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]


def get_recent_alerts(minutes=60, limit=50):
    """
    Seçilen zaman aralığındaki son güvenlik
    uyarılarını döndürür.
    """

    minutes = normalize_minutes(minutes)

    try:
        limit = int(limit)

    except (TypeError, ValueError):
        limit = 50

    limit = max(
        1,
        min(limit, 100)
    )

    time_modifier = f"-{minutes} minutes"

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                alert_type,
                severity,
                message,
                source_ip,
                created_at

            FROM alerts

            WHERE created_at >= datetime(
                'now',
                'localtime',
                ?
            )

            ORDER BY id DESC

            LIMIT ?
            """,
            (
                time_modifier,
                limit
            )
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]


def get_history_data(minutes=60):
    """
    Trafik geçmişi sayfasında kullanılacak
    bütün verileri tek sözlükte toplar.
    """

    minutes = normalize_minutes(minutes)

    return {
        "minutes": minutes,
        "summary": get_history_summary(minutes),
        "timeline": get_traffic_history(minutes),
        "packets": get_recent_packets(
            minutes=minutes,
            limit=100
        ),
        "alerts": get_recent_alerts(
            minutes=minutes,
            limit=50
        ),
    }


def normalize_retention_days(days):
    """Saklama süresini 1 ile 365 gün arasında sınırlar."""

    try:
        days = int(days)

    except (TypeError, ValueError):
        days = 30

    return max(
        1,
        min(days, 365)
    )


def cleanup_old_records(days=30):
    """
    Seçilen süreden eski paket ve
    güvenlik uyarısı kayıtlarını temizler.
    """

    days = normalize_retention_days(days)
    time_modifier = f"-{days} days"

    with get_connection() as connection:
        packet_cursor = connection.execute(
            """
            DELETE FROM packets
            WHERE captured_at < datetime(
                'now',
                'localtime',
                ?
            )
            """,
            (time_modifier,)
        )

        alert_cursor = connection.execute(
            """
            DELETE FROM alerts
            WHERE created_at < datetime(
                'now',
                'localtime',
                ?
            )
            """,
            (time_modifier,)
        )

        deleted_packets = packet_cursor.rowcount
        deleted_alerts = alert_cursor.rowcount

    return {
        "retention_days": days,
        "deleted_packets": deleted_packets,
        "deleted_alerts": deleted_alerts,
    }