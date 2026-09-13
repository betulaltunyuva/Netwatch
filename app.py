import atexit
import os
import secrets

from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    send_file
)

from flask_socketio import SocketIO

from database import (
    cleanup_old_records,
    get_history_data,
    init_database
)

from device_manager import get_devices_data

from export_manager import (
    create_alert_csv,
    create_packet_csv,
    create_pcap_export,
    get_export_information
)

from logger import get_logger
from packet_search import search_packets
from sniffer import monitor


logger = get_logger(__name__)


# Flask uygulamasını oluşturur.
app = Flask(__name__)


# Her çalıştırmada güvenli bir uygulama anahtarı üretir.
# İstenirse NETWATCH_SECRET_KEY ortam değişkeninden de alınabilir.
app.config["SECRET_KEY"] = (
    os.environ.get("NETWATCH_SECRET_KEY")
    or secrets.token_hex(32)
)


# SocketIO bağlantısına sadece yerel adreslerden izin verir.
socketio = SocketIO(
    app,
    cors_allowed_origins=[
        "http://127.0.0.1:5000",
        "http://localhost:5000"
    ]
)


# Veritabanını ve tabloları oluşturur.
init_database()


@app.after_request
def add_security_headers(response):
    """
    Tarayıcı yanıtlarına temel
    güvenlik başlıklarını ekler.
    """

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "no-referrer"

    return response


@app.route("/")
def home():
    """Canlı ağ izleme sayfasını açar."""

    summary = monitor.get_summary()

    return render_template(
        "index.html",
        summary=summary
    )


@app.route("/history")
def history():
    """Trafik geçmişi sayfasını açar."""

    history_data = get_history_data(
        minutes=60
    )

    return render_template(
        "history.html",
        history=history_data
    )


@app.route("/api/history")
def history_api():
    """Trafik geçmişini JSON olarak döndürür."""

    minutes = request.args.get(
        "minutes",
        default=60
    )

    return jsonify(
        get_history_data(
            minutes=minutes
        )
    )


@app.route("/search")
def packet_search_page():
    """Gelişmiş paket arama sayfasını açar."""

    return render_template(
        "search.html"
    )


@app.route("/api/packets/search")
def packet_search_api():
    """
    Girilen filtrelere göre
    veritabanındaki paketleri arar.
    """

    result = search_packets(
        source_ip=request.args.get(
            "source_ip",
            default=""
        ),

        destination_ip=request.args.get(
            "destination_ip",
            default=""
        ),

        protocol=request.args.get(
            "protocol",
            default=""
        ),

        port=request.args.get(
            "port",
            default=""
        ),

        start_time=request.args.get(
            "start_time",
            default=""
        ),

        end_time=request.args.get(
            "end_time",
            default=""
        ),

        limit=request.args.get(
            "limit",
            default=100
        )
    )

    return jsonify(
        result
    )


@app.route("/devices")
def devices_page():
    """Yerel ağ cihazları sayfasını açar."""

    return render_template(
        "devices.html"
    )


@app.route("/api/devices")
def devices_api():
    """
    Yerel ağda tespit edilen cihazları
    JSON olarak döndürür.
    """

    return jsonify(
        get_devices_data()
    )


@app.route("/exports")
def exports_page():
    """Dışa aktarma sayfasını açar."""

    return render_template(
        "exports.html"
    )


@app.route("/api/exports/info")
def exports_information_api():
    """
    Dışa aktarılabilecek kayıt
    sayılarını JSON olarak döndürür.
    """

    export_information = (
        get_export_information()
    )

    export_information["pcap_packets"] = (
        monitor.get_capture_packet_count()
    )

    return jsonify(
        export_information
    )


@app.post("/api/data/cleanup")
def cleanup_data_api():
    """
    Belirlenen günden eski paket ve
    güvenlik uyarısı kayıtlarını temizler.
    """

    request_data = request.get_json(
        silent=True
    ) or {}

    result = cleanup_old_records(
        days=request_data.get(
            "retention_days",
            30
        )
    )

    logger.info(
        "Old records cleaned: %s packets, %s alerts",
        result["deleted_packets"],
        result["deleted_alerts"]
    )

    return jsonify(
        result
    )


@app.route("/export/packets.csv")
def export_packets_csv():
    """
    Kayıtlı paketleri CSV dosyası
    olarak indirir.
    """

    export_result = create_packet_csv(
        source_ip=request.args.get(
            "source_ip",
            default=""
        ),

        destination_ip=request.args.get(
            "destination_ip",
            default=""
        ),

        protocol=request.args.get(
            "protocol",
            default=""
        ),

        port=request.args.get(
            "port",
            default=""
        ),

        start_time=request.args.get(
            "start_time",
            default=""
        ),

        end_time=request.args.get(
            "end_time",
            default=""
        ),

        limit=request.args.get(
            "limit",
            default=50000
        )
    )

    return send_file(
        export_result["buffer"],
        mimetype="text/csv; charset=utf-8",
        as_attachment=True,
        download_name=export_result["filename"]
    )


@app.route("/export/alerts.csv")
def export_alerts_csv():
    """
    Güvenlik uyarılarını CSV
    dosyası olarak indirir.
    """

    export_result = create_alert_csv(
        limit=request.args.get(
            "limit",
            default=10000
        )
    )

    return send_file(
        export_result["buffer"],
        mimetype="text/csv; charset=utf-8",
        as_attachment=True,
        download_name=export_result["filename"]
    )


@app.route("/export/capture.pcap")
def export_capture_pcap():
    """
    Bellekte tutulan ham paketleri
    PCAP dosyası olarak indirir.
    """

    packets = (
        monitor.get_capture_packets()
    )

    export_result = create_pcap_export(
        packets
    )

    if export_result is None:
        abort(
            400,
            description=(
                "No captured packets are available "
                "for PCAP export."
            )
        )

    return send_file(
        export_result["buffer"],
        mimetype="application/vnd.tcpdump.pcap",
        as_attachment=True,
        download_name=export_result["filename"]
    )


def send_network_updates():
    """
    Canlı ağ verilerini her saniye
    bağlı tarayıcılara gönderir.
    """

    while True:
        # Bekleyen veritabanı kayıtlarını kaydeder.
        monitor.flush_database()

        summary = monitor.get_summary()

        socketio.emit(
            "network_update",
            summary
        )

        socketio.sleep(1)


# Uygulama kapanırken paket yakalamayı durdurur
# ve bekleyen kayıtları veritabanına yazar.
atexit.register(
    monitor.stop
)


if __name__ == "__main__":
    monitor.start()

    socketio.start_background_task(
        send_network_updates
    )

    socketio.run(
        app,
        host="127.0.0.1",
        port=5000,
        debug=(
            os.environ.get(
                "NETWATCH_DEBUG",
                "0"
            ) == "1"
        ),
        use_reloader=False
    )