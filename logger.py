import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "netwatch.log"


def configure_logging():
    """Uygulama günlüklerini dönen bir dosyaya kaydeder."""

    LOG_DIR.mkdir(exist_ok=True)

    application_logger = logging.getLogger("netwatch")

    if application_logger.handlers:
        return application_logger

    application_logger.setLevel(logging.INFO)

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8"
    )

    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )
    )

    application_logger.addHandler(file_handler)
    application_logger.propagate = False

    return application_logger


def get_logger(name):
    """NetWatch ana günlükleyicisinin bir alt günlükleyicisini döndürür."""

    configure_logging()

    return logging.getLogger(
        f"netwatch.{name}"
    )