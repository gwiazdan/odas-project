import logging
import sys
from pathlib import Path


class LoggerConfig:
    """Configuration for logger singleton"""

    def __init__(self):
        self.logger = logging.getLogger("safemessage")
        if not self.logger.handlers:
            self._setup_logging()

    def _setup_logging(self):
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )

        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)

        log_file = Path("safemessage.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

        self.logger.addHandler(console)
        self.logger.setLevel(logging.INFO)

    def get_logger(self):
        return self.logger


logger_config = LoggerConfig()
logger = logger_config.get_logger()
