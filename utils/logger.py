"""
Centralized logging utilities for the Windows Service & Process Monitoring Agent.
"""

import logging
from pathlib import Path


class Logger:
    """
    Creates and manages the application's logging system.
    """

    def __init__(self):
        """
        Initialize the logging system.
        """

        self.log_directory = Path("logs")
        self.log_directory.mkdir(exist_ok=True)

        self.logger = logging.getLogger("ProcessMonitoringAgent")
        self.logger.setLevel(logging.INFO)
        self.console_handler = logging.StreamHandler()
        self.file_handler = logging.FileHandler(
            self.log_directory / "application.log"
        )
        self.formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        self.console_handler.setFormatter(self.formatter)
        self.file_handler.setFormatter(self.formatter)
        if not self.logger.handlers:
            self.logger.addHandler(self.console_handler)
            self.logger.addHandler(self.file_handler)
            
    def info(self, message : str) -> None:
        self.logger.info(message)

    def warning(self, message : str ) -> None:
        self.logger.warning(message)

    def error(self, message : str ) -> None:
        self.logger.error(message)

    def critical(self, message : str ) -> None :
        self.logger.critical(message)        