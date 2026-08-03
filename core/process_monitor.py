"""
Process monitoring utilities for the
Windows Service & Process Monitoring Agent.
"""

from datetime import datetime

import psutil

from utils.logger import Logger


class ProcessMonitor:
    """
    Enumerates and collects information about
    running Windows processes.
    """

    def __init__(self) -> None:
        """
        Initialize the process monitor.
        """

        self.logger = Logger()

    def scan(self) -> list[dict[str, object]]:
        """
        Scan all running processes on the system.

        Returns:
            A list of dictionaries containing process information.
        """

        self.logger.info("Starting process scan...")

        processes: list[dict[str, object]] = []

        for process in psutil.process_iter(
            [
                "pid",
                "ppid",
                "name",
                "exe",
                "username",
                "status",
                "create_time",
            ]
        ):
            try:
                info = process.info

                create_time = None
                if info["create_time"] is not None:
                    create_time = datetime.fromtimestamp(
                        info["create_time"]
                    ).strftime("%Y-%m-%d %H:%M:%S")

                processes.append(
                    {
                        "pid": info["pid"],
                        "ppid": info["ppid"],
                        "name": info["name"],
                        "exe": info["exe"],
                        "username": info["username"],
                        "status": info["status"],
                        "create_time": create_time,
                    }
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ) as error:
                self.logger.warning(
                    f"Skipped process during scan: {error}"
                )
                continue

        self.logger.info(
            f"Process scan completed. {len(processes)} processes collected."
        )

        return processes