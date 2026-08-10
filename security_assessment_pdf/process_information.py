"""
Process information section for the
Windows Service & Process Monitoring Agent PDF report.
"""


def build_process_information(
    processes: list[dict[str, object]],
) -> list[dict[str, str]]:
    """
    Prepare process information for the security assessment report.

    Args:
        processes:
            Processes collected by ProcessMonitor.

    Returns:
        List of formatted process records.
    """

    process_information: list[dict[str, str]] = []

    for process in processes:

        process_information.append(
            {
                "pid": str(
                    process.get("pid") or "N/A"
                ),
                "ppid": str(
                    process.get("ppid") or "N/A"
                ),
                "name": str(
                    process.get("name") or "N/A"
                ),
                "status": str(
                    process.get("status") or "N/A"
                ),
                "username": str(
                    process.get("username") or "N/A"
                ),
                "path": str(
                    process.get("path") or "N/A"
                ),
            }
        )

    return process_information