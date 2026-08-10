"""
Scan information section for the
Windows Service & Process Monitoring Agent PDF report.
"""

from datetime import datetime


def build_scan_information(
    process_count: int,
    service_count: int,
) -> dict[str, str]:
    """
    Build scan information for the security assessment report.

    Args:
        process_count:
            Number of processes scanned.

        service_count:
            Number of Windows services scanned.

    Returns:
        Dictionary containing scan information.
    """

    return {
        "scan_time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "processes_scanned": str(
            process_count
        ),
        "services_scanned": str(
            service_count
        ),
    }