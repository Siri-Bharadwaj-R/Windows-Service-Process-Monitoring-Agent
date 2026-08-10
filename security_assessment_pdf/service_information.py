"""
Service information section for the
Windows Service & Process Monitoring Agent PDF report.
"""


def build_service_information(
    services: list[dict[str, object]],
) -> list[dict[str, str]]:
    """
    Prepare Windows service information for the
    security assessment report.

    Args:
        services:
            Windows services collected by ServiceMonitor.

    Returns:
        List of formatted service records.
    """

    service_information: list[dict[str, str]] = []

    for service in services:

        service_information.append(
            {
                "name": str(
                    service.get("name") or "N/A"
                ),
                "display_name": str(
                    service.get("display_name") or "N/A"
                ),
                "state": str(
                    service.get("state") or "N/A"
                ),
                "start_mode": str(
                    service.get("start_mode") or "N/A"
                ),
                "account": str(
                    service.get("account") or "N/A"
                ),
                "pid": str(
                    service.get("pid") or "N/A"
                ),
                "path": str(
                    service.get("path") or "N/A"
                ),
            }
        )

    return service_information