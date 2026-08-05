"""
Windows service monitoring utilities for the
Windows Service & Process Monitoring Agent.
"""

import wmi

from utils.logger import Logger


class ServiceMonitor:
    """
    Enumerates and collects information about
    Windows services.
    """

    def __init__(self) -> None:
        """
        Initialize the service monitor.
        """

        self.logger = Logger()

        self.wmi_connection = wmi.WMI()

        self.services: list[dict[str, object]] = []

    def scan(self) -> list[dict[str, object]]:
        """
        Scan all Windows services.

        Returns:
            A list of dictionaries containing
            Windows service information.
        """

        self.logger.info("Starting Windows service scan...")

        self.services.clear()

        try:

            for service in self.wmi_connection.Win32_Service():

                self.services.append(
                    {
                        "name": service.Name,
                        "display_name": service.DisplayName,
                        "state": service.State,
                        "start_mode": service.StartMode,
                        "path": service.PathName,
                        "account": service.StartName,
                        "pid": service.ProcessId,
                        "description": service.Description,
                    }
                )

        except Exception as error:

            self.logger.error(
                f"Failed to enumerate Windows services: {error}"
            )

            raise

        self.logger.info(
            f"Service scan completed. "
            f"{len(self.services)} services collected."
        )

        return self.services
    
    def get_running_services(
    self,
) -> list[dict[str, object]]:
        """
        Return all currently running services.
        """

        return [
            service
            for service in self.services
            if service["state"] == "Running"
        ]
        
    def get_service(
    self,
    service_name: str,
) -> dict[str, object] | None:
        """
        Return a service by its exact service name.

        Args:
            service_name:
                Exact Windows service name.

        Returns:
            Service dictionary if found,
            otherwise None.
        """

        for service in self.services:

            name = service.get("name")

            if (
                isinstance(name, str)
                and name.lower() == service_name.lower()
            ):
                return service

        return None
    
    def find_service(
    self,
    keyword: str,
) -> list[dict[str, object]]:
        """
        Find all services whose name or display name
        contains the given keyword.

        Args:
            keyword:
                Text to search for.

        Returns:
            List of matching service dictionaries.
        """

        matches: list[dict[str, object]] = []

        keyword = keyword.lower()

        for service in self.services:

            name = service.get("name") or ""
            display_name = service.get("display_name") or ""

            if (
                keyword in name.lower()
                or keyword in display_name.lower()
            ):
                matches.append(service)

        return matches
    
    def statistics(self) -> dict[str, int]:
        """
        Return statistics about collected services.
        """

        return {
            "total": len(self.services),
            "running": sum(
                service["state"] == "Running"
                for service in self.services
            ),
            "stopped": sum(
                service["state"] == "Stopped"
                for service in self.services
            ),
            "automatic": sum(
                service["start_mode"] == "Auto"
                for service in self.services
            ),
            "manual": sum(
                service["start_mode"] == "Manual"
                for service in self.services
            ),
            "disabled": sum(
                service["start_mode"] == "Disabled"
                for service in self.services
            ),
        }