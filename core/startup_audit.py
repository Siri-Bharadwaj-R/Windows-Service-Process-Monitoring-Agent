"""
Startup service auditing utilities for the
Windows Service & Process Monitoring Agent.
"""

from utils.logger import Logger


class StartupAudit:
    """
    Audits Windows startup services for
    potentially suspicious configurations.
    """

    def __init__(self) -> None:
        """
        Initialize the startup audit engine.
        """

        self.logger = Logger()

        self.findings: list[dict[str, str]] = []

        self.automatic_services: list[
            dict[str, object]
        ] = []

    def audit(
        self,
        services: list[dict[str, object]],
    ) -> None:
        """
        Perform startup service auditing.

        Args:
            services:
                Collected Windows services.
        """

        self.logger.info(
            "Starting startup service audit..."
        )

        self.findings.clear()
        self.automatic_services.clear()

        for service in services:

            if service.get("start_mode") != "Auto":
                continue

            self.automatic_services.append(service)

            self._check_path(service)

            self._check_account(service)

            self._check_missing_path(service)

        self.logger.info(
            "Startup service audit completed."
        )

    def _check_path(
        self,
        service: dict[str, object],
    ) -> None:
        """
        Detect services running from
        suspicious locations.
        """

        path = str(
            service.get("path") or ""
        ).lower()

        suspicious_locations = [

            "\\temp\\",

            "\\downloads\\",

            "\\desktop\\",

            "\\users\\public\\",
        ]

        for location in suspicious_locations:

            if location in path:

                self.findings.append(
                    {
                        "severity": "HIGH",
                        "category": "Startup Service",
                        "title": "Suspicious Service Path",
                        "description":
                        f"{service['name']} runs "
                        f"from '{service['path']}'.",
                        "recommendation":
                        "Verify the service "
                        "installation path.",
                    }
                )

                self.logger.warning(
                    "[HIGH] Suspicious "
                    "startup service path"
                )

                break

    def _check_account(
    self,
    service: dict[str, object],
    ) -> None:
        """
        Detect services running under
        unexpected user accounts.
        """

        account = str(
            service.get("account") or ""
        ).strip()

        account_lower = account.lower()

        trusted_accounts = {

            "localsystem",

            "localservice",

            "networkservice",

            "nt authority\\localservice",

            "nt authority\\networkservice",
        }

        if (
            account_lower in trusted_accounts
            or account.upper().startswith("NT SERVICE\\")
            or account == ""
            or account.lower() == "none"
        ):
            return

        self.findings.append(
            {
                "severity": "MEDIUM",
                "category": "Startup Service",
                "title": "Service Running Under User Account",
                "description":
                f"{service['name']} "
                f"runs as "
                f"{service['account']}.",
                "recommendation":
                "Verify that the "
                "configured account "
                "is expected.",
            }
        )

        self.logger.warning(
            "[MEDIUM] Startup "
            "service account"
        )
    
    
    def _check_missing_path(
        self,
        service: dict[str, object],
    ) -> None:
        """
        Detect services without an
        executable path.
        """

        path = service.get("path")

        if path:

            return

        self.findings.append(
            {
                "severity": "LOW",
                "category": "Startup Service",
                "title": "Missing Executable Path",
                "description":
                f"{service['name']} "
                "has no executable path.",
                "recommendation":
                "Verify the service "
                "configuration.",
            }
        )

        self.logger.warning(
            "[LOW] Missing service path"
        )

    def get_automatic_services(
        self,
    ) -> list[dict[str, object]]:
        """
        Return all automatic startup services.
        """

        return self.automatic_services

    def get_findings(
        self,
    ) -> list[dict[str, str]]:
        """
        Return startup audit findings.
        """

        return self.findings