"""
Startup service auditing utilities for the
Windows Service & Process Monitoring Agent.
"""

import json
import re
import subprocess
from pathlib import Path

from utils.logger import Logger


class StartupAudit:
    """
    Audits Windows startup services for
    potentially suspicious configurations.
    """

    BASELINE_FILE = Path(
        "config/service_baseline.json"
    )

    def __init__(self) -> None:
        """
        Initialize the startup audit engine.
        """

        self.logger = Logger()

        self.findings: list[dict[str, str]] = []

        self.automatic_services: list[
            dict[str, object]
        ] = []

        self.baseline: dict[
            str,
            dict[str, str],
        ] = {}

    def audit(
        self,
        services: list[dict[str, object]],
    ) -> None:
        """
        Perform startup service auditing.

        Existing startup checks are preserved.

        Additional checks:
        - Weak service permissions
        - Newly added services
        - Modified service configurations
        """

        self.logger.info(
            "Starting startup service audit..."
        )

        self.findings.clear()
        self.automatic_services.clear()

        # ----------------------------------------------------
        # Load previous service baseline
        # ----------------------------------------------------

        self.baseline = self._load_baseline()

        current_services = (
            self._build_service_snapshot(
                services
            )
        )

        # ----------------------------------------------------
        # Existing startup-service checks
        # ----------------------------------------------------

        for service in services:

            # NEW:
            # Permission auditing applies to ALL services,
            # not only automatic startup services.
            self._check_service_permissions(
                service
            )

            # Existing startup checks remain limited
            # to automatic services.
            if service.get("start_mode") != "Auto":
                continue

            self.automatic_services.append(
                service
            )

            self._check_path(service)

            self._check_account(service)

            self._check_missing_path(service)

        # ----------------------------------------------------
        # New / modified service detection
        # ----------------------------------------------------

        self._check_service_changes(
            current_services
        )

        # ----------------------------------------------------
        # Save current baseline
        # ----------------------------------------------------

        self._save_baseline(
            current_services
        )

        self.logger.info(
            "Startup service audit completed."
        )

    # ========================================================
    # EXISTING CHECK: SUSPICIOUS SERVICE PATH
    # ========================================================

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
                        "title":
                            "Suspicious Service Path",
                        "description":
                            (
                                f"{service['name']} "
                                f"runs from "
                                f"'{service['path']}'."
                            ),
                        "recommendation":
                            (
                                "Verify the service "
                                "installation path."
                            ),
                    }
                )

                self.logger.warning(
                    "[HIGH] Suspicious "
                    "startup service path"
                )

                break

    # ========================================================
    # EXISTING CHECK: SERVICE ACCOUNT
    # ========================================================

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
            or account.upper().startswith(
                "NT SERVICE\\"
            )
            or account == ""
            or account.lower() == "none"
        ):
            return

        self.findings.append(
            {
                "severity": "MEDIUM",
                "category": "Startup Service",
                "title":
                    "Service Running Under User Account",
                "description":
                    (
                        f"{service['name']} "
                        f"runs as "
                        f"{service['account']}."
                    ),
                "recommendation":
                    (
                        "Verify that the "
                        "configured account "
                        "is expected."
                    ),
            }
        )

        self.logger.warning(
            "[MEDIUM] Startup "
            "service account"
        )

    # ========================================================
    # EXISTING CHECK: MISSING PATH
    # ========================================================

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
                "title":
                    "Missing Executable Path",
                "description":
                    (
                        f"{service['name']} "
                        "has no executable path."
                    ),
                "recommendation":
                    (
                        "Verify the service "
                        "configuration."
                    ),
            }
        )

        self.logger.warning(
            "[LOW] Missing service path"
        )

    # ========================================================
    # NEW CHECK: SERVICE PERMISSIONS
    # ========================================================

    def _check_service_permissions(
        self,
        service: dict[str, object],
    ) -> None:
        """
        Detect potentially dangerous Windows
        service permissions.

        Uses:
            sc.exe sdshow <service>

        The check focuses on broad principals
        receiving powerful service-management
        permissions.

        Relevant principals:

            WD = Everyone
            BU = Built-in Users
            AU = Authenticated Users
            IU = Interactive Users

        Relevant dangerous rights:

            CC = SERVICE_CHANGE_CONFIG
            WD = WRITE_DAC
            WO = WRITE_OWNER
            GA = GENERIC_ALL
            GW = GENERIC_WRITE
        """

        service_name = str(
            service.get("name") or ""
        ).strip()

        if not service_name:
            return

        try:

            result = subprocess.run(
                [
                    "sc.exe",
                    "sdshow",
                    service_name,
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        except (
            subprocess.SubprocessError,
            OSError,
        ) as error:

            self.logger.warning(
                f"Unable to query service "
                f"permissions for "
                f"{service_name}: {error}"
            )

            return

        if result.returncode != 0:
            return

        sddl = result.stdout.strip()

        if not sddl:
            return

        # Broad principals that should not
        # normally receive powerful service
        # management rights.
        broad_principals = {
            "WD",
            "BU",
            "AU",
            "IU",
        }

        # Rights that can potentially permit
        # service configuration manipulation
        # or security-descriptor modification.
        dangerous_rights = {
            "DC",  # SERVICE_CHANGE_CONFIG
            "WD",  # WRITE_DAC
            "WO",  # WRITE_OWNER
            "GA",  # GENERIC_ALL
            "GW",  # GENERIC_WRITE
        }

        # Windows SDDL ACE format:
        #
        # (A;;CCLCSWLOCRRC;;;WD)
        #
        # Rights are concatenated, NOT comma-separated.
        ace_pattern = re.compile(
            r"\([AD];;([^;]*);;;([^;)]+)\)"
        )

        for match in ace_pattern.finditer(
            sddl
        ):

            rights_string = match.group(1)
            principal = match.group(2)

            if (
                principal
                not in broad_principals
            ):
                continue

            # Extract two-character SDDL
            # permission codes.
            rights = set(
                re.findall(
                    r"[A-Z]{2}",
                    rights_string,
                )
            )

            dangerous = (
                rights
                & dangerous_rights
            )

            if not dangerous:
                continue

            dangerous_text = ", ".join(
                sorted(dangerous)
            )

            self.findings.append(
                {
                    "severity": "HIGH",
                    "category":
                        "Service Permissions",
                    "title":
                        "Weak Service Permissions",
                    "description":
                        (
                            f"{service_name} grants "
                            f"potentially dangerous "
                            f"service permissions "
                            f"({dangerous_text}) "
                            f"to broad principal "
                            f"'{principal}'."
                        ),
                    "recommendation":
                        (
                            "Review the service "
                            "security descriptor and "
                            "remove unnecessary "
                            "service-management "
                            "permissions from broad "
                            "user groups."
                        ),
                }
            )

            self.logger.warning(
                "[HIGH] Weak service "
                f"permissions: {service_name}"
            )

            # One finding per service is enough.
            break

    # ========================================================
    # SERVICE BASELINE
    # ========================================================

    def _build_service_snapshot(
        self,
        services: list[dict[str, object]],
    ) -> dict[
        str,
        dict[str, str],
    ]:
        """
        Build a compact service baseline.

        Tracked fields:
        - service name
        - executable path
        - start mode
        - account
        """

        snapshot: dict[
            str,
            dict[str, str],
        ] = {}

        for service in services:

            name = str(
                service.get("name") or ""
            ).strip()

            if not name:
                continue

            snapshot[
                name.lower()
            ] = {
                "name": name,
                "path": str(
                    service.get("path") or ""
                ),
                "start_mode": str(
                    service.get("start_mode")
                    or ""
                ),
                "account": str(
                    service.get("account")
                    or ""
                ),
            }

        return snapshot

    # ========================================================
    # LOAD BASELINE
    # ========================================================

    def _load_baseline(
        self,
    ) -> dict[
        str,
        dict[str, str],
    ]:
        """
        Load the previous service baseline.

        If no baseline exists, the current scan
        becomes the initial baseline.
        """

        try:

            if not self.BASELINE_FILE.exists():
                return {}

            with self.BASELINE_FILE.open(
                "r",
                encoding="utf-8",
            ) as file:

                data = json.load(file)

            if isinstance(data, dict):
                return data

        except (
            OSError,
            json.JSONDecodeError,
        ) as error:

            self.logger.warning(
                "Unable to load service "
                f"baseline: {error}"
            )

        return {}

    # ========================================================
    # SAVE BASELINE
    # ========================================================

    def _save_baseline(
        self,
        snapshot: dict[
            str,
            dict[str, str],
        ],
    ) -> None:
        """
        Save the current service state
        for future comparison.
        """

        try:

            self.BASELINE_FILE.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with self.BASELINE_FILE.open(
                "w",
                encoding="utf-8",
            ) as file:

                json.dump(
                    snapshot,
                    file,
                    indent=4,
                )

        except OSError as error:

            self.logger.warning(
                "Unable to save service "
                f"baseline: {error}"
            )

    # ========================================================
    # NEW / MODIFIED SERVICE DETECTION
    # ========================================================

    def _check_service_changes(
        self,
        current_services: dict[
            str,
            dict[str, str],
        ],
    ) -> None:
        """
        Detect newly added and modified services.

        The first scan establishes the baseline.
        Later scans are compared against it.
        """

        if not self.baseline:

            self.logger.info(
                "No previous service baseline "
                "found. Current services will "
                "establish the initial baseline."
            )

            return

        # ----------------------------------------------------
        # NEW SERVICES
        # ----------------------------------------------------

        for (
            service_key,
            current,
        ) in current_services.items():

            if service_key in self.baseline:
                continue

            self.findings.append(
                {
                    "severity": "MEDIUM",
                    "category":
                        "Service Change",
                    "title":
                        "New Service Detected",
                    "description":
                        (
                            f"Service "
                            f"{current['name']} "
                            "was not present in "
                            "the previous baseline."
                        ),
                    "recommendation":
                        (
                            "Verify that the service "
                            "was intentionally installed "
                            "and that its executable "
                            "path and account are trusted."
                        ),
                }
            )

            self.logger.warning(
                "[MEDIUM] New service detected: "
                f"{current['name']}"
            )

        # ----------------------------------------------------
        # MODIFIED SERVICES
        # ----------------------------------------------------

        for (
            service_key,
            current,
        ) in current_services.items():

            previous = self.baseline.get(
                service_key
            )

            if previous is None:
                continue

            changed_fields: list[str] = []

            for field in (
                "path",
                "start_mode",
                "account",
            ):

                current_value = current.get(
                    field,
                    "",
                )

                previous_value = previous.get(
                    field,
                    "",
                )

                if (
                    current_value
                    != previous_value
                ):
                    changed_fields.append(
                        field
                    )

            if not changed_fields:
                continue

            self.findings.append(
                {
                    "severity": "MEDIUM",
                    "category":
                        "Service Change",
                    "title":
                        "Service Configuration Changed",
                    "description":
                        (
                            f"{current['name']} "
                            "has changed service "
                            "configuration fields: "
                            f"{', '.join(changed_fields)}."
                        ),
                    "recommendation":
                        (
                            "Review the service change "
                            "and verify that it was "
                            "authorized."
                        ),
                }
            )

            self.logger.warning(
                "[MEDIUM] Service configuration "
                f"changed: {current['name']}"
            )

    # ========================================================
    # PUBLIC API
    # ========================================================

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