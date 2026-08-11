"""
Detection engine for the
Windows Service & Process Monitoring Agent.
"""

from utils.config_loader import ConfigLoader
from utils.logger import Logger


class DetectionEngine:
    """
    Performs rule-based security analysis
    on collected Windows telemetry.
    """

    def __init__(self) -> None:
        """
        Initialize the detection engine.
        """

        self.logger = Logger()

        self.config_loader = ConfigLoader()

        self.blacklist = (
            self.config_loader.load_blacklist()
        )

        # Stores all security findings
        self.findings: list[dict[str, str]] = []

    # ========================================================
    # FINDING MANAGEMENT
    # ========================================================

    def add_finding(
        self,
        severity: str,
        title: str,
        category: str,
        description: str,
        recommendation: str,
    ) -> None:
        """
        Add a security finding.
        """

        finding = {
            "severity": severity,
            "title": title,
            "category": category,
            "description": description,
            "recommendation": recommendation,
        }

        self.findings.append(finding)

        self.logger.warning(
            f"[{severity}] {title}"
        )

    def get_findings(
        self,
    ) -> list[dict[str, str]]:
        """
        Return all collected findings.
        """

        return self.findings

    def clear_findings(
        self,
    ) -> None:
        """
        Clear all stored findings.
        """

        self.findings.clear()

        self.logger.info(
            "Detection findings cleared."
        )

    # ========================================================
    # PARENT-CHILD PROCESS DETECTION
    # ========================================================

    def detect_suspicious_parent_child(
        self,
        processes: list[dict[str, object]],
    ) -> None:
        """
        Detect suspicious parent-child
        process relationships.

        Args:
            processes:
                List of collected processes.
        """

        self.logger.info(
            "Analyzing parent-child relationships..."
        )

        office_processes = {
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
        }

        scripting_processes = {
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        }

        process_lookup = {
            process["pid"]: process
            for process in processes
        }

        for process in processes:

            parent = process_lookup.get(
                process["ppid"]
            )

            if parent is None:
                continue

            parent_name = str(
                parent.get("name") or ""
            ).lower()

            child_name = str(
                process.get("name") or ""
            ).lower()

            if (
                parent_name in office_processes
                and child_name in scripting_processes
            ):

                self.add_finding(
                    severity="HIGH",
                    title=(
                        "Suspicious Parent-Child "
                        "Relationship"
                    ),
                    category="Process Behavior",
                    description=(
                        f"{parent.get('name')} "
                        f"spawned "
                        f"{process.get('name')}."
                    ),
                    recommendation=(
                        "Investigate the originating "
                        "Office document and child "
                        "process."
                    ),
                )

        self.logger.info(
            "Parent-child analysis completed."
        )

    # ========================================================
    # BLACKLIST DETECTION
    # ========================================================

    def detect_blacklisted_processes(
        self,
        processes: list[dict[str, object]],
    ) -> None:
        """
        Detect running blacklisted processes.

        Args:
            processes:
                List of collected processes.
        """

        self.logger.info(
            "Checking for blacklisted processes..."
        )

        blacklist = {
            process.lower()
            for process in self.blacklist.get(
                "blacklisted_processes",
                [],
            )
        }

        for process in processes:

            process_name = str(
                process.get("name") or ""
            ).lower()

            if process_name in blacklist:

                self.add_finding(
                    severity="CRITICAL",
                    title=(
                        "Blacklisted Process Detected"
                    ),
                    category="Process Reputation",
                    description=(
                        f"Blacklisted process "
                        f"'{process.get('name')}' "
                        "is currently running."
                    ),
                    recommendation=(
                        "Investigate the process "
                        "immediately and determine "
                        "whether the system has "
                        "been compromised."
                    ),
                )

        self.logger.info(
            "Blacklist analysis completed."
        )

    # ========================================================
    # SUSPICIOUS EXECUTABLE PATH DETECTION
    # ========================================================

    def detect_suspicious_paths(
        self,
        processes: list[dict[str, object]],
    ) -> None:
        """
        Detect processes running from suspicious
        executable locations while reducing
        common false positives.

        Args:
            processes:
                List of collected processes.
        """

        self.logger.info(
            "Checking executable paths..."
        )

        suspicious_locations = (
            "\\temp\\",
            "\\downloads\\",
            "\\desktop\\",
            "\\public\\",
        )

        trusted_appdata_locations = (
            "\\appdata\\local\\programs\\",
            "\\appdata\\local\\microsoft\\",
            "\\appdata\\local\\mathworks\\",
            "\\appdata\\local\\webex\\",
        )

        # Development environments that are expected
        # to contain executable files.
        trusted_development_locations = (
            "\\.venv\\",
            "\\venv\\",
        )

        seen_paths: set[str] = set()

        for process in processes:

            executable = str(
                process.get("exe") or ""
            ).lower()

            if not executable:
                continue

            # Prevent duplicate alerts for
            # the same executable.
            if executable in seen_paths:
                continue

            seen_paths.add(executable)

            # ------------------------------------------------
            # Trusted development environments
            # ------------------------------------------------

            # The monitoring agent itself runs from a
            # Python virtual environment. Do not classify
            # its Python interpreter or installed packages
            # as suspicious.
            if any(
                location in executable
                for location in trusted_development_locations
            ):
                continue

            suspicious = False

            # ------------------------------------------------
            # High-risk writable directories
            # ------------------------------------------------

            if any(
                location in executable
                for location in suspicious_locations
            ):
                suspicious = True

            # ------------------------------------------------
            # AppData requires additional checks
            # ------------------------------------------------

            elif "\\appdata\\" in executable:

                trusted = any(
                    trusted_path in executable
                    for trusted_path in (
                        trusted_appdata_locations
                    )
                )

                if not trusted:
                    suspicious = True

            # ------------------------------------------------
            # Generate finding
            # ------------------------------------------------

            if suspicious:

                self.add_finding(
                    severity="MEDIUM",
                    title=(
                        "Suspicious Executable Path"
                    ),
                    category="Process Location",
                    description=(
                        f"{process.get('name')} "
                        "is running from "
                        f"'{process.get('exe')}'."
                    ),
                    recommendation=(
                        "Verify that the executable "
                        "location is expected and "
                        "trusted."
                    ),
                )

        self.logger.info(
            "Executable path analysis completed."
        )