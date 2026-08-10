"""
Risk scoring utilities for the
Windows Service & Process Monitoring Agent.
"""

from utils.logger import Logger


class RiskEngine:
    """
    Calculates risk scores and severity levels
    for security findings.
    """

    SCORE_MAP = {
        "INFO": 10,
        "LOW": 25,
        "MEDIUM": 50,
        "HIGH": 75,
        "CRITICAL": 100,
    }

    def __init__(self) -> None:
        """
        Initialize the risk engine.
        """

        self.logger = Logger()

    def score_finding(
        self,
        finding: dict[str, str],
    ) -> int:
        """
        Return the numeric risk score for a finding.
        """

        severity = str(
            finding.get("severity", "INFO")
        ).upper()

        return self.SCORE_MAP.get(
            severity,
            self.SCORE_MAP["INFO"],
        )

    def score_to_severity(
        self,
        score: int,
    ) -> str:
        """
        Convert a numeric score into a severity level.
        """

        if score >= 100:
            return "CRITICAL"

        if score >= 75:
            return "HIGH"

        if score >= 50:
            return "MEDIUM"

        if score >= 25:
            return "LOW"

        return "INFO"

    def calculate_overall(
        self,
        findings: list[dict[str, str]],
    ) -> int:
        """
        Calculate the overall system risk score.

        The highest severity finding determines
        the overall risk score.
        """

        if not findings:
            return 0

        scores = [
            self.score_finding(finding)
            for finding in findings
        ]

        return max(scores)

    def statistics(
        self,
        findings: list[dict[str, str]],
    ) -> dict[str, int]:
        """
        Return statistics about findings by severity.
        """

        stats = {
            "INFO": 0,
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        for finding in findings:

            severity = str(
                finding.get("severity", "INFO")
            ).upper()

            if severity in stats:
                stats[severity] += 1

        return stats