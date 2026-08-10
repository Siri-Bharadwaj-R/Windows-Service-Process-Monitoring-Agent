"""
Risk overview section for the
Windows Service & Process Monitoring Agent PDF report.
"""


def build_risk_overview(
    risk_score: int,
    risk_level: str,
) -> dict[str, str]:
    """
    Build overall risk information for the
    security assessment report.

    Args:
        risk_score:
            Overall numeric risk score.

        risk_level:
            Overall risk severity.

    Returns:
        Dictionary containing risk information.
    """

    return {
        "risk_score": str(risk_score),
        "risk_level": str(risk_level).upper(),
    }