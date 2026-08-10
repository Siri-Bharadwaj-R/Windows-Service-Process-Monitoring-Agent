"""
Security recommendations section for the
Windows Service & Process Monitoring Agent PDF report.
"""


def build_recommendations(
    findings: list[dict[str, str]],
) -> list[str]:
    """
    Build security recommendations based on
    the detected findings.

    Args:
        findings:
            Combined security findings generated
            by the monitoring agent.

    Returns:
        List of unique security recommendations.
    """

    recommendations: list[str] = []
    seen: set[str] = set()

    for finding in findings:

        recommendation = str(
            finding.get("recommendation")
            or ""
        ).strip()

        if not recommendation:
            continue

        normalized = recommendation.lower()

        if normalized in seen:
            continue

        seen.add(normalized)

        recommendations.append(
            recommendation
        )

    if not recommendations:

        recommendations.append(
            "No immediate security recommendations "
            "were generated because no security findings "
            "were detected."
        )

    return recommendations