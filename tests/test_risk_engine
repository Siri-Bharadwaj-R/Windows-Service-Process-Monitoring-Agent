"""
Test script for the RiskEngine module.
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.detection_engine import DetectionEngine
from core.process_monitor import ProcessMonitor
from core.risk_engine import RiskEngine


def main() -> None:
    """
    Test the RiskEngine module.
    """

    monitor = ProcessMonitor()

    processes = monitor.scan()

    detection_engine = DetectionEngine()

    detection_engine.detect_suspicious_parent_child(
        processes
    )

    detection_engine.detect_blacklisted_processes(
        processes
    )

    detection_engine.detect_suspicious_paths(
        processes
    )

    findings = detection_engine.get_findings()

    risk_engine = RiskEngine()

    print("\n" + "=" * 100)
    print("RISK ENGINE TEST")
    print("=" * 100)

    if not findings:

        print("\nNo findings available.")

        return

    for index, finding in enumerate(
        findings,
        start=1,
    ):

        score = risk_engine.score_finding(
            finding
        )

        print(f"\nFinding #{index}")

        print(f"Severity : {finding['severity']}")
        print(f"Score    : {score}")

        print(f"Title    : {finding['title']}")

        print("-" * 100)

    overall_score = risk_engine.calculate_overall(
        findings
    )

    overall_severity = (
        risk_engine.score_to_severity(
            overall_score
        )
    )

    print("\n" + "=" * 100)
   


if __name__ == "__main__":
    main()