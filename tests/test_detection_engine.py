"""
Test script for the DetectionEngine module.
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.detection_engine import DetectionEngine
from core.process_monitor import ProcessMonitor


def main() -> None:
    """
    Test the DetectionEngine module.
    """

    monitor = ProcessMonitor()

    processes = monitor.scan()

    engine = DetectionEngine()

    engine.detect_suspicious_parent_child(processes)

    engine.detect_blacklisted_processes(processes)
    
    engine.detect_suspicious_paths(processes)

    findings = engine.get_findings()

    print("\n" + "=" * 100)
    print("DETECTION ENGINE TEST")
    print("=" * 100)

    print(f"\nFindings Generated : {len(findings)}")

    print("-" * 100)

    if not findings:

        print("No security findings detected.")

    else:

        for index, finding in enumerate(findings, start=1):

            print(f"\nFinding #{index}")

            print(f"Severity       : {finding['severity']}")
            print(f"Title          : {finding['title']}")
            print(f"Category       : {finding['category']}")
            print(f"Description    : {finding['description']}")
            print(f"Recommendation : {finding['recommendation']}")

            print("-" * 100)


if __name__ == "__main__":
    main()