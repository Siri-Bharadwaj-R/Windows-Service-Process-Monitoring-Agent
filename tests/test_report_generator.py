"""
Test script for the ReportGenerator module.
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.process_monitor import ProcessMonitor
from core.service_monitor import ServiceMonitor
from core.detection_engine import DetectionEngine
from core.report_generator import ReportGenerator


def main() -> None:
    """
    Test the ReportGenerator module.
    """

    print("\n" + "=" * 100)
    print("REPORT GENERATOR TEST")
    print("=" * 100)

    # -------------------------------------------------
    # Collect System Information
    # -------------------------------------------------

    process_monitor = ProcessMonitor()
    service_monitor = ServiceMonitor()

    processes = process_monitor.scan()
    services = service_monitor.scan()

    # -------------------------------------------------
    # Run Detection Engine
    # -------------------------------------------------

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

    # -------------------------------------------------
    # Generate Report
    # -------------------------------------------------

    report_generator = ReportGenerator()

    report_generator.generate_console_report(
        processes,
        services,
        findings,
    )


if __name__ == "__main__":
    main()