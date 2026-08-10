"""
Entry point for the Windows Service & Process Monitoring Agent.
"""

from time import perf_counter

from core.process_monitor import ProcessMonitor
from core.process_tree import ProcessTree
from core.service_monitor import ServiceMonitor
from core.detection_engine import DetectionEngine
from core.startup_audit import StartupAudit
from core.signature_verifier import SignatureVerifier
from core.risk_engine import RiskEngine
from core.report_generator import ReportGenerator

from utils.logger import Logger


LINE_WIDTH = 100


def print_header() -> None:
    """
    Display the application header.
    """

    print("\n" + "=" * LINE_WIDTH)
    print(
        "        WINDOWS SERVICE & PROCESS MONITORING AGENT"
    )
    print("=" * LINE_WIDTH)


def print_stage(
    number: int,
    title: str,
) -> None:
    """
    Display the current scan stage.
    """

    print(
        f"\n[{number}/7] {title}"
    )


def print_final_summary(
    processes: list[dict[str, object]],
    services: list[dict[str, object]],
    findings: list[dict[str, str]],
    risk_score: int,
    risk_level: str,
    duration: float,
) -> None:
    """
    Display a concise final assessment summary.
    """

    print("\n" + "=" * LINE_WIDTH)
    print("                    FINAL ASSESSMENT")
    print("=" * LINE_WIDTH)

    print(
        f"\nProcesses Scanned  : {len(processes)}"
    )

    print(
        f"Services Scanned   : {len(services)}"
    )

    print(
        f"Security Findings  : {len(findings)}"
    )

    print(
        f"Overall Risk Score : {risk_score}"
    )

    print(
        f"Overall Risk Level : {risk_level}"
    )

    print(
        f"Scan Duration      : {duration:.2f} seconds"
    )

    print("\n" + "=" * LINE_WIDTH)


def main() -> None:
    """
    Run the complete Windows security assessment.
    """

    logger = Logger()

    logger.info(
        "Windows Service & Process Monitoring Agent started."
    )

    print_header()

    start_time = perf_counter()

    # =================================================
    # 1. Process Enumeration
    # =================================================

    print_stage(
        1,
        "Collecting active Windows processes...",
    )

    process_monitor = ProcessMonitor()

    processes = process_monitor.scan()

    print(
        f"      Collected {len(processes)} processes."
    )

    # =================================================
    # 2. Windows Service Enumeration
    # =================================================

    print_stage(
        2,
        "Collecting Windows services...",
    )

    service_monitor = ServiceMonitor()

    services = service_monitor.scan()

    print(
        f"      Collected {len(services)} services."
    )

    # =================================================
    # 3. Process Tree Analysis
    # =================================================

    print_stage(
        3,
        "Building parent-child process tree...",
    )

    process_tree = ProcessTree()

    process_tree.build_tree(
        processes
    )

    print(
        "      Process tree built successfully."
    )

    # =================================================
    # 4. Detection Engine
    # =================================================

    print_stage(
        4,
        "Running security detections...",
    )

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

    detection_findings = (
        detection_engine.get_findings()
    )

    print(
        f"      Detection findings: "
        f"{len(detection_findings)}"
    )

    # =================================================
    # 5. Startup Service Audit
    # =================================================

    print_stage(
        5,
        "Auditing startup services...",
    )

    startup_audit = StartupAudit()

    startup_audit.audit(
        services
    )

    startup_findings = (
        startup_audit.get_findings()
    )

    print(
        f"      Startup findings: "
        f"{len(startup_findings)}"
    )

    # =================================================
    # 6. Digital Signature Verification
    # =================================================

    print_stage(
        6,
        "Verifying executable digital signatures...",
    )

    signature_verifier = SignatureVerifier()

    signature_results = (
        signature_verifier.verify_processes(
            processes
        )
    )

    signature_findings = (
        signature_verifier.get_findings()
    )

    print(
        f"      Executables checked: "
        f"{len(signature_results)}"
    )

    print(
        f"      Signature findings: "
        f"{len(signature_findings)}"
    )

    # =================================================
    # Combine Security Findings
    # =================================================

    findings: list[dict[str, str]] = []

    findings.extend(
        detection_findings
    )

    findings.extend(
        startup_findings
    )

    findings.extend(
        signature_findings
    )

    # =================================================
    # 7. Risk Assessment
    # =================================================

    print_stage(
        7,
        "Calculating overall system risk...",
    )

    risk_engine = RiskEngine()

    risk_score = (
        risk_engine.calculate_overall(
            findings
        )
    )

    risk_level = (
        risk_engine.score_to_severity(
            risk_score
        )
    )

    print(
        f"      Risk Score: {risk_score}"
    )

    print(
        f"      Risk Level: {risk_level}"
    )

    # =================================================
    # Final Timing
    # =================================================

    end_time = perf_counter()

    duration = (
        end_time - start_time
    )

    # =================================================
    # Final Summary
    # =================================================

    print_final_summary(
        processes=processes,
        services=services,
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        duration=duration,
    )

    # =================================================
    # Console Security Report
    # =================================================

    report_generator = ReportGenerator()

    report_generator.generate_console_report(
        processes=processes,
        services=services,
        findings=findings,
    )

    logger.info(
        "Windows security assessment completed."
    )


if __name__ == "__main__":
    main()