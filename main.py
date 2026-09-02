"""
Entry point for the Windows Service & Process Monitoring Agent.

This module coordinates the complete Windows security assessment:
1. Process enumeration
2. Windows service enumeration
3. Process tree analysis
4. Security detection
5. Startup service audit
6. Digital signature verification
7. Risk assessment
8. Console reporting
9. PDF security assessment
"""

from time import perf_counter
from datetime import datetime
import os
import textwrap

from core.process_monitor import ProcessMonitor
from core.process_tree import ProcessTree
from core.service_monitor import ServiceMonitor
from core.detection_engine import DetectionEngine
from core.startup_audit import StartupAudit
from core.signature_verifier import SignatureVerifier
from core.risk_engine import RiskEngine

from security_assessment_pdf.pdf_generator import SecurityAssessmentPDF

from utils.logger import Logger


# ============================================================
# ANSI COLORS
# ============================================================

RESET = "\033[0m"
BOLD = "\033[1m"

BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

BRIGHT_RED = "\033[91m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_YELLOW = "\033[93m"
BRIGHT_CYAN = "\033[96m"


LINE_WIDTH = 100


# ============================================================
# COLOR HELPER
# ============================================================

def paint(
    text: str,
    color: str = WHITE,
    bold: bool = False,
) -> str:
    """
    Apply ANSI color formatting to text.
    """

    style = BOLD if bold else ""

    return (
        f"{style}{color}{text}{RESET}"
    )


# ============================================================
# RISK COLOR
# ============================================================

def get_risk_color(
    risk_level: str,
) -> str:
    """
    Return the appropriate color for a risk level.
    """

    level = str(
        risk_level
    ).upper()

    if level == "CRITICAL":
        return BRIGHT_RED

    if level == "HIGH":
        return RED

    if level == "MEDIUM":
        return YELLOW

    if level == "LOW":
        return GREEN

    return BLUE


# ============================================================
# HEADER
# ============================================================

def print_header() -> None:
    """
    Display the application header.
    """

    width = 84

    print()

    print(
        paint(
            "╭" + "─" * width + "╮",
            CYAN,
            True,
        )
    )

    print(
        paint("│", CYAN, True)
        + paint(
            "⚙  WINDOWS SERVICE & PROCESS MONITORING AGENT  ◉".center(
                width
            ),
            CYAN,
            True,
        )
        + paint("│", CYAN, True)
    )

    print(
        paint("│", CYAN, True)
        + paint(
            "Security Assessment Framework".center(
                width
            ),
            WHITE,
        )
        + paint("│", CYAN, True)
    )

    print(
        paint("│", CYAN, True)
        + paint(
            "Version 1.0.0".center(
                width
            ),
            GREEN,
            True,
        )
        + paint("│", CYAN, True)
    )

    print(
        paint(
            "╰" + "─" * width + "╯",
            CYAN,
            True,
        )
    )


# ============================================================
# SECTION HEADER
# ============================================================

def print_section(
    title: str,
) -> None:
    """
    Display a clean CLI section heading.
    """

    width = 84

    print()

    print(
        paint(
            f"─  {title} "
            + "─" * max(
                1,
                width - len(title) - 4,
            ),
            MAGENTA,
            True,
        )
    )


# ============================================================
# SCAN STAGE
# ============================================================

def print_stage(
    number: int,
    title: str,
    result: str = "",
    success: bool = True,
) -> None:
    """
    Display the current scan stage.
    """

    status_icon = "✓" if success else "!"

    status_color = (
        GREEN
        if success
        else YELLOW
    )

    base = (
        f"[{number}/7] {title}"
    )

    dots = "." * max(
        3,
        60 - len(base),
    )

    print(
        paint(
            base,
            WHITE,
        )
        + paint(
            f" {dots} ",
            MAGENTA,
        )
        + paint(
            f"[{status_icon}]",
            status_color,
            True,
        )
        + (
            " "
            + paint(
                result,
                status_color,
                True,
            )
            if result
            else ""
        )
    )


# ============================================================
# PROCESS TREE COUNT
# ============================================================

def get_parent_node_count(
    process_tree: ProcessTree,
) -> int:
    """
    Attempt to obtain the number of parent nodes from the
    existing ProcessTree object without changing its logic.

    If the implementation stores the tree under a different
    attribute, return 0 rather than inventing a value.
    """

    possible_attributes = [
        "tree",
        "process_tree",
        "_tree",
        "children",
        "parent_map",
        "_parent_map",
    ]

    for attribute in possible_attributes:

        try:
            value = getattr(
                process_tree,
                attribute,
            )
        except AttributeError:
            continue

        try:
            return len(value)
        except TypeError:
            continue

    return 0


# ============================================================
# RISK BAR
# ============================================================

def create_risk_bar(
    score: int,
    width: int = 36,
) -> str:
    """
    Create a visual risk score bar.
    """

    score = max(
        0,
        min(
            100,
            int(score),
        ),
    )

    filled = int(
        width * score / 100
    )

    empty = width - filled

    return (
        "█" * filled
        + "░" * empty
    )


# ============================================================
# SCAN SUMMARY
# ============================================================

def print_scan_summary(
    processes: list[dict[str, object]],
    services: list[dict[str, object]],
    findings: list[dict[str, str]],
    risk_score: int,
    risk_level: str,
    duration: float,
) -> None:
    """
    Display the executive scan summary.
    """

    risk_color = get_risk_color(
        risk_level
    )

    CELL = 17
    WIDTH = CELL * 5

    def cell(
        text: str,
        color: str = WHITE,
        bold: bool = False,
    ) -> str:
        """
        Create one fixed-width summary cell.
        """

        return paint(
            text.center(CELL),
            color,
            bold,
        )

    print()

    # --------------------------------------------------------
    # TOP
    # --------------------------------------------------------

    print(
        paint(
            "╭" + "─" * WIDTH + "╮",
            BLUE,
            True,
        )
    )

    print(
        paint("│", BLUE, True)
        + paint(
            "✦  SCAN SUMMARY  ✦".center(
                WIDTH
            ),
            CYAN,
            True,
        )
        + paint("│", BLUE, True)
    )

    print(
        paint(
            "├" + "─" * WIDTH + "┤",
            BLUE,
            True,
        )
    )

    # --------------------------------------------------------
    # ICONS
    # --------------------------------------------------------

    print(
        paint("│", BLUE, True)
        + cell(
            "⚙",
            BLUE,
            True,
        )
        + cell(
            "▣",
            GREEN,
            True,
        )
        + cell(
            "⚠",
            RED,
            True,
        )
        + cell(
            "◉",
            YELLOW,
            True,
        )
        + cell(
            "◷",
            MAGENTA,
            True,
        )
        + paint("│", BLUE, True)
    )

    # --------------------------------------------------------
    # LABELS
    # --------------------------------------------------------

    print(
        paint("│", BLUE, True)
        + cell(
            "PROCESSES",
            BLUE,
            True,
        )
        + cell(
            "SERVICES",
            GREEN,
            True,
        )
        + cell(
            "FINDINGS",
            RED,
            True,
        )
        + cell(
            "RISK SCORE",
            YELLOW,
            True,
        )
        + cell(
            "RISK LEVEL",
            MAGENTA,
            True,
        )
        + paint("│", BLUE, True)
    )

    # --------------------------------------------------------
    # VALUES
    # --------------------------------------------------------

    print(
        paint("│", BLUE, True)
        + cell(
            str(len(processes)),
            GREEN,
            True,
        )
        + cell(
            str(len(services)),
            GREEN,
            True,
        )
        + cell(
            str(len(findings)),
            YELLOW,
            True,
        )
        + cell(
            f"{risk_score} / 100",
            YELLOW,
            True,
        )
        + cell(
            risk_level,
            risk_color,
            True,
        )
        + paint("│", BLUE, True)
    )

    # --------------------------------------------------------
    # SUBLABELS
    # --------------------------------------------------------

    print(
        paint("│", BLUE, True)
        + cell(
            "Scanned",
            WHITE,
        )
        + cell(
            "Scanned",
            WHITE,
        )
        + cell(
            "Total",
            WHITE,
        )
        + cell(
            "Overall Risk",
            WHITE,
        )
        + cell(
            "Current State",
            WHITE,
        )
        + paint("│", BLUE, True)
    )

    # --------------------------------------------------------
    # SEPARATOR
    # --------------------------------------------------------

    print(
        paint(
            "├" + "─" * WIDTH + "┤",
            BLUE,
        )
    )

    # --------------------------------------------------------
    # DURATION
    # --------------------------------------------------------

    duration_text = (
        f"◷  SCAN DURATION   {duration:.2f}s"
    )

    print(
        paint("│", BLUE, True)
        + paint(
            duration_text.center(
                WIDTH
            ),
            CYAN,
            True,
        )
        + paint("│", BLUE, True)
    )

    # --------------------------------------------------------
    # BOTTOM
    # --------------------------------------------------------

    print(
        paint(
            "╰" + "─" * WIDTH + "╯",
            BLUE,
            True,
        )
    )

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    print()

    print(
        "  "
        + paint(
            "◉  RISK LEVEL",
            WHITE,
            True,
        )
    )

    print()

    risk_bar = create_risk_bar(
        risk_score,
        width=36,
    )

    print(
        "  "
        + paint(
            "▐" + risk_bar + "▌",
            risk_color,
            True,
        )
        + "  "
        + paint(
            f"{risk_score}/100",
            risk_color,
            True,
        )
        + "  "
        + paint(
            risk_level,
            risk_color,
            True,
        )
    )


# ============================================================
# FINDING STATISTICS
# ============================================================

def print_finding_overview(
    findings: list[dict[str, str]],
) -> None:
    """
    Display finding counts grouped by severity.
    """

    print_section(
        "DETAILED FINDINGS OVERVIEW"
    )

    severities = [
        ("CRITICAL", RED, "✕"),
        ("HIGH", RED, "◆"),
        ("MEDIUM", YELLOW, "⚠"),
        ("LOW", GREEN, "✓"),
        ("INFO", BLUE, "ⓘ"),
    ]

    counts = {
        severity: 0
        for severity, _, _ in severities
    }

    for finding in findings:

        severity = str(
            finding.get(
                "severity",
                "INFO",
            )
        ).upper()

        if severity in counts:
            counts[severity] += 1

    for severity, color, icon in severities:

        count = counts[severity]

        bar = (
            "█"
            * min(
                count,
                20,
            )
        )

        if not bar:
            bar = "·"

        print(
            "  "
            + paint(
                f"{icon} {severity:<10}",
                color,
                True,
            )
            + paint(
                f"{bar:<20}",
                color,
                True,
            )
            + f" {count}"
        )

def print_finding_card(
    index: int,
    finding: dict[str, str],
) -> None:
    """
    Display one security finding in a clean wrapped card.
    """

    severity = str(
        finding.get(
            "severity",
            "INFO",
        )
    ).upper()

    if severity in {"CRITICAL", "HIGH"}:
        color = RED
        icon = "◆"
    elif severity == "MEDIUM":
        color = YELLOW
        icon = "⚠"
    elif severity == "LOW":
        color = GREEN
        icon = "✓"
    else:
        color = BLUE
        icon = "ⓘ"

    category = str(
        finding.get("category", "Unknown")
    )

    title = str(
        finding.get("title", "Unknown Finding")
    )

    description = str(
        finding.get("description", "")
    )

    recommendation = str(
        finding.get("recommendation", "")
    )

    # Width of the complete card.
    CARD_WIDTH = 84

    # Space available INSIDE the borders.
    CONTENT_WIDTH = CARD_WIDTH - 2

    # Width used for wrapped descriptions.
    TEXT_WIDTH = 66

    def print_line(
        text: str = "",
        color_value: str = WHITE,
        bold: bool = False,
    ) -> None:
        """
        Print one properly aligned line inside the card.
        """

        text = text[:CONTENT_WIDTH]

        print(
            paint("│", WHITE)
            + " "
            + paint(
                text.ljust(CONTENT_WIDTH),
                color_value,
                bold,
            )
            + " "
            + paint("│", WHITE)
        )

    # --------------------------------------------------------
    # TOP BORDER
    # --------------------------------------------------------

    print()

    print(
        paint(
            "╭" + "─" * CARD_WIDTH + "╮",
            WHITE,
        )
    )

    # --------------------------------------------------------
    # FINDING NUMBER + SEVERITY
    # --------------------------------------------------------

    print_line()

    print_line(
        f"[{index}]   {icon}  {severity}",
        color,
        True,
    )

    print_line()

    # --------------------------------------------------------
    # BASIC INFORMATION
    # --------------------------------------------------------

    print_line(
        f"Category      : {category}"
    )

    print_line(
        f"Title         : {title}"
    )

    print_line()

    # --------------------------------------------------------
    # DESCRIPTION
    # --------------------------------------------------------

    print_line(
        "Description",
        WHITE,
        True,
    )

    description_lines = textwrap.wrap(
        description,
        width=TEXT_WIDTH,
        break_long_words=True,
        break_on_hyphens=False,
    )

    for item in description_lines:
        print_line(
            f"    {item}"
        )

    # --------------------------------------------------------
    # RECOMMENDATION
    # --------------------------------------------------------

    if recommendation:

        print_line()

        print_line(
            "Recommendation",
            WHITE,
            True,
        )

        recommendation_lines = textwrap.wrap(
            recommendation,
            width=TEXT_WIDTH,
            break_long_words=True,
            break_on_hyphens=False,
        )

        for item in recommendation_lines:
            print_line(
                f"    {item}"
            )

    print_line()

    # --------------------------------------------------------
    # BOTTOM BORDER
    # --------------------------------------------------------

    print(
        paint(
            "╰" + "─" * CARD_WIDTH + "╯",
            WHITE,
        )
    )

# ============================================================
# TOP FINDINGS
# ============================================================

def print_top_findings(
    findings: list[dict[str, str]],
    limit: int = 5,
) -> None:
    """
    Display the highest-priority security findings.
    """

    print_section(
        "TOP SECURITY FINDINGS"
    )

    if not findings:

        print(
            paint(
                "  ✓ No security findings detected.",
                GREEN,
                True,
            )
        )

        return

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }

    sorted_findings = sorted(
        findings,
        key=lambda item: severity_order.get(
            str(
                item.get(
                    "severity",
                    "INFO",
                )
            ).upper(),
            5,
        ),
    )

    for index, finding in enumerate(
        sorted_findings[:limit],
        start=1,
    ):
        print_finding_card(
            index,
            finding,
        )


# ============================================================
# BOTTOM PANELS
# ============================================================

def print_bottom_panels() -> None:
    """
    Display recommendation and next-step panels.
    """

    BOX = 36
    GAP = "   "

    recommendations = [
        "Review all MEDIUM and HIGH findings.",
        "Verify executable locations.",
        "Check unsigned executables.",
        "Remove suspicious processes/services.",
        "Keep Windows security controls updated.",
    ]

    next_steps = [
        "Investigate identified findings.",
        "Take corrective actions.",
        "Re-run the assessment.",
        "Maintain the security baseline.",
        "Monitor future system changes.",
    ]

    def wrap_items(
        items: list[str],
    ) -> list[str]:

        result: list[str] = []

        for item in items:

            wrapped = textwrap.wrap(
                item,
                width=BOX - 4,
                break_long_words=False,
                break_on_hyphens=False,
            )

            for line in wrapped:

                result.append(
                    f"• {line}"
                )

        return result

    left = wrap_items(
        recommendations
    )

    right = wrap_items(
        next_steps
    )

    height = max(
        len(left),
        len(right),
    )

    left.extend(
        [""] * (
            height - len(left)
        )
    )

    right.extend(
        [""] * (
            height - len(right)
        )
    )

    print()

    # --------------------------------------------------------
    # TOP BORDER
    # --------------------------------------------------------

    print(
        paint(
            "╭" + "─" * BOX + "╮"
            + GAP
            + "╭" + "─" * BOX + "╮",
            CYAN,
        )
    )

    # --------------------------------------------------------
    # TITLES
    # --------------------------------------------------------

    print(
        paint("│", CYAN)
        + paint(
            "  ◈  RECOMMENDATION".center(
                BOX
            ),
            CYAN,
            True,
        )
        + paint("│", CYAN)
        + GAP
        + paint("│", CYAN)
        + paint(
            "  ➤  NEXT STEPS".center(
                BOX
            ),
            CYAN,
            True,
        )
        + paint("│", CYAN)
    )

    print(
        paint("│", CYAN)
        + " " * BOX
        + paint("│", CYAN)
        + GAP
        + paint("│", CYAN)
        + " " * BOX
        + paint("│", CYAN)
    )

    # --------------------------------------------------------
    # CONTENT
    # --------------------------------------------------------

    for left_line, right_line in zip(
        left,
        right,
    ):

        left_line = left_line[:BOX - 2]
        right_line = right_line[:BOX - 2]

        print(
            paint("│", CYAN)
            + f" {left_line}".ljust(
                BOX
            )
            + paint("│", CYAN)
            + GAP
            + paint("│", CYAN)
            + f" {right_line}".ljust(
                BOX
            )
            + paint("│", CYAN)
        )

    # --------------------------------------------------------
    # BOTTOM
    # --------------------------------------------------------

    print(
        paint("│", CYAN)
        + " " * BOX
        + paint("│", CYAN)
        + GAP
        + paint("│", CYAN)
        + " " * BOX
        + paint("│", CYAN)
    )

    print(
        paint(
            "╰" + "─" * BOX + "╯"
            + GAP
            + "╰" + "─" * BOX + "╯",
            CYAN,
        )
    )


# ============================================================
# LOG / REPORT SECTION
# ============================================================

def print_report_section(
    pdf_path: str,
) -> None:
    """
    Display report and log locations.
    """

    print_section(
        "LOGS & REPORT"
    )

    print(
        "  "
        + paint(
            "▣",
            CYAN,
            True,
        )
        + " Detailed logs saved to : "
        + paint(
            "logs\\application.log",
            GREEN,
            True,
        )
    )

    print(
        "  "
        + paint(
            "▣",
            CYAN,
            True,
        )
        + " PDF report generated  : "
        + paint(
            str(pdf_path),
            GREEN,
            True,
        )
    )


# ============================================================
# COMPLETION
# ============================================================

def print_completion() -> None:
    """
    Display the final assessment completion banner.
    """

    width = 84

    print()

    print(
        paint(
            "╭" + "═" * width + "╮",
            GREEN,
            True,
        )
    )

    print(
        paint("│", GREEN, True)
        + paint(
            "✦✦✦  ASSESSMENT COMPLETE  ✦✦✦".center(
                width
            ),
            GREEN,
            True,
        )
        + paint("│", GREEN, True)
    )

    print(
        paint("│", GREEN, True)
        + paint(
            "●  Windows security assessment completed successfully.".center(
                width
            ),
            GREEN,
            True,
        )
        + paint("│", GREEN, True)
    )

    print(
        paint("│", GREEN, True)
        + paint(
            "Thank you for using the Windows Service & Process Monitoring Agent!".center(
                width
            ),
            CYAN,
        )
        + paint("│", GREEN, True)
    )

    print(
        paint(
            "╰" + "═" * width + "╯",
            GREEN,
            True,
        )
    )


# ============================================================
# MAIN
# ============================================================

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

    # ========================================================
    # 1. PROCESS ENUMERATION
    # ========================================================

    print_section(
        "SYSTEM SCAN"
    )

    process_monitor = ProcessMonitor()

    print_stage(
        1,
        "Collecting active Windows processes",
    )

    processes = process_monitor.scan()

    print(
        "      "
        + paint(
            f"✓ {len(processes)} processes collected.",
            GREEN,
            True,
        )
    )

    # ========================================================
    # 2. SERVICE ENUMERATION
    # ========================================================

    print_stage(
        2,
        "Collecting Windows services",
    )

    service_monitor = ServiceMonitor()

    services = service_monitor.scan()

    print(
        "      "
        + paint(
            f"✓ {len(services)} Windows services collected.",
            GREEN,
            True,
        )
    )

    # ========================================================
    # 3. PROCESS TREE
    # ========================================================

    process_tree = ProcessTree()

    print_stage(
        3,
        "Building parent-child process tree",
    )

    process_tree.build_tree(
        processes
    )
    process_tree.print_summary()
    
    parent_nodes = get_parent_node_count(
        process_tree
    )

    if parent_nodes > 0:

        result = (
            f"{parent_nodes} parent nodes"
        )

    else:

        result = (
            "process tree built"
        )

    print(
        "      "
        + paint(
            f"✓ {result}",
            GREEN,
            True,
        )
    )

    # ========================================================
    # 4. DETECTION ENGINE
    # ========================================================

    print_stage(
        4,
        "Running security detections",
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
        "      "
        + paint(
            f"✓ {len(detection_findings)} finding(s) detected.",
            GREEN
            if not detection_findings
            else YELLOW,
            True,
        )
    )

    # ========================================================
    # 5. STARTUP SERVICE AUDIT
    # ========================================================

    print_stage(
        5,
        "Auditing startup services",
    )

    startup_audit = StartupAudit()

    startup_audit.audit(
        services
    )

    startup_findings = (
        startup_audit.get_findings()
    )

    print(
        "      "
        + paint(
            (
                "✓ No suspicious startup services detected."
                if not startup_findings
                else
                f"! {len(startup_findings)} startup finding(s) detected."
            ),
            GREEN
            if not startup_findings
            else YELLOW,
            True,
        )
    )

    # ========================================================
    # 6. DIGITAL SIGNATURE VERIFICATION
    # ========================================================

    print_stage(
        6,
        "Verifying executable digital signatures",
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
        "      "
        + paint(
            f"✓ {len(signature_results)} executables checked.",
            GREEN,
            True,
        )
    )

    print(
        "      "
        + paint(
            f"✓ {len(signature_findings)} signature finding(s) detected.",
            GREEN
            if not signature_findings
            else YELLOW,
            True,
        )
    )

    # ========================================================
    # COMBINE FINDINGS
    # ========================================================

    findings: list[
        dict[str, str]
    ] = []

    findings.extend(
        detection_findings
    )

    findings.extend(
        startup_findings
    )

    findings.extend(
        signature_findings
    )

    # ========================================================
    # 7. RISK ASSESSMENT
    # ========================================================

    print_stage(
        7,
        "Calculating overall system risk",
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

    risk_color = get_risk_color(
        risk_level
    )

    print(
        "      "
        + paint(
            "✓ Risk assessment completed.",
            GREEN,
            True,
        )
    )

    print(
        "      "
        + paint(
            f"Risk: {risk_score}/100  {risk_level}",
            risk_color,
            True,
        )
    )

    # ========================================================
    # TIMING
    # ========================================================

    end_time = perf_counter()

    duration = (
        end_time - start_time
    )

    # ========================================================
    # SCAN SUMMARY
    # ========================================================

    print_scan_summary(
        processes=processes,
        services=services,
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        duration=duration,
    )

    # ========================================================
    # FINDING OVERVIEW
    # ========================================================

    print_finding_overview(
        findings
    )

    # ========================================================
    # TOP FINDINGS
    # ========================================================

    print_top_findings(
        findings,
        limit=5,
    )

    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    print_bottom_panels()

    # ========================================================
    # PDF SECURITY ASSESSMENT
    # ========================================================

    pdf_generator = SecurityAssessmentPDF()

    pdf_path = pdf_generator.generate(
        processes=processes,
        services=services,
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        automatic_services=(
            startup_audit.get_automatic_services()
        ),
        startup_findings=startup_findings,
        signature_results=signature_results,
        signature_findings=signature_findings,
        signature_cache_size=len(
            signature_verifier.signature_cache
        ),
    )

    # ========================================================
    # LOGS + REPORT
    # ========================================================

    print_report_section(
        pdf_path
    )

    # ========================================================
    # COMPLETION
    # ========================================================

    print_completion()

    logger.info(
        "Windows security assessment completed."
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()