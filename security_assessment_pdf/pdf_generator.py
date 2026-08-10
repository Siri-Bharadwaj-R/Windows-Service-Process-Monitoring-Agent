"""
Professional PDF generator for the
Windows Service & Process Monitoring Agent.
"""

from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .scan_information import build_scan_information
from .risk_overview import build_risk_overview
from .finding_statistics import build_finding_statistics
from .process_information import build_process_information
from .service_information import build_service_information
from .startup_audit import build_startup_audit
from .digital_signature_results import (
    build_digital_signature_results
)
from .security_findings import build_security_findings
from .recommendations import build_recommendations

def wrap_path(path):
    if not path:
        return ""

    # Display Windows paths safely in the PDF.
    return str(path).replace("\\", "/")
LINE_WIDTH = 100


class SecurityAssessmentPDF:
    """
    Generates the final security assessment PDF.
    """

    def __init__(self, output_directory: str = "reports") -> None:
        """
        Initialize the PDF generator.
        """

        self.output_directory = Path(output_directory)

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.styles = getSampleStyleSheet()

        self.title_style = ParagraphStyle(
            "ReportTitle",
            parent=self.styles["Title"],
            alignment=TA_CENTER,
            fontSize=22,
            leading=28,
            spaceAfter=12,
        )

        self.subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=self.styles["Normal"],
            alignment=TA_CENTER,
            fontSize=13,
            leading=18,
            spaceAfter=20,
        )

        self.section_style = ParagraphStyle(
            "SectionHeading",
            parent=self.styles["Heading1"],
            fontSize=16,
            leading=20,
            spaceBefore=8,
            spaceAfter=12,
        )

        self.subsection_style = ParagraphStyle(
            "SubsectionHeading",
            parent=self.styles["Heading2"],
            fontSize=12,
            leading=15,
            spaceBefore=8,
            spaceAfter=6,
        )

        self.body_style = ParagraphStyle(
            "ReportBody",
            parent=self.styles["BodyText"],
            fontSize=9,
            leading=13,
            spaceAfter=6,
        )

        self.small_style = ParagraphStyle(
            "SmallText",
            parent=self.styles["BodyText"],
            fontSize=7,
            leading=9,
            spaceAfter=3,
        )

    def _header_footer(
        self,
        canvas,
        document,
    ) -> None:
        """
        Draw the report header and footer.
        """

        canvas.saveState()

        width, height = A4

        canvas.setFont(
            "Helvetica",
            8,
        )

        canvas.drawString(
            15 * mm,
            height - 12 * mm,
            "Windows Service & Process Monitoring Agent",
        )

        canvas.drawRightString(
            width - 15 * mm,
            10 * mm,
            f"Page {document.page}",
        )

        canvas.restoreState()

    def _create_table(
        self,
        data: list[list[str]],
        column_widths: list[float] | None = None,
        font_size: int = 8,
    ) -> Table:
        """
        Create a consistently formatted report table.
        """

        table = Table(
            data,
            colWidths=column_widths,
            repeatRows=1,
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#1F2937"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "FONTNAME",
                        (0, 1),
                        (-1, -1),
                        "Helvetica",
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        font_size,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        return table

    def _add_key_value_table(
        self,
        story: list,
        title: str,
        values: dict[str, str],
    ) -> None:
        """
        Add a simple key-value section.
        """

        story.append(
            Paragraph(
                title,
                self.section_style,
            )
        )

        data = [
            ["Field", "Value"],
        ]

        for key, value in values.items():

            data.append(
                [
                    key.replace("_", " ").title(),
                    str(value),
                ]
            )

        story.append(
            self._create_table(
                data,
                column_widths=[
                    55 * mm,
                    120 * mm,
                ],
            )
        )

        story.append(
            Spacer(1, 8)
        )

    def generate(
        self,
        processes: list[dict[str, object]],
        services: list[dict[str, object]],
        findings: list[dict[str, str]],
        risk_score: int,
        risk_level: str,
        automatic_services: list[dict[str, object]],
        startup_findings: list[dict[str, str]],
        signature_results: list[dict[str, object]],
        signature_findings: list[dict[str, str]],
        signature_cache_size: int,
    ) -> str:
        """
        Generate the complete security assessment PDF.

        Returns:
            Path to the generated PDF.
        """

        timestamp = datetime.now().strftime(
            "%Y-%m-%d_%H-%M-%S"
        )

        output_path = (
            self.output_directory
            / f"Security_Assessment_{timestamp}.pdf"
        )

        scan_information = build_scan_information(
            process_count=len(processes),
            service_count=len(services),
        )

        risk_overview = build_risk_overview(
            risk_score=risk_score,
            risk_level=risk_level,
        )

        finding_statistics = build_finding_statistics(
            findings
        )

        process_information = build_process_information(
            processes
        )

        service_information = build_service_information(
            services
        )

        startup_information = build_startup_audit(
            automatic_services=automatic_services,
            findings=startup_findings,
        )

        signature_information = (
            build_digital_signature_results(
                results=signature_results,
                findings=signature_findings,
                unique_paths=signature_cache_size,
            )
        )

        security_findings = build_security_findings(
            findings
        )

        recommendations = build_recommendations(
            findings
        )

        frame = Frame(
            15 * mm,
            15 * mm,
            A4[0] - 30 * mm,
            A4[1] - 30 * mm,
            id="normal",
        )

        document = BaseDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=15 * mm,
            leftMargin=15 * mm,
            topMargin=18 * mm,
            bottomMargin=15 * mm,
            title="Windows Service & Process Monitoring Agent",
            author="Windows Security Monitoring Agent",
        )

        document.addPageTemplates(
            [
                PageTemplate(
                    id="Report",
                    frames=frame,
                    onPage=self._header_footer,
                )
            ]
        )

        story: list = []

        # -------------------------------------------------
        # Cover Page
        # -------------------------------------------------

        story.append(
            Spacer(1, 55 * mm)
        )

        story.append(
            Paragraph(
                "WINDOWS SERVICE & PROCESS<br/>"
                "MONITORING AGENT",
                self.title_style,
            )
        )

        story.append(
            Paragraph(
                "Security Assessment Report",
                self.subtitle_style,
            )
        )

        story.append(
            Paragraph(
                f"Generated: "
                f"{scan_information['scan_time']}",
                self.body_style,
            )
        )

        story.append(
            Spacer(1, 15 * mm)
        )

        cover_data = [
            ["Risk Score", risk_overview["risk_score"]],
            ["Risk Level", risk_overview["risk_level"]],
            [
                "Processes Scanned",
                scan_information["processes_scanned"],
            ],
            [
                "Services Scanned",
                scan_information["services_scanned"],
            ],
            [
                "Security Findings",
                str(len(security_findings)),
            ],
        ]

        story.append(
            self._create_table(
                [
                    ["Assessment", "Result"],
                    *cover_data,
                ],
                column_widths=[
                    75 * mm,
                    75 * mm,
                ],
                font_size=10,
            )
        )

        story.append(
            PageBreak()
        )

        # -------------------------------------------------
        # Scan Information
        # -------------------------------------------------

        self._add_key_value_table(
            story,
            "1. Scan Information",
            scan_information,
        )

        # -------------------------------------------------
        # Risk Overview
        # -------------------------------------------------

        self._add_key_value_table(
            story,
            "2. Overall Risk",
            risk_overview,
        )

        # -------------------------------------------------
        # Finding Statistics
        # -------------------------------------------------

        story.append(
            Paragraph(
                "3. Finding Statistics",
                self.section_style,
            )
        )

        statistics_data = [
            ["Severity", "Count"],
        ]

        for severity in [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        ]:
            statistics_data.append(
                [
                    severity,
                    str(
                        finding_statistics[
                            severity
                        ]
                    ),
                ]
            )

        story.append(
            self._create_table(
                statistics_data,
                column_widths=[
                    75 * mm,
                    75 * mm,
                ],
            )
        )

        story.append(
            PageBreak()
        )

        # -------------------------------------------------
        # Security Findings
        # -------------------------------------------------

        story.append(
            Paragraph(
                "4. Security Findings",
                self.section_style,
            )
        )

        if not security_findings:

            story.append(
                Paragraph(
                    "No security findings were detected.",
                    self.body_style,
                )
            )

        else:

            for index, finding in enumerate(
                security_findings,
                start=1,
            ):

                story.append(
                    Paragraph(
                        f"Finding #{index}",
                        self.subsection_style,
                    )
                )

                finding_data = [
                    ["Field", "Details"],
                    [
                        "Severity",
                        Paragraph(
                            finding["severity"],
                            self.body_style,
                        ),
                    ],
                    [
                        "Category",
                        Paragraph(
                            finding["category"],
                            self.body_style,
                        ),
                    ],
                    [
                        "Title",
                        Paragraph(
                            finding["title"],
                            self.body_style,
                        ),
                    ],
                    [
                        "Description",
                        Paragraph(
                            wrap_path(finding["description"]),
                            self.body_style,
                        ),
                    ],
                    [
                        "Recommendation",
                        Paragraph(
                            finding["recommendation"],
                            self.body_style,
                        ),
                    ],
                ]

                story.append(
                    self._create_table(
                        finding_data,
                        column_widths=[
                            40 * mm,
                            135 * mm,
                        ],
                        font_size=8,
                    )
                )

                story.append(
                    Spacer(1, 8)
                )

        story.append(
            PageBreak()
        )

        # -------------------------------------------------
        # Process Information
        # -------------------------------------------------

        story.append(
            Paragraph(
                "5. Process Information",
                self.section_style,
            )
        )

        story.append(
            Paragraph(
                f"Total processes collected: "
                f"{len(process_information)}",
                self.body_style,
            )
        )

        process_data = [
            [
                "PID",
                "PPID",
                "Process",
                "Status",
                "User",
            ]
        ]

        for process in process_information:

            process_data.append(
                [
                    process["pid"],
                    process["ppid"],
                    process["name"],
                    process["status"],
                    process["username"],
                ]
            )

        process_table = Table(
            process_data,
            repeatRows=1,
            colWidths=[
                18 * mm,
                18 * mm,
                55 * mm,
                28 * mm,
                50 * mm,
            ],
        )

        process_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#1F2937"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.3,
                        colors.grey,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                ]
            )
        )

        story.append(process_table)

        story.append(
            PageBreak()
        )

        # -------------------------------------------------
        # Service Information
        # -------------------------------------------------

        story.append(
            Paragraph(
                "6. Windows Service Information",
                self.section_style,
            )
        )

        story.append(
            Paragraph(
                f"Total services collected: "
                f"{len(service_information)}",
                self.body_style,
            )
        )

        service_data = [
            [
                "Service",
                "State",
                "Start Mode",
                "Account",
            ]
        ]

        for service in service_information:

            service_data.append(
                [
                    service["name"],
                    service["state"],
                    service["start_mode"],
                    service["account"],
                ]
            )

        service_table = Table(
            service_data,
            repeatRows=1,
            colWidths=[
                55 * mm,
                30 * mm,
                35 * mm,
                55 * mm,
            ],
        )

        service_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#1F2937"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.3,
                        colors.grey,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                ]
            )
        )

        story.append(service_table)

        story.append(
            PageBreak()
        )

        # -------------------------------------------------
        # Startup Audit
        # -------------------------------------------------

        story.append(
            Paragraph(
                "7. Startup Service Audit",
                self.section_style,
            )
        )

        startup_summary = [
            ["Metric", "Value"],
            [
                "Automatic Startup Services",
                str(
                    startup_information[
                        "automatic_service_count"
                    ]
                ),
            ],
            [
                "Startup Audit Findings",
                str(
                    startup_information[
                        "finding_count"
                    ]
                ),
            ],
        ]

        story.append(
            self._create_table(
                startup_summary,
                column_widths=[
                    90 * mm,
                    60 * mm,
                ],
            )
        )

        story.append(
            Spacer(1, 8)
        )

        if startup_information["findings"]:

            story.append(
                Paragraph(
                    "Startup Audit Findings",
                    self.subsection_style,
                )
            )

            for finding in startup_information[
                "findings"
            ]:

                story.append(
                    Paragraph(
                        f"<b>{finding['title']}</b> — "
                        f"{finding['description']}",
                        self.body_style,
                    )
                )

        story.append(
            PageBreak()
        )

        # -------------------------------------------------
        # Digital Signature Verification
        # -------------------------------------------------

        story.append(
            Paragraph(
                "8. Digital Signature Verification",
                self.section_style,
            )
        )

        signature_summary = [
            ["Metric", "Value"],
            [
                "Executables Checked",
                str(
                    signature_information[
                        "executables_checked"
                    ]
                ),
            ],
            [
                "Unique Executable Paths",
                str(
                    signature_information[
                        "unique_paths"
                    ]
                ),
            ],
            [
                "Valid Signatures",
                str(
                    signature_information[
                        "valid_signatures"
                    ]
                ),
            ],
            [
                "Unsigned Executables",
                str(
                    signature_information[
                        "unsigned"
                    ]
                ),
            ],
            [
                "Other Signature States",
                str(
                    signature_information[
                        "other_status"
                    ]
                ),
            ],
        ]

        story.append(
            self._create_table(
                signature_summary,
                column_widths=[
                    90 * mm,
                    60 * mm,
                ],
            )
        )

        story.append(
            Spacer(1, 10)
        )

        unsigned = signature_information[
            "unsigned_executables"
        ]

        if unsigned:

            story.append(
                Paragraph(
                    "Unsigned Executables",
                    self.subsection_style,
                )
            )

            unsigned_data = [
                [
                    "Process",
                    "Publisher",
                    "Status",
                ]
            ]

            for item in unsigned:

                unsigned_data.append(
                    [
                        item["process_name"],
                        item["publisher"],
                        item["status"],
                    ]
                )

            story.append(
                self._create_table(
                    unsigned_data,
                    column_widths=[
                        70 * mm,
                        65 * mm,
                        40 * mm,
                    ],
                    font_size=7,
                )
            )

        story.append(
            PageBreak()
        )

        # -------------------------------------------------
        # Recommendations
        # -------------------------------------------------

        story.append(
            Paragraph(
                "9. Security Recommendations",
                self.section_style,
            )
        )

        for index, recommendation in enumerate(
            recommendations,
            start=1,
        ):

            story.append(
                Paragraph(
                    f"{index}. {recommendation}",
                    self.body_style,
                )
            )

        story.append(
            Spacer(1, 12)
        )

        story.append(
            Paragraph(
                "End of Security Assessment Report",
                self.subtitle_style,
            )
        )

        document.build(story)

        return str(output_path)