"""
Test script for the StartupAudit module.
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.service_monitor import ServiceMonitor
from core.startup_audit import StartupAudit


def main() -> None:
    """
    Test the StartupAudit module.
    """

    print("\n" + "=" * 100)
    print("STARTUP SERVICE AUDIT TEST")
    print("=" * 100)

    # -------------------------------------------------
    # Collect Windows Services
    # -------------------------------------------------

    service_monitor = ServiceMonitor()

    services = service_monitor.scan()

    # -------------------------------------------------
    # Run Startup Audit
    # -------------------------------------------------

    startup_audit = StartupAudit()

    startup_audit.audit(services)

    automatic_services = (
        startup_audit.get_automatic_services()
    )

    findings = startup_audit.get_findings()

    # -------------------------------------------------
    # Display Automatic Services
    # -------------------------------------------------

    print("\nAutomatic Startup Services")
    print("-" * 100)

    print(
        f"{'Service Name':<35}"
        f"{'State':<12}"
        f"{'Account'}"
    )

    print("-" * 100)

    for service in automatic_services[:10]:

        print(
            f"{service['name']:<35}"
            f"{service['state']:<12}"
            f"{service['account']}"
        )

    print("-" * 100)

    print(
        f"Showing first "
        f"{min(10, len(automatic_services))} "
        f"of {len(automatic_services)} "
        f"automatic startup services."
    )

    # -------------------------------------------------
    # Display Findings
    # -------------------------------------------------

    print("\n" + "=" * 100)
    print("STARTUP AUDIT FINDINGS")
    print("=" * 100)

    if not findings:

        print("\nNo suspicious startup services detected.")

    else:

        for index, finding in enumerate(
            findings,
            start=1,
        ):

            print(f"\nFinding #{index}")

            print(
                f"Severity       : "
                f"{finding['severity']}"
            )

            print(
                f"Category       : "
                f"{finding['category']}"
            )

            print(
                f"Title          : "
                f"{finding['title']}"
            )

            print(
                f"Description    : "
                f"{finding['description']}"
            )

            print(
                f"Recommendation : "
                f"{finding['recommendation']}"
            )

            print("-" * 100)


if __name__ == "__main__":
    main()