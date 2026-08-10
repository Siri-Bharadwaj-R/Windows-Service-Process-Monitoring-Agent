"""
Test script for the SignatureVerifier module.
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.append(
    str(Path(__file__).resolve().parent.parent)
)

from core.process_monitor import ProcessMonitor
from core.signature_verifier import SignatureVerifier


def main() -> None:
    """
    Test the SignatureVerifier module.
    """

    print("\n" + "=" * 100)
    print("DIGITAL SIGNATURE VERIFICATION TEST")
    print("=" * 100)

    # -------------------------------------------------
    # Collect Processes
    # -------------------------------------------------

    process_monitor = ProcessMonitor()

    processes = process_monitor.scan()

    # -------------------------------------------------
    # Verify Signatures
    # -------------------------------------------------

    verifier = SignatureVerifier()

    results = verifier.verify_processes(
        processes
    )

    findings = verifier.get_findings()

    # -------------------------------------------------
    # Calculate Statistics
    # -------------------------------------------------

    valid_count = sum(
        result.get("status") == "Valid"
        for result in results
    )

    unsigned_count = sum(
        result.get("status") == "NotSigned"
        for result in results
    )

    other_count = len(results) - (
        valid_count + unsigned_count
    )

    unique_paths = len(
        verifier.signature_cache
    )

    # -------------------------------------------------
    # Display Summary
    # -------------------------------------------------

    print("\n" + "=" * 100)
    print("SIGNATURE VERIFICATION SUMMARY")
    print("=" * 100)

    print(
        f"Processes Collected : {len(processes)}"
    )

    print(
        f"Executables Checked : {len(results)}"
    )

    print(
        f"Unique Executables  : {unique_paths}"
    )

    print(
        f"Valid Signatures    : {valid_count}"
    )

    print(
        f"Unsigned            : {unsigned_count}"
    )

    print(
        f"Other Status        : {other_count}"
    )

    # -------------------------------------------------
    # Display Unsigned Executables
    # -------------------------------------------------

    print("\n" + "=" * 100)
    print("UNSIGNED EXECUTABLES")
    print("=" * 100)

    unsigned_results = [
        result
        for result in results
        if result.get("status") == "NotSigned"
    ]

    if not unsigned_results:

        print("\nNo unsigned executables detected.")

    else:

        displayed_paths: set[str] = set()

        for result in unsigned_results:

            path = str(
                result.get("path")
                or "Unknown"
            )

            normalized_path = path.lower()

            if normalized_path in displayed_paths:
                continue

            displayed_paths.add(
                normalized_path
            )

            process_name = (
                result.get("process_name")
                or "Unknown"
            )

            publisher = (
                result.get("publisher")
                or "Unknown"
            )

            print(
                f"\nProcess   : {process_name}"
            )

            print(
                f"Path      : {path}"
            )

            print(
                f"Publisher : {publisher}"
            )

            print(
                f"Status    : "
                f"{result.get('status')}"
            )

            print("-" * 100)

    # -------------------------------------------------
    # Display Other Signature States
    # -------------------------------------------------

    print("\n" + "=" * 100)
    print("OTHER SIGNATURE STATES")
    print("=" * 100)

    other_results = [
        result
        for result in results
        if result.get("status")
        not in {
            "Valid",
            "NotSigned",
        }
    ]

    if not other_results:

        print("\nNo unusual signature states detected.")

    else:

        displayed_paths: set[str] = set()

        for result in other_results:

            path = str(
                result.get("path")
                or "Unknown"
            )

            normalized_path = path.lower()

            if normalized_path in displayed_paths:
                continue

            displayed_paths.add(
                normalized_path
            )

            print(
                f"\nProcess   : "
                f"{result.get('process_name') or 'Unknown'}"
            )

            print(
                f"Path      : {path}"
            )

            print(
                f"Status    : "
                f"{result.get('status')}"
            )

            print(
                f"Publisher : "
                f"{result.get('publisher') or 'Unknown'}"
            )

            print("-" * 100)

    # -------------------------------------------------
    # Display Security Findings
    # -------------------------------------------------

    print("\n" + "=" * 100)
    print("SIGNATURE SECURITY FINDINGS")
    print("=" * 100)

    if not findings:

        print(
            "\nNo unsigned executable findings detected."
        )

    else:

        for index, finding in enumerate(
            findings,
            start=1,
        ):

            print(
                f"\nFinding #{index}"
            )

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

    # -------------------------------------------------
    # Final Test Status
    # -------------------------------------------------

    print("\n" + "=" * 100)
    print("SIGNATURE VERIFICATION TEST COMPLETED")
    print("=" * 100)


if __name__ == "__main__":
    main()