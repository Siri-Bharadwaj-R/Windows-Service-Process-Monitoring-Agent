"""
Test script for the ServiceMonitor module.
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.service_monitor import ServiceMonitor


def main() -> None:
    """
    Test the ServiceMonitor module.
    """

    monitor = ServiceMonitor()

    monitor.scan()

    print("\n" + "=" * 100)
    print("WINDOWS SERVICE MONITOR TEST")
    print("=" * 100)

    # ------------------------------------------------------------------
    # Test statistics()
    # ------------------------------------------------------------------

    stats = monitor.statistics()

    print("\nService Statistics")

    print("-" * 100)

    print(f"Total Services : {stats['total']}")
    print(f"Running        : {stats['running']}")
    print(f"Stopped        : {stats['stopped']}")
    print(f"Automatic      : {stats['automatic']}")
    print(f"Manual         : {stats['manual']}")
    print(f"Disabled       : {stats['disabled']}")

    # ------------------------------------------------------------------
    # Test get_running_services()
    # ------------------------------------------------------------------

    running_services = monitor.get_running_services()

    print("\n" + "=" * 100)
    print("RUNNING SERVICES")
    print("=" * 100)

    print(f"\nRunning Services : {len(running_services)}")

    print("-" * 100)

    print(
        f"{'Service Name':<35}"
        f"{'PID':<8}"
        f"{'Account'}"
    )

    print("-" * 100)

    for service in running_services[:10]:

        print(
            f"{service['name']:<35}"
            f"{service['pid']:<8}"
            f"{service['account']}"
        )

    print("-" * 100)

    # ------------------------------------------------------------------
    # Test get_service()
    # ------------------------------------------------------------------

    print("\nSearching for WinDefend...")

    defender = monitor.get_service("WinDefend")

    if defender:

        print("Found!")

        print(f"Display Name : {defender['display_name']}")
        print(f"State        : {defender['state']}")
        print(f"Start Mode   : {defender['start_mode']}")

    else:

        print("Service not found.")

    # ------------------------------------------------------------------
    # Test find_service()
    # ------------------------------------------------------------------

    print("\nSearching for services containing 'audio'...")

    matches = monitor.find_service("audio")

    print(f"Found {len(matches)} matching services.\n")

    for service in matches:

        print(
            f"{service['name']}"
            f" ({service['state']})"
        )


if __name__ == "__main__":
    main()