"""
Entry point for the Windows Service & Process Monitoring Agent.
"""

from time import perf_counter

from core.process_monitor import ProcessMonitor
from utils.logger import Logger

LINE_WIDTH = 100


def print_header() -> None:
    """
    Print the application header.
    """

    print("\n" + "=" * LINE_WIDTH)
    print("        Windows Service & Process Monitoring Agent")
    print("=" * LINE_WIDTH)


def print_process_table(
    processes: list[dict[str, object]],
    limit: int = 10,
) -> None:
    """
    Display collected processes in a formatted table.

    Args:
        processes: List of collected processes.
        limit: Maximum number of processes to display.
    """

    print(f"\nProcesses Collected : {len(processes)}")
    print("-" * LINE_WIDTH)

    print(
        f"{'PID':<8}"
        f"{'PPID':<8}"
        f"{'Process Name':<35}"
        f"{'Status':<12}"
        f"{'User'}"
    )

    print("-" * LINE_WIDTH)

    for process in processes[:limit]:

        process_name = process["name"] or "N/A"
        username = process["username"] or "N/A"

        print(
            f"{process['pid']:<8}"
            f"{process['ppid']:<8}"
            f"{process_name:<35}"
            f"{process['status']:<12}"
            f"{username}"
        )

    print("-" * LINE_WIDTH)
    print(f"Showing first {min(limit, len(processes))} of {len(processes)} processes.")


def print_summary(
    total_processes: int,
    displayed: int,
    duration: float,
) -> None:
    """
    Display scan summary.
    """

    print("\n" + "=" * LINE_WIDTH)
    print("Scan Summary")
    print("=" * LINE_WIDTH)

    print(f"Processes Collected : {total_processes}")
    print(f"Processes Displayed : {displayed}")
    print(f"Scan Duration       : {duration:.2f} seconds")
    print("Status              : SUCCESS")

    print("=" * LINE_WIDTH)


def main() -> None:
    """
    Start the monitoring agent.
    """

    logger = Logger()

    logger.info("Monitoring agent started.")

    print_header()

    start_time = perf_counter()

    process_monitor = ProcessMonitor()
    processes = process_monitor.scan()

    end_time = perf_counter()

    print_process_table(processes)

    print_summary(
        total_processes=len(processes),
        displayed=min(10, len(processes)),
        duration=end_time - start_time,
    )


if __name__ == "__main__":
    main()