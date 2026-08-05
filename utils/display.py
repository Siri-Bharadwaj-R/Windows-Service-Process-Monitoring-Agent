"""
Console display utilities for the
Windows Service & Process Monitoring Agent.
"""


class ConsoleDisplay:
    """
    Handles all console output for the monitoring agent.
    """

    LINE_WIDTH = 100

    def __init__(self) -> None:
        """
        Initialize the console display.
        """

        pass

    def divider(self, character: str = "=") -> None:
        """
        Print a horizontal divider.

        Args:
            character:
                Character used to draw the divider.
        """

        print(character * self.LINE_WIDTH)

    def show_header(self) -> None:
        """
        Display the application header.
        """

        print()

        self.divider()

        print(
            "        Windows Service & Process Monitoring Agent"
        )

        self.divider()

    def show_process_table(
        self,
        processes: list[dict[str, object]],
        limit: int = 10,
    ) -> None:
        """
        Display running processes in a formatted table.

        Args:
            processes:
                List of collected process information.

            limit:
                Maximum number of processes to display.
        """

        print(f"\nProcesses Collected : {len(processes)}")

        self.divider("-")

        print(
            f"{'PID':<8}"
            f"{'PPID':<8}"
            f"{'Process Name':<35}"
            f"{'Status':<12}"
            f"{'User'}"
        )

        self.divider("-")

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

        self.divider("-")

        print(
            f"Showing first {min(limit, len(processes))} "
            f"of {len(processes)} processes."
        )

    def show_summary(
        self,
        total_processes: int,
        displayed: int,
        duration: float,
    ) -> None:
        """
        Display scan summary.

        Args:
            total_processes:
                Total number of collected processes.

            displayed:
                Number of displayed processes.

            duration:
                Scan duration in seconds.
        """

        print()

        self.divider()

        print("Scan Summary")

        self.divider()

        print(f"Processes Collected : {total_processes}")
        print(f"Processes Displayed : {displayed}")
        print(f"Scan Duration       : {duration:.2f} seconds")
        print("Status              : SUCCESS")

        self.divider()