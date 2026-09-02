"""
Process tree utilities for the
Windows Service & Process Monitoring Agent.
"""

from utils.logger import Logger


class ProcessTree:
    """
    Builds and manages parent-child relationships
    between running Windows processes.
    """

    def __init__(self) -> None:
        """
        Initialize the process tree engine.
        """

        self.logger = Logger()

        # Maps PID -> Process
        self.process_index: dict[int, dict[str, object]] = {}

        # Maps Parent PID -> Child Processes
        self.children_index: dict[
            int,
            list[dict[str, object]]
        ] = {}

    def build_tree(
        self,
        processes: list[dict[str, object]],
    ) -> None:
        """
        Build the process tree indexes.

        Args:
            processes:
                List of collected processes.
        """

        self.logger.info("Building process tree...")

        self.process_index.clear()
        self.children_index.clear()

        for process in processes:

            pid = process["pid"]
            parent_pid = process["ppid"]

            self.process_index[pid] = process

            if parent_pid not in self.children_index:
                self.children_index[parent_pid] = []

            self.children_index[parent_pid].append(process)

        self.logger.info(
            f"Process tree built successfully with "
            f"{len(self.children_index)} parent nodes."
        )

    def get_children(
        self,
        parent_pid: int,
    ) -> list[dict[str, object]]:
        """
        Return all child processes for a given parent PID.
        """

        return self.children_index.get(parent_pid, [])

    def get_parent(
        self,
        pid: int,
    ) -> dict[str, object] | None:
        """
        Return the parent process for a given PID.
        """

        process = self.process_index.get(pid)

        if process is None:
            return None

        parent_pid = process["ppid"]

        return self.process_index.get(parent_pid)

    def find_process(
        self,
        process_name: str,
    ) -> list[dict[str, object]]:
        """
        Find all running processes with the given name.

        Args:
            process_name:
                Name of the process to search for.

        Returns:
            List of matching process dictionaries.
        """

        matches = []

        for process in self.process_index.values():

            name = process.get("name")

            if (
                isinstance(name, str)
                and name.lower() == process_name.lower()
            ):
                matches.append(process)

        return matches

    def print_tree(
        self,
        parent_pid: int,
    ) -> None:
        """
        Display all child processes for a given parent PID.

        Args:
            parent_pid:
                Parent Process ID.
        """

        parent = self.process_index.get(parent_pid)

        if parent is None:
            print(f"Parent PID {parent_pid} not found.")
            return

        parent_name = parent.get("name") or "Unknown"

        print()
        print(f"{parent_name} (PID {parent_pid})")
        print("-" * 50)

        children = self.get_children(parent_pid)

        if not children:
            print("No child processes found.")
            return

        total_children = len(children)

        for index, child in enumerate(children):

            child_name = child.get("name") or "Unknown"

            if index == total_children - 1:
                connector = "\\--"
            else:
                connector = "|--"

            print(
                f"{connector} {child_name} "
                f"(PID {child['pid']})"
            )

    def print_summary(
        self,
        max_parents: int = 5,
        max_children: int = 3,
    ) -> None:
        """
        Display a concise summary of actual parent-child
        process relationships.

        Args:
            max_parents:
                Maximum number of parent processes to display.

            max_children:
                Maximum number of children to display
                for each parent.
        """

        print()
        print(
            "┌─ Parent-Child Process Relationships ────────────────┐"
        )

        displayed_parents = 0

        for parent_pid, children in self.children_index.items():

            parent = self.process_index.get(parent_pid)

            # Skip entries where the parent process is not
            # present in the current process snapshot.
            if parent is None or not children:
                continue

            parent_name = parent.get("name") or "Unknown"

            print(
                f"│ {parent_name} (PID {parent_pid})"
            )

            visible_children = children[:max_children]

            for index, child in enumerate(visible_children):

                child_name = child.get("name") or "Unknown"

                if index == len(visible_children) - 1:
                    connector = "└──"
                else:
                    connector = "├──"

                print(
                    f"│   {connector} "
                    f"{child_name} (PID {child['pid']})"
                )

            # Show when additional children exist.
            if len(children) > max_children:

                remaining = len(children) - max_children

                print(
                    f"│       ... "
                    f"{remaining} additional child process(es)"
                )

            displayed_parents += 1

            if displayed_parents >= max_parents:
                break

        if displayed_parents == 0:

            print(
                "│ No parent-child relationships available."
            )

        print(
            "└─────────────────────────────────────────────────────┘"
        )
        print()
        
    def print_summary(self, limit: int = 10) -> None:
        """
        Display a concise summary of parent-child process relationships.
        """

        print()
        print("=" * 60)
        print("PARENT-CHILD PROCESS RELATIONSHIPS")
        print("=" * 60)

        relationships = []

        for parent_pid, children in self.children_index.items():

            parent = self.process_index.get(parent_pid)

            if parent is None:
                continue

            parent_name = parent.get("name") or "Unknown"

            for child in children:

                child_name = child.get("name") or "Unknown"

                relationships.append(
                    (
                        parent_name,
                        parent_pid,
                        child_name,
                        child["pid"],
                    )
                )

        if not relationships:
            print("No parent-child relationships found.")
            return

        for index, relationship in enumerate(
            relationships[:limit],
            start=1,
        ):

            parent_name, parent_pid, child_name, child_pid = relationship

            print(
                f"{index:02d}. "
                f"{parent_name} (PID {parent_pid}) "
                f"--> "
                f"{child_name} (PID {child_pid})"
            )

        if len(relationships) > limit:
            print(
                f"... and "
                f"{len(relationships) - limit} more relationships"
            )

        print("=" * 60)