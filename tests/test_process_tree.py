"""
Test script for the ProcessTree module.
"""

"""
Test script for the ProcessTree module.
"""

import sys
from pathlib import Path

# Add the project root to Python's module search path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.process_monitor import ProcessMonitor
from core.process_tree import ProcessTree

from core.process_monitor import ProcessMonitor
from core.process_tree import ProcessTree


def main() -> None:
    """
    Test the ProcessTree engine.
    """

    monitor = ProcessMonitor()
    processes = monitor.scan()

    tree = ProcessTree()
    tree.build_tree(processes)

    print("\n" + "=" * 60)
    print("PROCESS TREE TEST")
    print("=" * 60)

    # Test get_children()
    print("\nChildren of PID 4:")
    children = tree.get_children(4)

    print(f"Found {len(children)} child processes.")

    # Test get_parent()
    if children:
        child_pid = children[0]["pid"]
        parent = tree.get_parent(child_pid)

        print(f"\nParent of PID {child_pid}:")

        if parent:
            print(
                f"{parent['name']} "
                f"(PID {parent['pid']})"
            )

    # Test find_process()
    print("\nSearching for svchost.exe...")

    matches = tree.find_process("svchost.exe")

    print(f"Found {len(matches)} instance(s).")

    # Test print_tree()
    print("\nDisplaying process tree for PID 4:\n")

    tree.print_tree(4)


if __name__ == "__main__":
    main()