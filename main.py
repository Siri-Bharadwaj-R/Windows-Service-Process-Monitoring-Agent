"""
Entry point for the Windows Service & Process Monitoring Agent.
"""

from utils.logger import Logger
from utils.config_loader import ConfigLoader


def main() -> None:
    """
    Start the monitoring agent and test the configuration loader.
    """

    logger = Logger()
    logger.info("Monitoring agent started.")

    loader = ConfigLoader()

    whitelist = loader.load_whitelist()
    blacklist = loader.load_blacklist()
    rules = loader.load_rules()

    print("\nWhitelist:")
    print(whitelist)

    print("\nBlacklist:")
    print(blacklist)

    print("\nRules:")
    print(rules)

    print("\nConfiguration loader initialized successfully.")


if __name__ == "__main__":
    main()