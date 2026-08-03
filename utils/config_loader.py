"""
Configuration loading utilities for the
Windows Service & Process Monitoring Agent.
"""

import json
from pathlib import Path

from utils.logger import Logger


class ConfigLoader:
    """
    Loads configuration files used by the monitoring agent.
    """

    def __init__(self) -> None:
        """
        Initialize the configuration loader.
        """

        self.config_directory = Path("config")
        self.logger = Logger()
        
    def load_json(self, filename: str) -> dict:
        """
        Load and return a JSON configuration file.

        Args:
            filename: Name of the JSON file inside the config directory.

        Returns:
            Parsed JSON data as a dictionary.

        Raises:
            FileNotFoundError: If the configuration file does not exist.
            json.JSONDecodeError: If the JSON is invalid.
        """

        file_path = self.config_directory / filename

        try:
            with file_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            self.logger.info(f"Loaded configuration: {filename}")
            return data

        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {filename}")
            raise

        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON in configuration file: {filename}")
            raise
    def load_whitelist(self) -> dict:
            """
            Load the process whitelist configuration.
            """

            return self.load_json("whitelist.json")


    def load_blacklist(self) -> dict:
        """
        Load the process blacklist configuration.
        """

        return self.load_json("blacklist.json")


    def load_rules(self) -> dict:
        """
        Load the detection rules configuration.
        """

        return self.load_json("rules.json")
        