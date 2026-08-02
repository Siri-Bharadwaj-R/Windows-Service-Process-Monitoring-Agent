from utils.logger import Logger


def main():
    logger = Logger()

    logger.info("Monitoring agent started.")
    logger.warning("This is a warning message.")
    logger.error("This is an error message.")
    logger.critical("This is a critical message.")


if __name__ == "__main__":
    main()