#!/usr/bin/env python3
import configparser
import json
import logging
import logging.handlers
import signal
import subprocess
import sys

from argo_scg.config import Config
from argo_scg.sensu import MetricOutput


class timeout:
    def __init__(self, seconds=1, error_message="Timeout"):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)


def main():
    logger = logging.getLogger("argo-scg")
    logger.setLevel(logging.INFO)

    stdout = logging.StreamHandler()
    stdout.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
    logger.addHandler(stdout)

    # setting up logging to syslog
    syslog = logging.handlers.SysLogHandler(address="/dev/log")
    syslog.setLevel(logging.INFO)
    syslog.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
    )

    logger.addHandler(syslog)

    try:
        with timeout(seconds=10, error_message="Timeout when reading stdin"):
            output = MetricOutput(data=json.load(sys.stdin))
            namespace = output.get_namespace()

    except TimeoutError as err:
        logger.error(err)
        sys.exit(1)

    except json.JSONDecodeError as err:
        logger.error(f"Error decoding stdin: {err}")
        sys.exit(1)

    except KeyError as err:
        logger.error(f"Error fetching namespace: {err}")
        sys.exit(1)

    try:
        config = Config(config_file="/etc/argo-scg/scg.conf")
        publisher_queue = config.get_publisher_queue()[namespace]

    except (
            configparser.ParsingError, configparser.NoOptionError,
            configparser.NoSectionError
    ) as err:
        logger.error(f"Error parsing config file: {err}")
        sys.exit(1)

    try:
        subprocess.call(
            [
                "ams-metric-to-queue", "--servicestatetype", "HARD",
                "--queue", publisher_queue, "--service", output.get_service(),
                "--hostname", output.get_hostname(),
                "--metric", output.get_metric_name(),
                "--status", output.get_status(),
                "--summary", output.get_summary()
            ]
        )

    except subprocess.CalledProcessError as err:
        logger.error(f"Error executing command: {err}")
        sys.exit(1)


if __name__ == '__main__':
    main()
