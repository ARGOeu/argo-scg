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
    logger = logging.getLogger("ams-metric-to-queue")
    logger.setLevel(logging.INFO)

    stdout = logging.StreamHandler()
    stdout.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(stdout)

    try:
        with timeout(seconds=10, error_message="Timeout when reading stdin"):
            output = MetricOutput(data=json.load(sys.stdin))
            tenants = output.get_tenants()

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

        service = output.get_service()
        hostname = output.get_hostname()
        metric_name = output.get_metric_name()
        status = output.get_status()
        perfdata = output.get_perfdata()
        summary = output.get_summary()
        message = output.get_message()

        for tenant in tenants:
            publisher_queue = config.get_publisher_queue()[tenant]

            ams_m2q_call = [
                "ams-metric-to-queue", "--servicestatetype", "HARD",
                "--queue", publisher_queue, "--service", service,
                "--hostname", hostname, "--metric", metric_name,
                "--status", status, "--summary", summary,
                "--message", repr(message)
            ]
            if perfdata:
                ams_m2q_call.extend(["--actual_data", perfdata])

            subprocess.call(ams_m2q_call)

            logger.info(
                f"Command '{' '.join(ams_m2q_call)}' called successfully"
            )

    except (
            configparser.ParsingError, configparser.NoOptionError,
            configparser.NoSectionError
    ) as err:
        logger.error(f"Error parsing config file: {err}")
        sys.exit(1)

    except subprocess.CalledProcessError as err:
        logger.error(f"Error executing command: {err}")
        sys.exit(1)


if __name__ == '__main__':
    main()
