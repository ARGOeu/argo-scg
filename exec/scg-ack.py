#!/usr/bin/env python3
import argparse

from argo_scg.config import Config
from argo_scg.exceptions import SensuException, ConfigException
from argo_scg.sensu import Sensu

CONFFILE = "/etc/argo-scg/scg.conf"


def main():
    parser = argparse.ArgumentParser(
        "Acknowledge an event so it does not send any more notifications"
    )
    parser.add_argument(
        "-c", "--check", dest="check", type=str, help="check name",
        required=True
    )
    parser.add_argument(
        "-e", "--entity", dest="entity", type=str, help="entity name",
        required=True
    )
    parser.add_argument(
        "-n", "--namespace", dest="namespace", type=str, default="default",
        help="namespace"
    )
    parser.add_argument(
        "--conf", dest="conf", help="configuration file", default=CONFFILE
    )
    args = parser.parse_args()

    try:
        config = Config(config_file=args.conf)

        sensu = Sensu(
            url=config.get_sensu_url(), token=config.get_sensu_token()
        )

        sensu.create_silencing_entry(
            check=args.check, entity=args.entity, namespace=args.namespace
        )

        print(f"Created silencing entry for {args.entity}/{args.check}")

    except (ConfigException, SensuException, Exception) as e:
        print(str(e))


if __name__ == "__main__":
    main()
