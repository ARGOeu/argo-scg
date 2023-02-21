#!/usr/bin/env python3
import argparse

from argo_scg.config import Config
from argo_scg.exceptions import SensuException, ConfigException
from argo_scg.sensu import Sensu

CONFFILE = "/etc/argo-scg/scg.conf"


def main():
    parser = argparse.ArgumentParser(
        "Check how the probe is envoked for a given entity"
    )
    parser.add_argument(
        "-e", "--entity", dest="entity", type=str, required=True, help="entity"
    )
    parser.add_argument(
        "-c", "--check", dest="check", type=str, required=True, help="check"
    )
    parser.add_argument(
        "-n", "--namespace", dest="namespace", type=str, default="default",
        help="namespace"
    )
    parser.add_argument(
        "--config", type=str, dest="config", help="configuration file",
        default=CONFFILE
    )
    args = parser.parse_args()

    try:
        config = Config(config_file=args.config)
        url = config.get_sensu_url()
        token = config.get_sensu_token()

        sensu = Sensu(url=url, token=token)
        print(
            sensu.get_check_run(
                entity=args.entity, check=args.check, namespace=args.namespace
            )
        )

    except ConfigException as e:
        print(e)

    except SensuException as e:
        print(e)

    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
