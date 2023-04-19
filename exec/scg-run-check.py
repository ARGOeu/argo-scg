#!/usr/bin/env python3
import argparse
import json
import sys
import time

import requests
from argo_scg.config import Config
from argo_scg.exceptions import SensuException, ConfigException
from argo_scg.generator import generate_adhoc_check
from argo_scg.sensu import Sensu

CONFFILE = "/etc/argo-scg/scg.conf"


def main():
    parser = argparse.ArgumentParser(
        "Check how the probe is invoked for a given entity"
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
    parser.add_argument(
        "--execute", dest="execute", action="store_true", help="run the command"
    )
    args = parser.parse_args()

    try:
        try:
            config = Config(config_file=args.config)
            url = config.get_sensu_url()
            token = config.get_sensu_token()

        except ConfigException as e:
            print(e)
            sys.exit(2)

        sensu = Sensu(url=url, token=token)
        command = sensu.get_check_run(
            entity=args.entity, check=args.check, namespace=args.namespace
        )

        if args.execute:
            if sensu.is_entity_agent(
                    entity=args.entity, namespace=args.namespace
            ):
                check_name = args.check

            else:
                subscriptions = sensu.get_check_subscriptions(
                    check=args.check, namespace=args.namespace
                )
                check = generate_adhoc_check(
                    command=command, subscriptions=subscriptions,
                    namespace=args.namespace
                )
                sensu.put_check(check=check, namespace=args.namespace)
                check_name = check["metadata"]["name"]

            response = requests.post(
                f"{url}/api/core/v2/namespaces/{args.namespace}/checks/"
                f"{check_name}/execute",
                headers={
                    "Authorization": f"Key {token}",
                    "Content-Type": "application/json"
                },
                data=json.dumps({"check": check_name})
            )

            time.sleep(5)

            if response.ok:
                agent = sensu.get_agents(namespace=args.namespace)[0]
                print(f"Executing command:\n{command}\n")
                print(
                    sensu.get_event_output(
                        entity=agent["metadata"]["name"],
                        check=check_name,
                        namespace=args.namespace
                    )
                )
                if not sensu.is_entity_agent(
                        entity=args.entity, namespace=args.namespace
                ):
                    sensu.delete_event(
                        entity=agent["metadata"]["name"],
                        check=check_name,
                        namespace=args.namespace
                    )
                    sensu.delete_check(
                        check=check_name,
                        namespace=args.namespace
                    )

            else:
                print(f"{args.namespace}: Error executing ad-hoc check")

        else:
            print(f"Executing command:\n{command}")

    except SensuException as e:
        print(e)

    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
