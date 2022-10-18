#!/usr/bin/env python3
import argparse
import json

import requests
from argo_scg.config import Config

CONFFILE = "/etc/argo-scg/scg.conf"


def main():
    parser = argparse.ArgumentParser("Create an ad-hoc check execution request")
    parser.add_argument(
        "-c", "--check", type=str, required=True, help="check name"
    )
    parser.add_argument(
        "-n", "--namespace", type=str, required=True, help="namespace"
    )
    args = parser.parse_args()

    try:
        config = Config(config_file=CONFFILE)
        url = config.get_sensu_url()
        token = config.get_sensu_token()

        response = requests.post(
            f"{url}/api/core/v2/namespaces/{args.namespace}/checks/"
            f"{args.check}/execute",
            headers={
                "Authorization": f"Key {token}",
                "Content-Type": "application/json"
            },
            data=json.dumps({"check": args.check})
        )

        if response.ok:
            print(response.json())

        else:
            print(f"{args.namespace}: Error")

    except Exception as e:
        print(f"{args.namespace}: {str(e)}")


if __name__ == "__main__":
    main()
