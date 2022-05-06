#!/usr/bin/env python3
import argparse
import json

from argo_scg.config import Config
from argo_scg.exceptions import SensuException, PoemException, \
    WebApiException, ConfigException
from argo_scg.generator import ConfigurationGenerator
from argo_scg.poem import Poem
from argo_scg.sensu import Sensu
from argo_scg.webapi import WebApi


def main():
    parser = argparse.ArgumentParser(
        "Sync data from POEM and Web-api with Sensu"
    )
    parser.add_argument(
        "-c", "--conf", dest="conf", help="configuration file",
        default="/etc/argo-scg/scg.conf"
    )
    args = parser.parse_args()

    try:
        config = Config(config_file=args.conf)

        sensu = Sensu(
            url=config.get_sensu_url(),
            token=config.get_sensu_token(),
        )
        webapi_url = config.get_webapi_url()
        webapi_tokens = config.get_webapi_tokens()
        poem_urls = config.get_poem_urls()
        poem_tokens = config.get_poem_tokens()
        metricprofiles = config.get_metricprofiles()
        attributes = config.get_local_attributes()
        local_topology = config.get_topology()
        publish_bool = config.publish()

        tenants = config.get_tenants()

        sensu.handle_namespaces(tenants=tenants)

        for tenant in tenants:
            namespace = tenant

            try:
                webapi = WebApi(
                    url=webapi_url,
                    token=webapi_tokens[tenant]
                )

                poem = Poem(
                    url=poem_urls[tenant],
                    token=poem_tokens[tenant]
                )

                if local_topology[tenant]:
                    with open(local_topology[tenant]) as f:
                        topology = json.load(f)

                else:
                    topology = webapi.get_topology()

                generator = ConfigurationGenerator(
                    metrics=poem.get_metrics_configurations(),
                    profiles=metricprofiles[tenant],
                    metric_profiles=webapi.get_metric_profiles(),
                    topology=topology,
                    local_attributes=attributes[tenant]
                )

                if publish_bool[namespace]:
                    sensu.handle_publisher_handler(namespace=namespace)

                sensu.handle_checks(
                    checks=generator.generate_checks(
                        publish=publish_bool[namespace], namespace=namespace
                    ),
                    namespace=namespace
                )

                if namespace != "default":
                    sensu.handle_proxy_entities(
                        entities=generator.generate_entities(
                            namespace=namespace
                        ),
                        namespace=namespace
                    )

                sensu.add_subscriptions_to_agents(
                    subscriptions=generator.generate_subscriptions(),
                    namespace=namespace
                )

            except Exception as e:
                print(f"{namespace}: {str(e)}")

    except (
            SensuException, PoemException, WebApiException, ConfigException
    ) as e:
        print("\n{}".format(str(e)))

    except Exception as e:
        print("\n{}".format(str(e)))


if __name__ == "__main__":
    main()
