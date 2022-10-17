#!/usr/bin/env python3
import argparse
import json

from argo_scg.config import Config
from argo_scg.exceptions import SensuException, ConfigException, \
    PoemException, WebApiException, GeneratorException
from argo_scg.generator import ConfigurationGenerator
from argo_scg.logger import get_logger
from argo_scg.poem import Poem
from argo_scg.sensu import Sensu
from argo_scg.webapi import WebApi

CONFFILE = "/etc/argo-scg/scg.conf"


def main():
    parser = argparse.ArgumentParser(
        "Sync data from POEM and Web-API with Sensu"
    )
    parser.add_argument(
        "-c", "--conf", dest="conf", help="configuration file", default=CONFFILE
    )
    args = parser.parse_args()

    logger = get_logger()

    try:
        config = Config(config_file=args.conf)

        sensu_url = config.get_sensu_url()
        sensu_token = config.get_sensu_token()
        webapi_url = config.get_webapi_url()
        webapi_tokens = config.get_webapi_tokens()
        poem_urls = config.get_poem_urls()
        poem_tokens = config.get_poem_tokens()
        metricprofiles = config.get_metricprofiles()
        local_topology = config.get_topology()
        secrets = config.get_secrets()
        publish_bool = config.publish()

        tenants = config.get_tenants()

        logger.info(f"Configuration file {args.conf} read successfully")

        sensu = Sensu(url=sensu_url, token=sensu_token)

        sensu.handle_namespaces(tenants=tenants)

        for tenant in tenants:
            namespace = tenant

            try:
                webapi = WebApi(
                    url=webapi_url,
                    token=webapi_tokens[tenant],
                    tenant=tenant
                )

                poem = Poem(
                    url=poem_urls[tenant],
                    token=poem_tokens[tenant],
                    tenant=tenant
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
                    attributes=poem.get_metric_overrides(),
                    secrets_file=secrets[namespace],
                    default_ports=poem.get_default_ports(),
                    tenant=tenant
                )

                sensu.add_daily_filter(namespace=namespace)
                sensu.handle_slack_handler(
                    secrets_file=secrets[namespace], namespace=namespace
                )
                sensu.add_reduce_alerts_pipeline(namespace=namespace)

                if publish_bool[namespace]:
                    sensu.handle_publisher_handler(namespace=namespace)
                    sensu.add_hard_state_filter(namespace=namespace)
                    sensu.add_hard_state_pipeline(namespace=namespace)

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

            except json.decoder.JSONDecodeError as e:
                logger.error(f"{namespace}: Error reading JSON: {str(e)}")
                logger.warning(f"{namespace}: Skipping configuration...")
                continue

            except (
                    WebApiException, PoemException, GeneratorException,
                    SensuException
            ):
                logger.warning(f"{namespace}: Skipping configuration...")
                continue

            except Exception as e:
                logger.warning(
                    f"{namespace}: {str(e)} Skipping configuration..."
                )
                continue

        logger.info("Done")

    except ConfigException as e:
        logger.error(str(e))
        logger.info("Exiting...")

    except SensuException:
        logger.info("Exiting...")

    except Exception as e:
        logger.error(f"{str(e)}")
        logger.info("Exiting...")


if __name__ == "__main__":
    main()
