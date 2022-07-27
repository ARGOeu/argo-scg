import logging

import requests
from argo_scg.exceptions import PoemException


class Poem:
    def __init__(self, url, token, tenant):
        self.url = url
        self.token = token
        self.tenant = tenant
        self.logger = logging.getLogger("argo-scg.poem")

    def _get_metrics(self):
        response = requests.get(
            "{}/api/v2/metrics".format(self.url),
            headers={"x-api-key": self.token}
        )

        if not response.ok:
            msg = f"{self.tenant}: Error fetching metrics: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['detail']}"

            except (ValueError, TypeError, KeyError):
                pass

            self.logger.error(msg)
            raise PoemException(msg)

        else:
            self.logger.info(f"{self.tenant}: Successfully fetched metrics")
            return response.json()

    def get_metric_overrides(self):
        response = requests.get(
            "{}/api/v2/metricoverrides".format(self.url),
            headers={"x-api-key": self.token}
        )

        if not response.ok:
            msg = f"{self.tenant}: Metric overrides not fetched: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['detail']}"

            except (ValueError, TypeError, KeyError):
                pass

            self.logger.warning(msg)
            return dict()

        else:
            self.logger.info(
                f"{self.tenant}: Successfully fetched metric overrides"
            )
            return response.json()

    def get_metrics_configurations(self):
        metrics = self._get_metrics()

        metric_confs = list()
        for metric in metrics:
            for name, configuration in metric.items():
                try:
                    if configuration["config"] and \
                            configuration["config"]["path"] == "$USER1$":
                        configuration["config"]["path"] = \
                            "/usr/lib64/nagios/plugins"
                    metric_confs.append({name: configuration})

                except KeyError as e:
                    self.logger.warning(
                        f"{self.tenant}: Metric {name} skipped: "
                        f"Missing key {str(e)}"
                    )

        return metric_confs
