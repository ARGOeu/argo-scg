import logging

import requests
from argo_scg.exceptions import WebApiException


class WebApi:
    def __init__(self, url, token, tenant):
        self.url = url
        self.token = token
        self.tenant = tenant
        self.logger = logging.getLogger("argo-scg.webapi")

    def get_metric_profiles(self):
        response = requests.get(
            "{}/api/v2/metric_profiles".format(self.url),
            headers={"Accept": "application/json", "x-api-key": self.token}
        )

        if not response.ok:
            msg = f"{self.tenant}: Metric profiles fetch error: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, TypeError, KeyError):
                pass

            self.logger.error(msg)
            raise WebApiException(msg)

        else:
            mps = response.json()["data"]
            self.logger.info(
                f"{self.tenant}: Metric profiles fetched successfully"
            )

            return mps

    def get_topology(self):
        response = requests.get(
            "{}/api/v2/topology/endpoints".format(self.url),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "x-api-key": self.token
            }
        )

        if not response.ok:
            msg = f"{self.tenant}: Topology endpoints fetch error: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, TypeError, KeyError):
                pass

            self.logger.error(msg)
            raise WebApiException(msg)

        else:
            topology = response.json()["data"]
            self.logger.info(
                f"{self.tenant}: Topology endpoints fetched successfully"
            )

            return topology
