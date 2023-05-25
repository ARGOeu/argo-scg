import logging

import requests
from argo_scg.exceptions import WebApiException


class WebApi:
    def __init__(
            self, url, token, tenant, topo_groups_filter=None,
            topo_endpoints_filter=None
    ):
        self.url = url
        self.token = token
        self.tenant = tenant
        self.groups_filter = topo_groups_filter
        self.endpoints_filter = topo_endpoints_filter
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

    def _get_topology_groups(self):
        url = f"{self.url}/api/v2/topology/groups"
        if self.groups_filter:
            url = f"{url}?{self.groups_filter}"

        response = requests.get(
            url,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "x-api-key": self.token
            }
        )

        if not response.ok:
            msg = f"{self.tenant}: Topology groups fetch error: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, TypeError, KeyError):
                pass

            self.logger.error(msg)
            raise WebApiException(msg)

        else:
            groups = response.json()["data"]
            self.logger.info(
                f"{self.tenant}: Topology groups fetched successfully"
            )

            return groups

    def _get_topology_endpoints(self):
        url = f"{self.url}/api/v2/topology/endpoints"
        if self.endpoints_filter:
            url = f"{url}?{self.endpoints_filter}"
        response = requests.get(
            url,
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
            endpoints = response.json()["data"]
            self.logger.info(
                f"{self.tenant}: Topology endpoints fetched successfully"
            )

            return endpoints

    def get_topology(self):
        endpoints = self._get_topology_endpoints()

        if self.groups_filter:
            groups = self._get_topology_groups()

            eligible_sites = [group["subgroup"] for group in groups]

            endpoints = [
                endpoint for endpoint in endpoints if
                endpoint["group"] in eligible_sites
            ]

        return endpoints
