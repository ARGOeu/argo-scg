import requests
from argo_scg.exceptions import WebApiException


class WebApi:
    def __init__(self, url, token):
        self.url = url
        self.token = token

    def get_metric_profiles(self):
        response = requests.get(
            "{}/api/v2/metric_profiles".format(self.url),
            headers={"Accept": "application/json", "x-api-key": self.token}
        )

        if not response.ok:
            msg = "Error fetching metric profiles: {} {}".format(
                response.status_code, response.reason
            )

            try:
                msg = "{}: {}".format(msg, response.json()["message"])

            except (ValueError, TypeError, KeyError):
                pass

            raise WebApiException(msg)

        else:
            mps = response.json()["data"]

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
            msg = "Error fetching topology endpoints: {} {}".format(
                response.status_code, response.reason
            )

            try:
                msg = "{}: {}".format(msg, response.json()["message"])

            except (ValueError, TypeError, KeyError):
                pass

            raise WebApiException(msg)

        else:
            topology = response.json()["data"]

            return topology
