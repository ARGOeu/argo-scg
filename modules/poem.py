import requests
from argo_scg.exceptions import PoemException


class Poem:
    def __init__(self, url, token):
        self.url = url
        self.token = token

    def _get_metrics(self):
        response = requests.get(
            "{}/api/v2/metrics".format(self.url),
            headers={"x-api-key": self.token}
        )

        if not response.ok:
            msg = "Error fetching metrics: {} {}".format(
                response.status_code, response.reason
            )

            try:
                msg = "{}: {}".format(msg, response.json()["detail"])

            except (ValueError, TypeError, KeyError):
                pass

            raise PoemException(msg)

        else:
            return response.json()

    def get_metrics_configurations(self):
        metrics = self._get_metrics()

        try:
            metric_confs = list()
            for metric in metrics:
                for name, configuration in metric.items():
                    path = configuration["config"]["path"]
                    if path == "$USER1$":
                        configuration["config"]["path"] = \
                            "/usr/lib64/nagios/plugins"
                    metric_confs.append({name: configuration})

            return metric_confs

        except Exception as e:
            msg = "Error creating metric configuration: {}".format(str(e))
            raise PoemException(msg)
