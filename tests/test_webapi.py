import unittest
from unittest.mock import patch

from argo_scg.exceptions import WebApiException
from argo_scg.webapi import WebApi

from utils import MockResponse

mock_metric_profiles = [
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-11-24",
        "name": "OPS_MONITOR",
        "description": "Profile for monitoring operational tools",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.http.ar-argoui-ni4os",
                    "generic.http.connect",
                    "generic.certificate.validity"
                ]
            },
            {
                "service": "argo.test",
                "metrics": [
                    "generic.tcp.connect",
                    "generic.certificate.validity"
                ]
            },
            {
                "service": "gr.group3.service",
                "metrics": [
                    "generic.http.connect",
                    "generic.http.connect-nagios-ui"
                ]
            }
        ]
    },
    {
        "id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
        "date": "2021-12-01",
        "name": "ARGO_TEST",
        "description": "Profile for testing",
        "services": [
            {
                "service": "eu.ni4os.ops.gocdb",
                "metrics": [
                    "generic.tcp.connect",
                    "generic.http.connect-gocdb",
                    "generic.http.connect-gocdb-pi-ni4os"
                ]
            }
        ]
    }
]

mock_topology_endpoints = [
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.webui",
        "hostname": "argo.ni4os.eu",
        "tags": {
            "info_ID": "0000",
            "info_URL": "https://argo.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.test",
        "hostname": "argo.ni4os.eu",
        "tags": {
            "info_ID": "0000",
            "info_URL": "https://argo.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "UKIM",
        "type": "SITES",
        "service": "eu.ni4os.ops.gocdb",
        "hostname": "gocdb.ni4os.eu",
        "tags": {
            "info_ID": "1111",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.mon",
        "hostname": "argo-mon2.ni4os.eu",
        "tags": {
            "info_ID": "2222",
            "info_URL": "https://argo-mon2.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.webui",
        "hostname": "argo-devel.ni4os.eu",
        "tags": {
            "info_ID": "3333",
            "info_URL": "https://argo-devel.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-03-09",
        "group": "GROUP3",
        "type": "SITES",
        "service": "gr.group3.service",
        "hostname": "www.group3.argo.gr",
        "tags": {
            "info_ID": "4444",
            "info_URL": "https://www.group3.argo.gr/",
            "info_ext_extraUrl": "/index.php/results",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-03-09",
        "group": "GROUP4",
        "type": "SITES",
        "service": "eu.argo.hpc",
        "hostname": "hpc.argo.eu",
        "tags": {
            "info_ID": "5555",
            "info_ext_PORT": "1022",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    }
]


def mock_webapi_requests(*args, **kwargs):
    if args[0].endswith("metric_profiles"):
        return MockResponse(
            {
                "status": {
                    "message": "Success",
                    "code": "200"
                },
                "data": mock_metric_profiles
            },
            status_code=200
        )

    elif args[0].endswith("endpoints"):
        return MockResponse(
            {
                "status": {
                    "message": "Success",
                    "code": "200"
                },
                "data": mock_topology_endpoints
            },
            status_code=200
        )


def mock_webapi_metricprofile_error_with_msg(*args, **kwargs):
    if args[0].endswith("metric_profiles"):
        return MockResponse(
            {
                "code": "400",
                "message": "There has been an error.",
                "errors": [
                    {
                        "message": "There has been an error.",
                        "code": "400",
                        "details": "Something went wrong."
                    }
                ],
                "details": "Something went wrong."
            },
            status_code=400
        )

    elif args[0].endswith("endpoints"):
        return MockResponse(
            {
                "status": {
                    "message": "Success",
                    "code": "200"
                },
                "data": mock_topology_endpoints
            },
            status_code=200
        )


def mock_webapi_metricprofile_error_without_msg(*args, **kwargs):
    if args[0].endswith("metric_profiles"):
        return MockResponse(None, status_code=400)

    elif args[0].endswith("endpoints"):
        return MockResponse(
            {
                "status": {
                    "message": "Success",
                    "code": "200"
                },
                "data": mock_topology_endpoints
            },
            status_code=200
        )


def mock_webapi_requests_endpoints_error_with_msg(*args, **kwargs):
    if args[0].endswith("metric_profiles"):
        return MockResponse(
            {
                "status": {
                    "message": "Success",
                    "code": "200"
                },
                "data": mock_metric_profiles
            },
            status_code=200
        )

    elif args[0].endswith("endpoints"):
        return MockResponse(
            {
                "code": "400",
                "message": "There has been an error.",
                "errors": [
                    {
                        "message": "There has been an error.",
                        "code": "400",
                        "details": "Something went wrong."
                    }
                ],
                "details": "Something went wrong."
            },
            status_code=400
        )


def mock_webapi_requests_endpoints_error_without_msg(*args, **kwargs):
    if args[0].endswith("metric_profiles"):
        return MockResponse(
            {
                "status": {
                    "message": "Success",
                    "code": "200"
                },
                "data": mock_metric_profiles
            },
            status_code=200
        )

    elif args[0].endswith("endpoints"):
        return MockResponse(None, status_code=400)


class WebApiTests(unittest.TestCase):
    def setUp(self):
        self.webapi = WebApi(
            url="https://web-api.com", token="W3b4p1t0k3n", tenant="MOCK_TENANT"
        )
        self.logname = "argo-scg.webapi"

    @patch("requests.get")
    def test_get_metric_profiles(self, mock_request):
        mock_request.side_effect = mock_webapi_requests
        with self.assertLogs(self.logname) as log:
            data = self.webapi.get_metric_profiles()
        self.assertEqual(data, mock_metric_profiles)
        self.assertEqual(
            log.output,
            [
                "INFO:argo-scg.webapi:MOCK_TENANT: Successfully fetched "
                "metric profiles"
            ]
        )

    @patch("requests.get")
    def test_error_fetching_metricprofiles_with_msg(self, mock_get):
        mock_get.side_effect = mock_webapi_metricprofile_error_with_msg
        with self.assertRaises(WebApiException) as context:
            with self.assertLogs(self.logname) as log:
                self.webapi.get_metric_profiles()

        self.assertEqual(
            context.exception.__str__(),
            "WebApi error: MOCK_TENANT: Error fetching metric profiles: "
            "400 BAD REQUEST: There has been an error."
        )

        self.assertEqual(
            log.output,
            [
                f"ERROR:{self.logname}:MOCK_TENANT: "
                f"Error fetching metric profiles: 400 BAD REQUEST: "
                f"There has been an error."
            ]
        )

    @patch("requests.get")
    def test_error_fetching_metricprofiles_without_msg(self, mock_get):
        mock_get.side_effect = mock_webapi_metricprofile_error_without_msg
        with self.assertRaises(WebApiException) as context:
            with self.assertLogs(self.logname) as log:
                self.webapi.get_metric_profiles()

        self.assertEqual(
            context.exception.__str__(),
            "WebApi error: MOCK_TENANT: Error fetching metric profiles: "
            "400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{self.logname}:MOCK_TENANT: "
                f"Error fetching metric profiles: 400 BAD REQUEST"
            ]
        )

    @patch("requests.get")
    def test_get_topology(self, mock_request):
        mock_request.side_effect = mock_webapi_requests
        with self.assertLogs(self.logname) as log:
            topology = self.webapi.get_topology()

        self.assertEqual(topology, mock_topology_endpoints)
        self.assertEqual(
            log.output, [
                f"INFO:{self.logname}:MOCK_TENANT: Successfully fetched "
                f"topology endpoints"
            ]
        )

    @patch("requests.get")
    def test_error_fetching_topology_with_msg(self, mock_get):
        mock_get.side_effect = mock_webapi_requests_endpoints_error_with_msg
        with self.assertRaises(WebApiException) as context:
            with self.assertLogs(self.logname) as log:
                self.webapi.get_topology()

        self.assertEqual(
            context.exception.__str__(),
            "WebApi error: MOCK_TENANT: Error fetching topology endpoints: "
            "400 BAD REQUEST: There has been an error."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{self.logname}:MOCK_TENANT: "
                f"Error fetching topology endpoints: "
                f"400 BAD REQUEST: There has been an error."
            ]
        )

    @patch("requests.get")
    def test_error_fetching_topology_without_msg(self, mock_get):
        mock_get.side_effect = mock_webapi_requests_endpoints_error_without_msg
        with self.assertRaises(WebApiException) as context:
            with self.assertLogs(self.logname) as log:
                self.webapi.get_topology()

        self.assertEqual(
            context.exception.__str__(),
            "WebApi error: MOCK_TENANT: "
            "Error fetching topology endpoints: 400 BAD REQUEST"
        )

        self.assertEqual(
            log.output, [
                f"ERROR:{self.logname}:MOCK_TENANT: "
                f"Error fetching topology endpoints: 400 BAD REQUEST"
            ]
        )
