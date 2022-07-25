import unittest
from unittest.mock import patch

from argo_scg.poem import Poem, PoemException

from utils import MockResponse

mock_metrics = [
    {
        "generic.http.ar-argoui-ni4os": {
            "tags": [
                "argo.webui",
                "harmonized"
            ],
            "probe": "check_http",
            "config": {
                "timeout": "30",
                "retryInterval": "3",
                "path": "$USER1$",
                "maxCheckAttempts": "3",
                "interval": "5"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-r": "argo.eu",
                "-u": "/ni4os/report-ar/Critical/NGI?accept=csv",
                "--ssl": "0",
                "--onredirect": "follow"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http.html"
        }
    },
    {
        "generic.http.connect": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_http",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "path": "$USER1$",
                "retryInterval": "3",
                "timeout": "60"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "SSL": "-S --sni",
                "PORT": "-p",
                "PATH": "-u"
            },
            "parameter": {
                "--link": "0",
                "--onredirect": "follow"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http.html"
        }
    },
    {
        "generic.tcp.connect": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_tcp",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "path": "$USER1$",
                "retryInterval": "3",
                "timeout": "120"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-p": "443"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_tcp.html"
        }
    },
    {
        "generic.http.connect-gocdb": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_http",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "path": "$USER1$",
                "retryInterval": "3",
                "timeout": "120"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "NAGIOS_HOST_CERT": "-J",
                "NAGIOS_HOST_KEY": "-K"
            },
            "parameter": {
                "--link": "0",
                "-u": "/portal/GOCDB_monitor/ops_monitor_check.php",
                "--ssl": "0"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http.html"
        }
    },
    {
        "generic.http.connect-gocdb-pi-ni4os": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_http",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "path": "$USER1$",
                "retryInterval": "3",
                "timeout": "120"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "NAGIOS_HOST_CERT": "-J",
                "NAGIOS_HOST_KEY": "-K"
            },
            "parameter": {
                "--link": "0",
                "-u": "\"/gocdbpi/public/?method=get_site_list&sitename=UKIM\"",
                "--onredirect": "follow",
                "-r": "'<SITE .* NAME=\"UKIM\" .*/>'"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http.html"
        }
    },
    {
        "generic.certificate.validity": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_ssl_cert",
            "config": {
                "timeout": "60",
                "retryInterval": "30",
                "path": "$USER1$",
                "maxCheckAttempts": "2",
                "interval": "240"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "NAGIOS_HOST_CERT": "-C",
                "NAGIOS_HOST_KEY": "-K"
            },
            "parameter": {
                "-w": "30 -c 0 -N --altnames",
                "--rootcert-dir": "/etc/grid-security/certificates",
                "--rootcert-file": "/etc/pki/tls/certs/ca-bundle.crt"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/matteocorti/check_ssl_cert/blob/"
                      "master/README.md"
        }
    },
    {
        "generic.http.connect-nagios-ui": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_http",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "path": "$USER1$",
                "retryInterval": "3",
                "timeout": "30"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "NAGIOS_ACTUAL_HOST_CERT": "-J",
                "NAGIOS_ACTUAL_HOST_KEY": "-K",
            },
            "parameter": {
                "--ssl": "0",
                "-s": "\"Status Details\"",
                "-u": "\"/nagios/cgi-bin/status.cgi?"
                      "hostgroup=all&style=hostdetail\""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http.html"
        }
    }
]


mock_metrics_with_config_error = [
    mock_metrics[0],
    {
        "generic.http.connect": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_http",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "pth": "$USER1$",
                "retryInterval": "3",
                "timeout": "60"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "SSL": "-S --sni",
                "PORT": "-p",
                "PATH": "-u"
            },
            "parameter": {
                "--link": "0",
                "--onredirect": "follow"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http.html"
        }
    },
    {
        "ch.cern.HTCondorCE-JobSubmit": {
            "tags": [
                "compute",
                "htc",
                "htcondor",
                "job submit"
            ],
            "probe": "",
            "config": {},
            "flags": {
                "OBSESS": "1",
                "PASSIVE": "1",
                "VO": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "ch.cern.HTCondorCE-JobState",
            "docurl": ""
        }
    }
]


mock_metric_overrides = {
    "local": {
        "global_attributes": [
            {
                "attribute": "NAGIOS_ACTUAL_HOST_CERT",
                "value": "/etc/nagios/actual/path/hostcert.pem"
            },
            {
                "attribute": "NAGIOS_ACTUAL_HOST_KEY",
                "value": "/etc/nagios/actual/path/hostkey.pem"
            }
        ],
        "host_attributes": [
            {
                "hostname": "host.argo.com",
                "attribute": "AMS_TOKEN",
                "value": "ANOTHER_AMS_TOKEN"
            },
            {
                "hostname": "host2.argo.com",
                "attribute": "GRIDPROXY_NAGIOS_SERVICE",
                "value": "hr.srce.GridProxy-Valid-ops"
            }
        ],
        "metric_parameters": [
            {
                "hostname": "host.argo.com",
                "metric": "argo.mock.metric",
                "parameter": "-u",
                "value": "https://some.other.url"
            }
        ]
    }
}


def mock_poem_metrics_request(*args, **kwargs):
    return MockResponse(mock_metrics, status_code=200)


def mock_poem_metrics_request_error_param(*args, **kwargs):
    return MockResponse(mock_metrics_with_config_error, status_code=200)


def mock_poem_metric_overrides_request(*args, **kwargs):
    return MockResponse(mock_metric_overrides, status_code=200)


def mock_poem_request_with_error_with_msg(*args, **kwargs):
    return MockResponse({"detail": "Something went wrong."}, status_code=400)


def mock_poem_request_with_error_without_msg(*args, **kwargs):
    return MockResponse(None, status_code=400)


class PoemTests(unittest.TestCase):
    def setUp(self):
        self.poem = Poem(
            url="https://mock.poem.url", token="P03mt0k3n", tenant="MOCK_TENANT"
        )
        self.logname = "argo-scg.poem"

    @patch("requests.get")
    def test_get_metrics(self, mock_request):
        mock_request.side_effect = mock_poem_metrics_request
        with self.assertLogs(self.logname) as log:
            metrics = self.poem.get_metrics_configurations()
        mock_request.assert_called_once()
        mock_request.assert_called_with(
            "https://mock.poem.url/api/v2/metrics",
            headers={'x-api-key': 'P03mt0k3n'}
        )
        metrics2 = mock_metrics
        for metric in metrics2:
            for key, value in metric.items():
                metric[key]["config"]["path"] = "/usr/lib64/nagios/plugins"
        self.assertEqual(metrics, metrics2)
        self.assertEqual(
            log.output, [
                f"INFO:{self.logname}:MOCK_TENANT: Fetching metrics...",
                f"INFO:{self.logname}:MOCK_TENANT: Fetching metrics... ok",
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Checking metric configuration: "
                f"generic.http.ar-argoui-ni4os... ok",
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Checking metric configuration: generic.http.connect... ok",
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Checking metric configuration: generic.tcp.connect... ok",
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Checking metric configuration: generic.http.connect-gocdb... "
                f"ok",
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Checking metric configuration: "
                f"generic.http.connect-gocdb-pi-ni4os... ok",
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Checking metric configuration: "
                f"generic.certificate.validity... ok",
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Checking metric configuration: "
                f"generic.http.connect-nagios-ui... ok"
            ]
        )

    @patch("requests.get")
    def test_get_metrics_with_error_with_msg(self, mock_request):
        mock_request.side_effect = mock_poem_request_with_error_with_msg
        with self.assertRaises(PoemException) as context:
            with self.assertLogs(self.logname) as log:
                self.poem.get_metrics_configurations()

        mock_request.assert_called_once_with(
            "https://mock.poem.url/api/v2/metrics",
            headers={'x-api-key': 'P03mt0k3n'}
        )

        self.assertEqual(
            context.exception.__str__(),
            "Poem error: MOCK_TENANT: Error fetching metrics: 400 BAD REQUEST: "
            "Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"INFO:{self.logname}:MOCK_TENANT: Fetching metrics...",
                f"ERROR:{self.logname}:MOCK_TENANT: Error fetching metrics: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.get")
    def test_get_metrics_with_error_without_msg(self, mock_request):
        mock_request.side_effect = mock_poem_request_with_error_without_msg
        with self.assertRaises(PoemException) as context:
            with self.assertLogs(self.logname) as log:
                self.poem.get_metrics_configurations()

        mock_request.assert_called_once_with(
            "https://mock.poem.url/api/v2/metrics",
            headers={'x-api-key': 'P03mt0k3n'}
        )

        self.assertEqual(
            context.exception.__str__(),
            "Poem error: MOCK_TENANT: Error fetching metrics: 400 BAD REQUEST"
        )

        self.assertEqual(
            log.output, [
                f"INFO:{self.logname}:MOCK_TENANT: Fetching metrics...",
                f"ERROR:{self.logname}:MOCK_TENANT: Error fetching metrics: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.get")
    def test_get_metrics_with_error_in_config(self, mock_request):
        mock_request.side_effect = mock_poem_metrics_request_error_param
        with self.assertLogs(self.logname) as log:
            metrics = self.poem.get_metrics_configurations()
        mock_request.assert_called_once()
        mock_request.assert_called_with(
            "https://mock.poem.url/api/v2/metrics",
            headers={'x-api-key': 'P03mt0k3n'}
        )
        metrics2 = [
            mock_metrics_with_config_error[0], mock_metrics_with_config_error[2]
        ]
        metrics2[0]["generic.http.ar-argoui-ni4os"]["config"]["path"] = \
            "/usr/lib64/nagios/plugins"

        self.assertEqual(metrics, metrics2)
        self.assertEqual(
            log.output, [
                f"INFO:{self.logname}:MOCK_TENANT: Fetching metrics...",
                f"INFO:{self.logname}:MOCK_TENANT: Fetching metrics... ok",
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Checking metric configuration: "
                f"generic.http.ar-argoui-ni4os... ok",
                f"WARNING:{self.logname}:MOCK_TENANT: "
                f"Error checking metric configuration: "
                f"generic.http.connect: Missing key 'path'",
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Checking metric configuration: "
                f"ch.cern.HTCondorCE-JobSubmit... ok"
            ]
        )

    @patch("requests.get")
    def test_get_metric_overrides(self, mock_request):
        mock_request.side_effect = mock_poem_metric_overrides_request
        with self.assertLogs(self.logname) as log:
            overrides = self.poem.get_metric_overrides()
        mock_request.assert_called_once()
        mock_request.assert_called_with(
            "https://mock.poem.url/api/v2/metricoverrides",
            headers={'x-api-key': 'P03mt0k3n'}
        )
        self.assertEqual(overrides, mock_metric_overrides)
        self.assertEqual(
            log.output, [
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Fetching metric overrides...",
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Fetching metric overrides... ok"
            ]
        )

    @patch("requests.get")
    def test_get_metric_overrides_with_error_with_msg(self, mock_request):
        mock_request.side_effect = mock_poem_request_with_error_with_msg
        with self.assertRaises(PoemException) as context:
            with self.assertLogs(self.logname) as log:
                self.poem.get_metric_overrides()

        mock_request.assert_called_once_with(
            "https://mock.poem.url/api/v2/metricoverrides",
            headers={'x-api-key': 'P03mt0k3n'}
        )

        self.assertEqual(
            context.exception.__str__(),
            "Poem error: MOCK_TENANT: Error fetching metric overrides: "
            "400 BAD REQUEST: Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Fetching metric overrides...",
                f"ERROR:{self.logname}:MOCK_TENANT: "
                f"Error fetching metric overrides: 400 BAD REQUEST: "
                f"Something went wrong."
            ]
        )

    @patch("requests.get")
    def test_get_metric_overrides_with_error_without_msg(self, mock_request):
        mock_request.side_effect = mock_poem_request_with_error_without_msg
        with self.assertRaises(PoemException) as context:
            with self.assertLogs(self.logname) as log:
                self.poem.get_metric_overrides()

        mock_request.assert_called_once_with(
            "https://mock.poem.url/api/v2/metricoverrides",
            headers={'x-api-key': 'P03mt0k3n'}
        )

        self.assertEqual(
            context.exception.__str__(),
            "Poem error: MOCK_TENANT: Error fetching metric overrides: "
            "400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"INFO:{self.logname}:MOCK_TENANT: "
                f"Fetching metric overrides...",
                f"ERROR:{self.logname}:MOCK_TENANT: "
                f"Error fetching metric overrides: 400 BAD REQUEST"
            ]
        )
