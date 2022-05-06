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
                "SAM_PORT": "-p"
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


def mock_poem_metrics_request(*args, **kwargs):
    return MockResponse(mock_metrics, status_code=200)


def mock_poem_metrics_request_with_error_with_msg(*args, **kwargs):
    return MockResponse({"detail": "Something went wrong."}, status_code=400)


def mock_poem_metrics_request_with_error_without_msg(*args, **kwargs):
    return MockResponse(None, status_code=400)


class PoemTests(unittest.TestCase):
    def setUp(self) -> None:
        servicetypes = {
            "generic.http.ar-argoui-ni4os": ["argo.webui"],
            "generic.http.connect": ["argo.webui"],
            "generic.certificate.validity": ["argo.webui", "argo.test"],
            "generic.tcp.connect": ["argo.test"]
        }
        self.poem = Poem(
            url="https://mock.poem.url", token="P03mt0k3n"
        )

    @patch("requests.get")
    def test_get_metrics(self, mock_request):
        mock_request.side_effect = mock_poem_metrics_request
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

    @patch("requests.get")
    def test_get_metrics_with_error_with_msg(self, mock_request):
        mock_request.side_effect = mock_poem_metrics_request_with_error_with_msg
        with self.assertRaises(PoemException) as context:
            self.poem.get_metrics_configurations()
            mock_request.assert_called_once_with(
                "https://mock.poem.url/api/v2/metrics",
                headers={'x-api-key': 'P03mt0k3n'}
            )

        self.assertEqual(
            context.exception.__str__(),
            "Poem error: Error fetching metrics: 400 BAD REQUEST: "
            "Something went wrong."
        )

    @patch("requests.get")
    def test_get_metrics_with_error_without_msg(self, mock_request):
        mock_request.side_effect = \
            mock_poem_metrics_request_with_error_without_msg
        with self.assertRaises(PoemException) as context:
            self.poem.get_metrics_configurations()
            mock_request.assert_called_once_with(
                "https://mock.poem.url/api/v2/metrics",
                headers={'x-api-key': 'P03mt0k3n'}
            )

        self.assertEqual(
            context.exception.__str__(),
            "Poem error: Error fetching metrics: 400 BAD REQUEST"
        )
