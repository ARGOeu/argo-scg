import os
import unittest

from argo_scg.config import Config
from argo_scg.exceptions import ConfigException

config_file_ok = """
[GENERAL]\n
sensu_url = http://sensu.mock.url/\n
sensu_token = s3ns8t0k3n\n
webapi_url = https://web-api.mock.url/\n
\n
[TENANT1]\n
poem_url = https://tenant1.poem.mock.url/\n
poem_token = p03mtok3n\n
webapi_token = w3b4p1t0k3n\n
attributes = /path/to/attributes1\n
metricprofiles = PROFILE1, PROFILE2,PROFILE3\n
topology = /path/to/topology1\n
secrets = /path/to/secrets\n
publish = true\n
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant1_metrics\n
\n
[TENANT2]\n
poem_url = https://tenant2.poem.mock.url/\n
poem_token = p03mtok3n22\n
webapi_token = w3b4p1t0k3n2\n
attributes = /path/to/attributes2\n
metricprofiles = PROFILE4\n
publish = false
"""

config_file_missing_section = """
[TENANT1]\n
poem_url = https://tenant1.poem.mock.url/\n
poem_token = p03mtok3n\n
webapi_token = w3b4p1t0k3n\n
attributes = /path/to/attributes1\n
metricprofiles = PROFILE1, PROFILE2,PROFILE3\n
topology = /path/to/topology1\n
publish = true\n
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant1_metrics\n
\n
[TENANT2]\n
poem_url = https://tenant2.poem.mock.url/\n
poem_token = p03mtok3n22\n
webapi_token = w3b4p1t0k3n2\n
attributes = /path/to/attributes2\n
metricprofiles = PROFILE4\n
publish = false
"""

config_file_missing_option_general = """
[GENERAL]\n
mock_option = http://sensu.mock.url/\n
\n
[TENANT1]\n
poem_url = https://tenant1.poem.mock.url/\n
poem_token = p03mtok3n\n
webapi_token = w3b4p1t0k3n\n
attributes = /path/to/attributes1\n
metricprofiles = PROFILE1, PROFILE2,PROFILE3\n
topology = /path/to/topology1\n
publish = true\n
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant1_metrics\n
\n
[TENANT2]\n
poem_url = https://tenant2.poem.mock.url/\n
poem_token = p03mtok3n22\n
webapi_token = w3b4p1t0k3n2\n
attributes = /path/to/attributes2\n
metricprofiles = PROFILE4\n
publish = false
"""

config_file_missing_option_tenant = """
[GENERAL]\n
sensu_url = http://sensu.mock.url/\n
sensu_token = s3ns8t0k3n\n
webapi_url = https://web-api.mock.url/\n
\n
[TENANT1]\n
mock_option = yes
\n
[TENANT2]\n
poem_url = https://tenant2.poem.mock.url/\n
poem_token = p03mtok3n22\n
webapi_token = w3b4p1t0k3n2\n
attributes = /path/to/attributes2\n
metricprofiles = PROFILE4\n
publish = false
"""

config_file_name = "test.conf"


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        with open(config_file_name, "w") as f:
            f.write(config_file_ok)

        self.config = Config(config_file=config_file_name)

    def tearDown(self) -> None:
        if os.path.isfile(config_file_name):
            os.remove(config_file_name)

    def test_read_config_nonexisting_file(self):
        with self.assertRaises(ConfigException) as context:
            Config(config_file="nonexisting.conf")

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: "
            "File nonexisting.conf does not exist"
        )

    def test_get_tenants(self):
        self.assertEqual(self.config.get_tenants(), ["TENANT1", "TENANT2"])

    def test_get_sensu_url(self):
        self.assertEqual(self.config.get_sensu_url(), "http://sensu.mock.url")

    def test_get_sensu_url_missing_section(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_section)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_sensu_url()

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: No section: 'GENERAL'"
        )

    def test_get_sensu_url_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_general)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_sensu_url()

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: "
            "No option 'sensu_url' in section: 'GENERAL'"
        )

    def test_get_sensu_token(self):
        self.assertEqual(self.config.get_sensu_token(), "s3ns8t0k3n")

    def test_get_sensu_token_missing_section(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_section)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_sensu_token()

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: No section: 'GENERAL'"
        )

    def test_get_sensu_token_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_general)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_sensu_token()

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: "
            "No option 'sensu_token' in section: 'GENERAL'"
        )

    def test_get_poem_urls(self):
        self.assertEqual(
            self.config.get_poem_urls(),
            {
                "TENANT1": "https://tenant1.poem.mock.url",
                "TENANT2": "https://tenant2.poem.mock.url"
            }
        )

    def test_get_poem_urls_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_tenant)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_poem_urls()

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: "
            "No option 'poem_url' in section: 'TENANT1'"
        )

    def test_get_poem_tokens(self):
        self.assertEqual(
            self.config.get_poem_tokens(),
            {
                "TENANT1": "p03mtok3n",
                "TENANT2": "p03mtok3n22"
            }
        )

    def test_get_poem_tokens_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_tenant)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_poem_tokens()

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: "
            "No option 'poem_token' in section: 'TENANT1'"
        )

    def test_get_webapi_url(self):
        self.assertEqual(
            self.config.get_webapi_url(), 'https://web-api.mock.url'
        )

    def test_get_webapi_url_missing_section(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_section)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_webapi_url()

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: No section: 'GENERAL'"
        )

    def test_get_webapi_url_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_general)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_webapi_url()

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: "
            "No option 'webapi_url' in section: 'GENERAL'"
        )

    def test_get_webapi_tokens(self):
        self.assertEqual(
            self.config.get_webapi_tokens(),
            {
                "TENANT1": "w3b4p1t0k3n",
                "TENANT2": "w3b4p1t0k3n2"
            }
        )

    def test_get_webapi_tokens_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_tenant)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_webapi_tokens()

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: "
            "No option 'webapi_token' in section: 'TENANT1'"
        )

    def test_get_metricprofiles(self):
        self.assertEqual(
            self.config.get_metricprofiles(),
            {
                "TENANT1": ["PROFILE1", "PROFILE2", "PROFILE3"],
                "TENANT2": ["PROFILE4"]
            }
        )

    def test_get_metricprofiles_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_tenant)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_metricprofiles()

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: "
            "No option 'metricprofiles' in section: 'TENANT1'"
        )

    def test_get_topology(self):
        self.assertEqual(
            self.config.get_topology(),
            {
                "TENANT1": "/path/to/topology1",
                "TENANT2": ""
            }
        )

    def test_get_topology_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_tenant)

        config = Config(config_file=config_file_name)
        self.assertEqual(
            config.get_topology(),
            {
                "TENANT1": "",
                "TENANT2": ""
            }
        )

    def test_get_secrets(self):
        self.assertEqual(
            self.config.get_secrets(),
            {
                "TENANT1": "/path/to/secrets",
                "TENANT2": ""
            }
        )

    def test_get_secrets_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_tenant)

        config = Config(config_file=config_file_name)
        self.assertEqual(
            config.get_secrets(),
            {
                "TENANT1": "",
                "TENANT2": ""
            }
        )

    def test_publish(self):
        self.assertEqual(
            self.config.publish(), {"TENANT1": True, "TENANT2": False}
        )

    def test_publish_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_tenant)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.publish()

        self.assertEqual(
            context.exception.__str__(),
            "Error reading configuration file: "
            "No option 'publish' in section: 'TENANT1'"
        )

    def test_get_publisher_queue(self):
        self.assertEqual(
            self.config.get_publisher_queue(),
            {
                "TENANT1":
                    "/var/spool/argo-nagios-ams-publisher/tenant1_metrics"
            }
        )
