import os
import unittest

from argo_scg.config import Config, AgentConfig
from argo_scg.exceptions import ConfigException

config_file_ok = """[GENERAL]
sensu_url = http://sensu.mock.url/
sensu_token = s3ns8t0k3n
webapi_url = https://web-api.mock.url/

[TENANT1]
poem_url = https://tenant1.poem.mock.url/
poem_token = p03mtok3n
webapi_token = w3b4p1t0k3n
topology_groups_filter = type=NGI&tags=certification:Certified
topology_endpoints_filter = tags=monitored:1
attributes = /path/to/attributes1
metricprofiles = PROFILE1, PROFILE2,PROFILE3
topology = /path/to/topology1
secrets = /path/to/secrets
publish = true
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant1_metrics
agents_configuration = /path/to/config-file

[TENANT2]
poem_url = https://tenant2.poem.mock.url/
poem_token = p03mtok3n22
webapi_token = w3b4p1t0k3n2
attributes = /path/to/attributes2
metricprofiles = PROFILE4
publish = false
subscription = hostname_with_id
skipped_metrics = eudat.b2safe.irods-crud, argo.connectors.check
"""

config_file_ok_hostname_service_sub = """[GENERAL]
sensu_url = http://sensu.mock.url/
sensu_token = s3ns8t0k3n
webapi_url = https://web-api.mock.url/

[TENANT1]
poem_url = https://tenant1.poem.mock.url/
poem_token = p03mtok3n
webapi_token = w3b4p1t0k3n
topology_groups_filter = type=NGI&tags=certification:Certified
topology_endpoints_filter = tags=monitored:1
attributes = /path/to/attributes1
metricprofiles = PROFILE1, PROFILE2,PROFILE3
topology = /path/to/topology1
secrets = /path/to/secrets
publish = true
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant1_metrics
agents_configuration = /path/to/config-file
subscription = servicetype

[TENANT2]
poem_url = https://tenant2.poem.mock.url/
poem_token = p03mtok3n22
webapi_token = w3b4p1t0k3n2
attributes = /path/to/attributes2
metricprofiles = PROFILE4
publish = false
subscription = hostname
"""

config_file_ok_entity_sub = """[GENERAL]
sensu_url = http://sensu.mock.url/
sensu_token = s3ns8t0k3n
webapi_url = https://web-api.mock.url/

[TENANT1]
poem_url = https://tenant1.poem.mock.url/
poem_token = p03mtok3n
webapi_token = w3b4p1t0k3n
topology_groups_filter = type=NGI&tags=certification:Certified
topology_endpoints_filter = tags=monitored:1
attributes = /path/to/attributes1
metricprofiles = PROFILE1, PROFILE2,PROFILE3
topology = /path/to/topology1
secrets = /path/to/secrets
publish = true
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant1_metrics
agents_configuration = /path/to/config-file

[TENANT2]
poem_url = https://tenant2.poem.mock.url/
poem_token = p03mtok3n22
webapi_token = w3b4p1t0k3n2
attributes = /path/to/attributes2
metricprofiles = PROFILE4
publish = false
subscription = entity
"""

config_file_ok_custom_namespace = """[GENERAL]
sensu_url = http://sensu.mock.url/
sensu_token = s3ns8t0k3n
webapi_url = https://web-api.mock.url/

[TENANT1]
poem_url = https://tenant1.poem.mock.url/
poem_token = p03mtok3n
webapi_token = w3b4p1t0k3n
topology_groups_filter = type=NGI&tags=certification:Certified
topology_endpoints_filter = tags=monitored:1
attributes = /path/to/attributes1
metricprofiles = PROFILE1, PROFILE2,PROFILE3
topology = /path/to/topology1
secrets = /path/to/secrets
publish = true
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant1_metrics
namespace = custom

[TENANT2]
poem_url = https://tenant2.poem.mock.url/
poem_token = p03mtok3n22
webapi_token = w3b4p1t0k3n2
attributes = /path/to/attributes2
metricprofiles = PROFILE4
publish = false
subscription = hostname_with_id
"""

config_file_ok_custom_namespace_multiple_tenants = """[GENERAL]
sensu_url = http://sensu.mock.url/
sensu_token = s3ns8t0k3n
webapi_url = https://web-api.mock.url/

[TENANT1]
poem_url = https://tenant1.poem.mock.url/
poem_token = p03mtok3n
webapi_token = w3b4p1t0k3n
topology_groups_filter = type=NGI&tags=certification:Certified
topology_endpoints_filter = tags=monitored:1
attributes = /path/to/attributes1
metricprofiles = PROFILE1, PROFILE2,PROFILE3
topology = /path/to/topology1
secrets = /path/to/secrets
publish = true
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant1_metrics
namespace = custom

[TENANT2]
poem_url = https://tenant2.poem.mock.url/
poem_token = p03mtok3n22
webapi_token = w3b4p1t0k3n2
attributes = /path/to/attributes2
metricprofiles = PROFILE4
publish = false
subscription = hostname_with_id

[TENANT3]
poem_url = https://tenant3.poem.mock.url/
poem_token = p03mtok3n3
webapi_token = w3b4p1t0k3n3
attributes = /path/to/attributes3
metricprofiles = PROFILE
secrets = /path/to/secrets
publish = true
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant3_metrics
namespace = custom
"""

config_file_missing_section = """[TENANT1]
poem_url = https://tenant1.poem.mock.url/
poem_token = p03mtok3n
webapi_token = w3b4p1t0k3n
attributes = /path/to/attributes1
metricprofiles = PROFILE1, PROFILE2,PROFILE3
topology = /path/to/topology1
publish = true
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant1_metrics

[TENANT2]
poem_url = https://tenant2.poem.mock.url/
poem_token = p03mtok3n22
webapi_token = w3b4p1t0k3n2
attributes = /path/to/attributes2
metricprofiles = PROFILE4
publish = false
"""

config_file_missing_option_general = """[GENERAL]
mock_option = http://sensu.mock.url/

[TENANT1]
poem_url = https://tenant1.poem.mock.url/
poem_token = p03mtok3n
webapi_token = w3b4p1t0k3n
attributes = /path/to/attributes1
metricprofiles = PROFILE1, PROFILE2,PROFILE3
topology = /path/to/topology1
publish = true
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant1_metrics

[TENANT2]
poem_url = https://tenant2.poem.mock.url/
poem_token = p03mtok3n22
webapi_token = w3b4p1t0k3n2
attributes = /path/to/attributes2
metricprofiles = PROFILE4
publish = false
"""

config_file_missing_option_tenant = """[GENERAL]
sensu_url = http://sensu.mock.url/
sensu_token = s3ns8t0k3n
webapi_url = https://web-api.mock.url/

[TENANT1]
mock_option = yes

[TENANT2]
poem_url = https://tenant2.poem.mock.url/
poem_token = p03mtok3n22
webapi_token = w3b4p1t0k3n2
attributes = /path/to/attributes2
metricprofiles = PROFILE4
publish = false
"""

config_file_wrong_subscription_entry = """[GENERAL]
sensu_url = http://sensu.mock.url/
sensu_token = s3ns8t0k3n
webapi_url = https://web-api.mock.url/

[TENANT1]
poem_url = https://tenant1.poem.mock.url/
poem_token = p03mtok3n
webapi_token = w3b4p1t0k3n
topology_groups_filter = type=NGI&tags=certification:Certified
topology_endpoints_filter = tags=monitored:1
attributes = /path/to/attributes1
metricprofiles = PROFILE1, PROFILE2,PROFILE3
topology = /path/to/topology1
secrets = /path/to/secrets
publish = true
publisher_queue = /var/spool/argo-nagios-ams-publisher/tenant1_metrics

[TENANT2]
poem_url = https://tenant2.poem.mock.url/
poem_token = p03mtok3n22
webapi_token = w3b4p1t0k3n2
attributes = /path/to/attributes2
metricprofiles = PROFILE4
publish = false
subscription = nonexisting
"""

agents_config_ok = """[AGENTS]
sensu-agent1.argo.eu = webdav, xrootd
sensu-agent2.argo.eu = ARC-CE
"""

agents_config_missing_agents_section = """[TEST]
sensu-agent1.argo.eu = webdav, xrootd
"""

agents_config_empty_file = """
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
            "Configuration file error: "
            "File nonexisting.conf does not exist"
        )

    def test_get_tenants(self):
        self.assertEqual(
            self.config.get_tenants(), {
                "TENANT1": "TENANT1",
                "TENANT2": "TENANT2"
            }
        )

    def test_get_tenants_if_custom(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_ok_custom_namespace)

        config = Config(config_file=config_file_name)

        self.assertEqual(
            config.get_tenants(), {
                "TENANT1": "custom",
                "TENANT2": "TENANT2"
            }
        )

    def test_get_namespaces(self):
        self.assertEqual(
            self.config.get_namespaces(), {
                "TENANT1": ["TENANT1"],
                "TENANT2": ["TENANT2"]
            }
        )

    def test_get_namespaces_if_custom(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_ok_custom_namespace)

        config = Config(config_file=config_file_name)

        self.assertEqual(
            config.get_namespaces(), {
                "custom": ["TENANT1"],
                "TENANT2": ["TENANT2"]
            }
        )

    def test_get_namespaces_if_multiple_tenants(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_ok_custom_namespace_multiple_tenants)

        config = Config(config_file=config_file_name)

        self.assertEqual(
            config.get_namespaces(), {
                "custom": ["TENANT1", "TENANT3"],
                "TENANT2": ["TENANT2"]
            }
        )

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
            "Configuration file error: No section: 'GENERAL'"
        )

    def test_get_sensu_url_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_general)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_sensu_url()

        self.assertEqual(
            context.exception.__str__(),
            "Configuration file error: "
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
            "Configuration file error: No section: 'GENERAL'"
        )

    def test_get_sensu_token_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_general)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_sensu_token()

        self.assertEqual(
            context.exception.__str__(),
            "Configuration file error: "
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
            "Configuration file error: "
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
            "Configuration file error: "
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
            "Configuration file error: No section: 'GENERAL'"
        )

    def test_get_webapi_url_missing_option(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_missing_option_general)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_webapi_url()

        self.assertEqual(
            context.exception.__str__(),
            "Configuration file error: "
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
            "Configuration file error: "
            "No option 'webapi_token' in section: 'TENANT1'"
        )

    def test_get_topology_groups_filter(self):
        self.assertEqual(
            self.config.get_topology_groups_filter(),
            {
                "TENANT1": "type=NGI&tags=certification:Certified",
                "TENANT2": ""
            }
        )

    def test_Get_topology_endpoints_filter(self):
        self.assertEqual(
            self.config.get_topology_endpoints_filter(),
            {
                "TENANT1": "tags=monitored:1",
                "TENANT2": ""
            }
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
            "Configuration file error: "
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
            "Configuration file error: "
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

    def test_get_subscriptions(self):
        self.assertEqual(
            self.config.get_subscriptions(), {
                "TENANT1": "hostname", "TENANT2": "hostname_with_id"
            }
        )

    def test_get_subscriptions_hostname_servicetype(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_ok_hostname_service_sub)

        config = Config(config_file=config_file_name)

        self.assertEqual(
            config.get_subscriptions(), {
                "TENANT1": "servicetype", "TENANT2": "hostname"
            }
        )

    def test_get_subscriptions_entity(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_ok_entity_sub)

        config = Config(config_file=config_file_name)

        self.assertEqual(
            config.get_subscriptions(), {
                "TENANT1": "hostname", "TENANT2": "entity"
            }
        )

    def test_get_subscriptions_with_wrong_entry(self):
        with open(config_file_name, "w") as f:
            f.write(config_file_wrong_subscription_entry)

        config = Config(config_file=config_file_name)

        with self.assertRaises(ConfigException) as context:
            config.get_subscriptions()

        self.assertEqual(
            context.exception.__str__(),
            "Configuration file error: Unacceptable value 'nonexisting' for "
            "option: 'subscription' in section: 'TENANT2'"
        )

    def test_get_agents_configurations(self):
        self.assertEqual(
            self.config.get_agents_configurations(), {
                "TENANT1": "/path/to/config-file", "TENANT2": ""
            }
        )

    def test_get_skipped_metrics(self):
        self.assertEqual(
            self.config.get_skipped_metrics(), {
                "TENANT1": [],
                "TENANT2": ["eudat.b2safe.irods-crud", "argo.connectors.check"]
            }
        )


class AgentConfigTests(unittest.TestCase):
    def setUp(self):
        with open(config_file_name, "w") as f:
            f.write(agents_config_ok)

        self.config = AgentConfig(file=config_file_name)

    def tearDown(self):
        if os.path.isfile(config_file_name):
            os.remove(config_file_name)

    def test_config_nonexisting_file(self):
        with self.assertRaises(ConfigException) as context:
            AgentConfig(file="nonexisting.conf")

        self.assertEqual(
            context.exception.__str__(),
            "Configuration file error: "
            "File nonexisting.conf does not exist"
        )

    def test_get_custom_subs(self):
        self.assertEqual(
            self.config.get_custom_subs(), {
                "sensu-agent1.argo.eu": ["webdav", "xrootd"],
                "sensu-agent2.argo.eu": ["ARC-CE"]
            }
        )

    def test_get_custom_subs_if_missing_agents_section(self):
        with open(config_file_name, "w") as f:
            f.write(agents_config_missing_agents_section)

        config = AgentConfig(file=config_file_name)
        self.assertEqual(config.get_custom_subs(), None)

    def test_get_custom_subs_if_empty_file(self):
        with open(config_file_name, "w") as f:
            f.write(agents_config_empty_file)

        config = AgentConfig(file=config_file_name)
        self.assertEqual(config.get_custom_subs(), None)
