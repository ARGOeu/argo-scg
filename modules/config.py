import configparser

from argo_scg.exceptions import ConfigException


class _Config:
    def __init__(self, file):
        self.file = file
        self._check_file_exists()
        self.conf = self._read()

    def _check_file_exists(self):
        conf = configparser.ConfigParser()
        try:
            with open(self.file) as f:
                conf.read_file(f)

        except IOError:
            raise ConfigException(f"File {self.file} does not exist")

    def _read(self):
        config = configparser.ConfigParser()
        config.read(self.file)
        return config


class Config(_Config):
    def __init__(self, config_file):
        super().__init__(config_file)
        self.tenants = self._get_tenants()

    @staticmethod
    def _remove_trailing_slash(url):
        if url.endswith("/"):
            url = url[:-1]

        return url

    def get_sensu_url(self):
        try:
            return self._remove_trailing_slash(
                self.conf.get("GENERAL", "sensu_url")
            )

        except (configparser.NoSectionError, configparser.NoOptionError) as err:
            raise ConfigException(err)

    def get_sensu_token(self):
        try:
            return self.conf.get("GENERAL", "sensu_token")

        except (configparser.NoSectionError, configparser.NoOptionError) as err:
            raise ConfigException(err)

    def _get_tenants(self):
        tenants = list()
        for section in self.conf.sections():
            if section != "GENERAL":
                tenants.append(section)

        return tenants

    def get_tenants(self):
        return self.tenants

    def get_poem_urls(self):
        try:
            urls = dict()
            for tenant in self.tenants:
                urls.update(
                    {
                        tenant:
                            self._remove_trailing_slash(
                                self.conf.get(tenant, "poem_url")
                            )
                    }
                )

            return urls

        except configparser.NoOptionError as err:
            raise ConfigException(err)

    def get_poem_tokens(self):
        try:
            tokens = dict()
            for tenant in self.tenants:
                tokens.update({tenant: self.conf.get(tenant, "poem_token")})

            return tokens

        except configparser.NoOptionError as err:
            raise ConfigException(err)

    def get_webapi_url(self):
        try:
            return self._remove_trailing_slash(
                self.conf.get("GENERAL", "webapi_url")
            )

        except (configparser.NoSectionError, configparser.NoOptionError) as err:
            raise ConfigException(err)

    def get_webapi_tokens(self):
        try:
            tokens = dict()
            for tenant in self.tenants:
                tokens.update({tenant: self.conf.get(tenant, "webapi_token")})

            return tokens

        except configparser.NoOptionError as err:
            raise ConfigException(err)

    def _get_topology_filter(self, topo_type):
        try:
            topology_filter = dict()
            for tenant in self.tenants:
                try:
                    filter_value = self.conf.get(
                        tenant, f"topology_{topo_type}_filter"
                    )

                except configparser.NoOptionError:
                    filter_value = ""

                topology_filter.update({tenant: filter_value})

            return topology_filter

        except configparser.NoOptionError as err:
            raise ConfigException(err)

    def get_topology_groups_filter(self):
        return self._get_topology_filter(topo_type="groups")

    def get_topology_endpoints_filter(self):
        return self._get_topology_filter(topo_type="endpoints")

    def get_metricprofiles(self):
        try:
            profiles = dict()
            for tenant in self.tenants:
                metricprofiles = self.conf.get(
                    tenant, "metricprofiles"
                ).split(",")
                profiles.update({tenant: [mp.strip() for mp in metricprofiles]})

            return profiles

        except configparser.NoOptionError as err:
            raise ConfigException(err)

    def get_topology(self):
        try:
            topology = dict()
            for tenant in self.tenants:
                try:
                    topology_value = self.conf.get(tenant, "topology")

                except configparser.NoOptionError:
                    topology_value = ""

                topology.update({tenant: topology_value})

            return topology

        except configparser.NoOptionError as err:
            raise ConfigException(err)

    def get_secrets(self):
        secrets = dict()
        for tenant in self.tenants:
            try:
                secret_value = self.conf.get(tenant, "secrets")

            except configparser.NoOptionError:
                secret_value = ""

            secrets.update({tenant: secret_value})

        return secrets

    def publish(self):
        try:
            publish = dict()
            for tenant in self.tenants:
                value = self.conf.getboolean(tenant, "publish")
                publish.update({tenant: value})

            return publish

        except configparser.NoOptionError as err:
            raise ConfigException(err)

    def get_publisher_queue(self):
        queue = dict()
        for tenant, publish in self.publish().items():
            if publish:
                queue_value = self.conf.get(tenant, "publisher_queue")

                queue.update({tenant: queue_value})

        return queue

    def get_subscriptions(self):
        subscriptions = dict()
        for tenant in self.tenants:
            try:
                value = self.conf.get(tenant, "subscription")

                if value not in [
                    "entity", "hostname", "hostname_with_id", "servicetype"
                ]:
                    raise ConfigException(
                        f"Unacceptable value '{value}' for option: "
                        f"'subscription' in section: '{tenant}'"
                    )

            except configparser.NoOptionError:
                value = "hostname"

            subscriptions.update({tenant: value})

        return subscriptions

    def get_agents_configurations(self):
        configurations = dict()

        for tenant in self.tenants:
            try:
                configuration = self.conf.get(tenant, "agents_configuration")

            except configparser.NoOptionError:
                configuration = ""

            configurations.update({tenant: configuration})

        return configurations

    def get_skipped_metrics(self):
        skipped_metrics = dict()
        for tenant in self.tenants:
            try:
                metrics = self.conf.get(tenant, "skipped_metrics").split(",")
                skipped_metrics.update({tenant: [m.strip() for m in metrics]})

            except configparser.NoOptionError:
                skipped_metrics.update({tenant: []})

        return skipped_metrics


class AgentConfig(_Config):
    def get_custom_subs(self):
        custom = dict()
        try:
            agents = self.conf.items("AGENTS")

            for agent in agents:
                custom.update({
                    agent[0]: [item.strip() for item in agent[1].split(",")]
                })

        except configparser.NoSectionError:
            pass

        if custom:
            return custom

        else:
            return None
