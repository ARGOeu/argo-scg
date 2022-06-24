import configparser

from argo_scg.exceptions import ConfigException


class Config:
    def __init__(self, config_file):
        self.conf = self._read(config_file)
        self.tenants = self._get_tenants()

    @staticmethod
    def _read(config_file):
        config = configparser.ConfigParser()
        config.read(config_file)
        return config

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
