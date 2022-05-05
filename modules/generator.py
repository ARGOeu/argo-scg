import os
from urllib.parse import urlparse


hardcoded_attributes = {
    "NAGIOS_HOST_CERT": "/etc/nagios/globus/hostcert.pem",
    "NAGIOS_HOST_KEY": "/etc/nagios/globus/hostkey.pem",
    "KEYSTORE": "/etc/nagios/globus/keystore.jks",
    "TRUSTSTORE": "/etc/nagios/globus/truststore.ts"
}

default_ports = {
    "SITE_BDII_PORT": "2170",
    "BDII_PORT": "2170",
    "MDS_PORT": "2135",
    "GRIDFTP_PORT": "2811",
    "GRAM_PORT": "2119",
    "RB_PORT": "7772",
    "WMS_PORT": "7772",
    "MYPROXY_PORT": "7512",
    "RGMA_PORT": "8443",
    "TOMCAT_PORT": "8443",
    "LL_PORT": "9002",
    "LB_PORT": "9000",
    "WMPROXY_PORT": "7443",
    "SRM1_PORT": "8443",
    "SRM2_PORT": "8443",
    "GSISSH_PORT": "1975",
    "FTS_PORT": "8446",
    "VOMS_PORT": "8443",
    "GRIDICE_PORT": "2136",
    "CREAM_PORT": "8443",
    "QCG-COMPUTING_PORT": "19000",
    "QCG-NOTIFICATION_PORT": "19001",
    "QCG-BROKER_PORT": "8443",
    "STOMP_PORT": "6163",
    "STOMP_SSL_PORT": "6162",
    "OPENWIRE_PORT": "6166",
    "OPENWIRE_SSL_PORT": "6167",
    "HTCondorCE_PORT": "9619"
}

secrets = [
    "argo.api_EUDAT_STATUS_TOKEN",
    "argo.api_STATUS_TOKEN",
    "argo.ams_CE_PROJECT",
    "argo.ams_TOKEN",
    "ARGUS_SALT",
    "NAGIOS_B2ACCESS_LOGIN",
    "argo.api_TEST_TOKEN",
    "KEYCLOAK_CLIEND_ID",
    "BROKER_PASSWORD",
    "OIDC_REFRESH_TOKEN",
    "EDUGAIN_USER",
    "EGISSO_PASSWORD",
    "argo.ams_CE_TOKEN",
    "AGORA_PASSWORD",
    "KEYCLOAK_CLIENT_SECRET",
    "argo.api_EUDAT_TOKEN",
    "B2STAGE_API_PASSWORD",
    "AGORA_USERNAME",
    "B2STAGE_API_USERNAME",
    "BROKER_USERNAME",
    "KEYSTORE_PASSWORD",
    "OIDC_CLIENT_ID",
    "NAGIOS_B2ACCESS_PASSWORD",
    "APPDB_TOKEN",
    "EGISSO_USER",
    "OIDC_CLIENT_SECRET",
    "argo.api_TOKEN",
    "EDUGAIN_PASSWORD"
]


class ConfigurationGenerator:
    def __init__(
            self, metrics, metric_profiles, topology, profiles, local_attributes
    ):
        self.metric_profiles = [
            p for p in metric_profiles if p["name"] in profiles
        ]
        metrics_set = set()
        for profile in self.metric_profiles:
            for service in profile["services"]:
                for metric in service["metrics"]:
                    metrics_set.add(metric)

        metrics_list = list()
        metrics_with_endpoint_url = list()
        metrics_with_ports = list()
        metrics_with_ssl = list()
        for metric in metrics:
            for key, value in metric.items():
                if key in metrics_set:
                    metrics_list.append(metric)

                    if "PORT" in value["attribute"]:
                        metrics_with_ports.append(key)

                    if "SSL" in value["attribute"]:
                        metrics_with_ssl.append(key)

                    for attribute, attr_val in value["attribute"].items():
                        if attribute == "URL" or \
                                (attribute.endswith("_URL") and not
                                    (attribute.endswith("GOCDB_SERVICE_URL") or
                                        attribute == "OS_KEYSTONE_URL")):
                            metrics_with_endpoint_url.append(key)

        self.metrics = metrics_list
        self.topology = topology
        self.local_attributes = self._read_local_attributes(local_attributes)
        self.servicetypes = self._get_servicetypes()
        self.servicetypes4metrics = self._get_servicetypes4metrics()
        self.metrics4servicetypes = self._get_metrics4servicetypes()
        self.extensions = self._get_extensions()
        self.extensions4metrics = self._get_extensions4metrics()

        self.servicetypes_with_endpointURL = list()
        for metric in metrics_with_endpoint_url:
            self.servicetypes_with_endpointURL.extend(
                self.servicetypes4metrics[metric]
            )

        self.servicetypes_with_port = list()
        for metric in metrics_with_ports:
            self.servicetypes_with_port.extend(
                self.servicetypes4metrics[metric]
            )

        self.servicetypes_with_SSL = list()
        for metric in metrics_with_ssl:
            self.servicetypes_with_SSL.extend(
                self.servicetypes4metrics[metric]
            )

    @staticmethod
    def _read_local_attributes(filename):
        attrs = dict()
        with open(filename, 'r') as f:
            lines = f.readlines()

        for line in lines:
            data = line.strip().split('=')
            attrs.update({data[0].strip(): "=".join(data[1:]).strip()})

        return attrs

    def _is_extension_present_in_all_endpoints(self, services, extension):
        is_present = True
        endpoints = [
            endpoint for endpoint in self.topology
            if endpoint["service"] in services
        ]

        for endpoint in endpoints:
            if extension not in endpoint["tags"]:
                is_present = False
                break

        return is_present

    def _get_servicetypes4metrics(self):
        service_types = dict()
        for mp in self.metric_profiles:
            for service in mp["services"]:
                for metric in service["metrics"]:
                    if metric not in service_types:
                        service_types.update({metric: [service["service"]]})

                    else:
                        service_type = service_types[metric]
                        service_type.append(service["service"])
                        service_types.update({metric: service_type})

        return service_types

    def _get_metrics4servicetypes(self):
        metrics = dict()
        for mp in self.metric_profiles:
            for service in mp["services"]:
                metrics.update({service["service"]: service["metrics"]})

        return metrics

    def _get_extensions(self):
        extensions = set()
        for item in self.topology:
            for tag, value in item["tags"].items():
                if tag.startswith("info_ext_"):
                    extensions.add(tag[9:])

        return list(extensions)

    def _get_extensions4metrics(self):
        ext_dict = dict()
        for metric in self.metrics:
            for name, configuration in metric.items():
                for attribute, value in configuration["attribute"].items():
                    if attribute in self.extensions:
                        if attribute not in ext_dict:
                            ext_dict.update({attribute: [name]})

                        else:
                            metrics = ext_dict[attribute]
                            metrics.append(name)
                            ext_dict.update({attribute: metrics})

        return ext_dict

    def _handle_attributes(self, metric, attrs):
        attributes = ""
        issecret = False
        for key, value in attrs.items():
            if key in self.local_attributes:
                key = self.local_attributes[key]

            elif key in secrets:
                if "." in key:
                    key = key.split(".")[-1].upper()

                key = f"${key}"
                issecret = True

            else:
                if key == "NAGIOS_HOST_CERT":
                    if "ROBOT_CERT" in self.local_attributes:
                        key = self.local_attributes["ROBOT_CERT"]
                    else:
                        key = hardcoded_attributes[key]

                elif key == "NAGIOS_HOST_KEY":
                    if "ROBOT_KEY" in self.local_attributes:
                        key = self.local_attributes["ROBOT_KEY"]

                    else:
                        key = hardcoded_attributes[key]

                elif key in ["KEYSTORE", "TRUSTSTORE"]:
                    key = hardcoded_attributes[key]

                elif key == "TOP_BDII":
                    if "BDII_HOST" in self.local_attributes:
                        key = self.local_attributes["BDII_HOST"]
                    else:
                        key = ""

                elif key in default_ports:
                    key = default_ports[key]

                elif key == "SSL":
                    key = "{{ .labels.ssl }}"
                    value = ""

                elif key == "PATH":
                    key = "{{ .labels.path | default '/' }}"

                elif key == "PORT":
                    key = "{{ .labels.port }}"

                elif key.endswith("GOCDB_SERVICE_URL"):
                    key = "{{ .labels.info_url }}"

                elif key == "OS_KEYSTONE_URL":
                    key = "{{ .labels.info_url }}"

                elif key == "URL" or key.endswith("_URL"):
                    key = "{{ .labels.info_service_endpoint_url }}"

                elif key == "SITENAME":
                    key = "{{ .labels.site }}"

                elif key in self.extensions:
                    if self._is_extension_present_in_all_endpoints(
                        services=self.servicetypes4metrics[metric],
                        extension=f"info_ext_{key}"
                    ):
                        key = "{{ .labels.%s }}" % key.lower()

                    else:
                        key = "{{ .labels.%s__%s | default '' }}" % (
                            value.lstrip("-").lstrip("-").replace("-", "_"),
                            key.lower()
                        )
                        value = ""

                else:
                    key = "{{ .labels.%s }}" % key.lower()

            attr = f"{value} {key}".strip()

            attributes = f"{attributes} {attr}".strip()

        return attributes, issecret

    def generate_checks(self, publish, namespace="default"):
        checks = list()

        for metric in self.metrics:
            for name, configuration in metric.items():
                path = configuration["config"]["path"]
                if path.endswith("/"):
                    path = path[:-1]

                executable = os.path.join(path, configuration["probe"])

                if "NOTIMEOUT" not in configuration["flags"]:
                    parameters = "-t " + configuration["config"]["timeout"]

                else:
                    parameters = ""

                if "NOHOSTNAME" not in configuration["flags"]:
                    parameters = "-H {{ .labels.hostname }} " + parameters
                    parameters = parameters.strip()

                for key, value in configuration["parameter"].items():
                    param = f"{key} {value}".strip()
                    parameters = f"{parameters} {param}".strip()

                attributes, issecret = self._handle_attributes(
                    metric=name,
                    attrs=configuration["attribute"]
                )

                command = "{} {} {}".format(
                    executable, parameters.strip(), attributes.lstrip()
                )

                if issecret:
                    command = f"source /etc/sensu_envs ; " \
                              f"export $(cut -d= -f1 /etc/sensu_envs) ; " \
                              f"{command}"

                check = {
                    "command": command.strip(),
                    "subscriptions": self.servicetypes4metrics[name],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.{} == '{}'".format(
                                name.lower().replace(".", "_").replace(
                                    "-", "_"
                                ), name
                            )
                        ]
                    },
                    "interval":
                        int(configuration["config"]["interval"]) * 60,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": name,
                        "namespace": namespace
                    },
                    "round_robin": False
                }

                if publish and "NOPUBLISH" not in configuration["flags"]:
                    check.update({"handlers": ["publisher-handler"]})

                checks.append(check)

        return checks

    def _get_servicetypes(self):
        service_types = set()
        for mp in self.metric_profiles:
            for service in mp["services"]:
                service_types.add(service["service"])

        return service_types

    def generate_entities(self, namespace="default"):
        entities = list()
        topo_entities = [
            item for item in self.topology if
            item["service"] in self.servicetypes
        ]
        for item in topo_entities:
            types = list()
            labels = {"hostname": item["hostname"]}

            if "info_URL" in item["tags"]:
                labels.update({"info_url": item["tags"]["info_URL"]})
                o = urlparse(item["tags"]["info_URL"])
                port = o.port

                if item["service"] in self.servicetypes_with_SSL:
                    if o.scheme == "https":
                        ssl = "-S --sni"
                    else:
                        ssl = ""

                    labels.update({"ssl": ssl})

                    path = o.path
                    if not o.path:
                        path = "/"

                    labels.update({"path": path})

                if item["service"] in self.servicetypes_with_port:
                    if port:
                        port = str(port)

                    else:
                        if o.scheme == "https":
                            port = "443"

                        else:
                            port = "80"

                    labels.update({"port": port})

                if item["service"] in [
                    "org.openstack.nova", "org.openstack.swift"
                ]:
                    if port:
                        labels.update({"os_keystone_port": str(port)})

                    labels.update({"os_keystone_host": o.hostname})

            if "info_service_endpoint_URL" in item["tags"]:
                url = item["tags"]["info_service_endpoint_URL"]
                if "," in item["tags"]["info_service_endpoint_URL"]:
                    url = url.split(",")[0].strip()

                labels.update({"info_service_endpoint_url": url})

            else:
                if item["service"] in self.servicetypes_with_endpointURL:
                    labels.update(
                        {"info_service_endpoint_url": item["tags"]["info_URL"]}
                    )

            if item["service"] == "Top-BDII":
                labels.update({"bdii_dn": "Mds-Vo-Name=local,O=Grid"})
                labels.update({"bdii_type": "bdii_top"})
                labels.update(
                    {"glue2_bdii_dn": "GLUE2DomainID=%s,o=glue" % item["group"]}
                )

            if item["service"] == "Site-BDII":
                labels.update(
                    {"bdii_dn": "Mds-Vo-Name=%s,O=Grid" % item["group"]}
                )
                labels.update({"bdii_type": "bdii_site"})
                labels.update(
                    {"glue2_bdii_dn": "GLUE2DomainID=%s,o=glue" % item["group"]}
                )

            if "info_HOSTDN" in item["tags"]:
                labels.update({"info_hostdn": item["tags"]["info_HOSTDN"]})

            types.append(item["service"])
            for metric in self.metrics4servicetypes[item["service"]]:
                key = metric.lower().replace(".", "_").replace("-", "_")
                if key not in labels:
                    labels.update({key.lower(): metric})

                if metric == "generic.ssh.connect" and "port" not in labels:
                    labels.update({"port": "22"})

            for tag, value in item["tags"].items():
                if tag.startswith("info_ext_"):
                    if tag.lower() == "info_ext_port":
                        labels.update({"port": value})

                    else:
                        if self._is_extension_present_in_all_endpoints(
                            services=[item["service"]], extension=tag
                        ):
                            labels.update({tag[9:].lower(): value})
                        else:
                            metrics = list()
                            for metric in self.metrics:
                                for name, configuration in metric.items():
                                    if name in self.metrics4servicetypes[
                                        item["service"]
                                    ]:
                                        metrics.append(metric)

                            for metric in metrics:
                                for name, configuration in metric.items():
                                    if tag[9:] in configuration["attribute"]:
                                        labels.update({
                                            "{}__{}".format(
                                                configuration["attribute"][
                                                    tag[9:]
                                                ].lstrip("-").lstrip(
                                                    "-"
                                                ).replace("-", "_"),
                                                tag[9:].lower()
                                            ): "{} {}".format(
                                                configuration["attribute"][
                                                    tag[9:]
                                                ], value
                                            )
                                        })

            labels.update({"service": item["service"], "site": item["group"]})

            site_entries = [
                i for i in self.topology if i["group"] == item["group"]
            ]
            site_bdii_entries = [
                i for i in site_entries if i["service"] == "Site-BDII"
            ]
            if len(site_bdii_entries) > 0:
                labels.update({"site_bdii": site_bdii_entries[0]["hostname"]})

            entities.append({
                "entity_class": "proxy",
                "metadata": {
                    "name": "{}__{}".format(
                        item["service"], item["hostname"]
                    ),
                    "namespace": namespace,
                    "labels": labels
                },
                "subscriptions": types
            })

        return entities

    def generate_subscriptions(self):
        return self.servicetypes
