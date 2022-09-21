import logging
import os
from urllib.parse import urlparse

from argo_scg.exceptions import GeneratorException

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


class ConfigurationGenerator:
    def __init__(
            self, metrics, metric_profiles, topology, profiles,
            attributes, secrets_file, tenant
    ):
        self.logger = logging.getLogger("argo-scg.generator")
        self.tenant = tenant
        self.metric_profiles = [
            p for p in metric_profiles if p["name"] in profiles
        ]
        metrics_set = set()
        for profile in self.metric_profiles:
            for service in profile["services"]:
                for metric in service["metrics"]:
                    metrics_set.add(metric)

        self.global_attributes = self._read_global_attributes(attributes)
        self.servicetypes = self._get_servicetypes()

        metrics_list = list()
        internal_metrics = list()
        metrics_with_endpoint_url = list()
        metrics_with_ports = list()
        metrics_with_ssl = list()
        metrics_with_url = dict()
        for metric in metrics:
            for key, value in metric.items():
                if key in metrics_set:
                    metrics_list.append(metric)

                    if "PORT" in value["attribute"]:
                        metrics_with_ports.append(key)

                    if "SSL" in value["attribute"]:
                        metrics_with_ssl.append(key)

                    if "internal" in value["tags"]:
                        internal_metrics.append(key)

                    for attribute, attr_val in value["attribute"].items():
                        if attribute == "URL":
                            metrics_with_endpoint_url.append(key)

                        if attribute.endswith("_URL") and not (
                                attribute.endswith("GOCDB_SERVICE_URL")
                        ):
                            metrics_with_url.update({key: attribute})

        self.metrics = metrics_list
        self.internal_metrics = internal_metrics
        self.topology = topology
        self.secrets = secrets_file

        self.metric_parameter_overrides = self._read_metric_parameter_overrides(
            attributes
        )
        self.metrics_attr_override = dict()
        self.host_attribute_overrides = self._read_host_attribute_overrides(
            attributes
        )
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

        self.servicetypes_with_url = dict()
        for metric, attribute in metrics_with_url.items():
            sts = self.servicetypes4metrics[metric]
            for st in sts:
                if st in self.servicetypes_with_url:
                    att = self.servicetypes_with_url[st]
                    att.append(attribute)
                    self.servicetypes_with_url.update({st: list(set(att))})

                else:
                    self.servicetypes_with_url.update({st: [attribute]})

    @staticmethod
    def _read_global_attributes(input_attrs):
        attrs = dict()

        for file, keys in input_attrs.items():
            for item in keys["global_attributes"]:
                attrs.update({item["attribute"]: item["value"]})

        return attrs

    def _read_metric_parameter_overrides(self, input_attrs):
        metric_parameter_overrides = dict()

        for file, keys in input_attrs.items():
            for item in keys["metric_parameters"]:
                metric_parameter_overrides.update({
                    item["metric"]: {
                        "hostname": item["hostname"],
                        "label": self._create_metric_parameter_label(
                            item["metric"], item["parameter"]
                        ),
                        "value": item["value"]
                    }
                })

        return metric_parameter_overrides

    def _read_host_attribute_overrides(self, input_attrs):
        host_attribute_overrides = list()

        for files, keys in input_attrs.items():
            for item in keys["host_attributes"]:
                host_attribute_overrides.append({
                    "hostname": item["hostname"],
                    "attribute": item["attribute"],
                    "label": self._create_label(item["attribute"]),
                    "value": item["value"].strip("$")
                })
                for metric in self._get_metrics4attribute(item["attribute"]):
                    if metric in self.metrics_attr_override:
                        attrs = self.metrics_attr_override[metric]
                        attrs.add(item["attribute"])
                        self.metrics_attr_override.update({metric: attrs})

                    else:
                        self.metrics_attr_override.update({
                            metric: {item["attribute"]}
                        })

        return host_attribute_overrides

    @staticmethod
    def _create_label(item):
        return item.lower().replace(".", "_").replace("-", "_")

    @staticmethod
    def _get_single_endpoint_url(url):
        if "," in url:
            url = url.split(",")[0].strip()

        return url

    @staticmethod
    def _create_attribute_env(item):
        return item.upper().replace(".", "_").replace("-", "_")

    def _get_metrics4attribute(self, attribute):
        metrics_with_attribute = list()
        for metric in self.metrics:
            for name, config in metric.items():
                if attribute in config["attribute"]:
                    metrics_with_attribute.append(name)

        return metrics_with_attribute

    def _create_metric_parameter_label(self, metric, parameter):
        return f"{self._create_label(metric)}_{parameter.strip('-').strip('-')}"

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
        overridden_attributes = [
            item["attribute"] for item in self.host_attribute_overrides
        ]
        for key, value in attrs.items():
            if key in self.global_attributes:
                key = self.global_attributes[key]

            elif key.endswith("_TOKEN") or key.endswith("_LOGIN") or \
                    key.endswith("_SALT") or key.endswith("_ID") or \
                    key.endswith("_PASSWORD") or key.endswith("_USER") or \
                    key.endswith("_SECRET") or key.endswith("_USERNAME") or \
                    key.endswith("_CREDENTIALS"):
                if key in overridden_attributes:
                    key = "{{ .labels.%s }}" % self._create_label(key)

                else:
                    if "." in key:
                        key = key.upper().replace(".", "_")

                    key = f"${key}"

                issecret = True

            else:
                if key == "NAGIOS_HOST_CERT":
                    if "ROBOT_CERT" in self.global_attributes:
                        key = self.global_attributes["ROBOT_CERT"]
                    else:
                        key = hardcoded_attributes[key]

                elif key == "NAGIOS_HOST_KEY":
                    if "ROBOT_KEY" in self.global_attributes:
                        key = self.global_attributes["ROBOT_KEY"]

                    else:
                        key = hardcoded_attributes[key]

                elif key in ["KEYSTORE", "TRUSTSTORE"]:
                    key = hardcoded_attributes[key]

                elif key == "TOP_BDII":
                    if "BDII_HOST" in self.global_attributes:
                        key = self.global_attributes["BDII_HOST"]
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

                elif key == "URL":
                    key = "{{ .labels.info_service_endpoint_url }}"

                elif key == "SITENAME":
                    key = "{{ .labels.site }}"

                elif key in self.extensions:
                    if self._is_extension_present_in_all_endpoints(
                        services=self.servicetypes4metrics[metric],
                        extension=f"info_ext_{key}"
                    ) or key.endswith("_URL"):
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
                try:
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
                        if name in self.metric_parameter_overrides:
                            value = "{{ .labels.%s | default '%s' }}" % (
                                self.metric_parameter_overrides[name]["label"],
                                value
                            )

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
                        command = f"source {self.secrets} ; " \
                                  f"export $(cut -d= -f1 {self.secrets}) ; " \
                                  f"{command}"

                    check = {
                        "command": command.strip(),
                        "subscriptions": self.servicetypes4metrics[name],
                        "handlers": [],
                        "interval":
                            int(configuration["config"]["interval"]) * 60,
                        "timeout": 900,
                        "publish": True,
                        "metadata": {
                            "name": name,
                            "namespace": namespace,
                            "annotations": {
                                "attempts":
                                    configuration["config"]["maxCheckAttempts"]
                            }
                        },
                        "round_robin": False
                    }

                    if publish and "NOPUBLISH" not in configuration["flags"]:
                        check.update({
                            "pipelines": [
                                {
                                    "name": "hard_state",
                                    "type": "Pipeline",
                                    "api_version": "core/v2"
                                }
                            ]
                        })

                    elif not publish or "internal" in configuration["tags"]:
                        check.update({
                            "pipelines": [
                                {
                                    "name": "reduce_alerts",
                                    "type": "Pipeline",
                                    "api_version": "core/v2"
                                }
                            ]
                        })

                    else:
                        check.update({"pipelines": []})

                    if namespace != "default" and \
                            "internal" not in configuration["tags"]:
                        check.update({
                            "proxy_requests": {
                                "entity_attributes": [
                                    "entity.entity_class == 'proxy'",
                                    "entity.labels.{} == '{}'".format(
                                        name.lower().replace(".", "_").replace(
                                            "-", "_"
                                        ), name
                                    )
                                ]
                            }
                        })

                    checks.append(check)

                except KeyError as e:
                    self.logger.warning(
                        f"{self.tenant}: Skipping check {name}: "
                        f"Missing key {str(e)}"
                    )
                    continue

        return checks

    def _get_servicetypes(self):
        service_types = set()
        for mp in self.metric_profiles:
            for service in mp["services"]:
                service_types.add(service["service"])

        return service_types

    def generate_entities(self, namespace="default"):
        try:
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
                        labels.update({
                            "os_keystone_url": item["tags"]["info_URL"]
                        })

                if "info_service_endpoint_URL" in item["tags"]:
                    labels.update({
                        "info_service_endpoint_url":
                            self._get_single_endpoint_url(
                                item["tags"]["info_service_endpoint_URL"]
                            )
                    })

                else:
                    if item["service"] in self.servicetypes_with_endpointURL:
                        labels.update({
                            "info_service_endpoint_url":
                                item["tags"]["info_URL"]
                        })

                if item["service"] in self.servicetypes_with_url:
                    for attr in self.servicetypes_with_url[item["service"]]:
                        if "info_service_endpoint_URL" in item["tags"]:
                            labels.update({
                                self._create_label(attr):
                                    self._get_single_endpoint_url(
                                        item["tags"][
                                            "info_service_endpoint_URL"
                                        ]
                                    )
                            })

                        elif "info_URL" in item["tags"]:
                            labels.update({
                                self._create_label(attr):
                                    item["tags"]["info_URL"]
                            })

                        else:
                            pass

                if item["service"] == "Top-BDII":
                    labels.update({"bdii_dn": "Mds-Vo-Name=local,O=Grid"})
                    labels.update({"bdii_type": "bdii_top"})
                    labels.update({
                        "glue2_bdii_dn":
                            "GLUE2DomainID=%s,o=glue" % item["group"]
                    })

                if item["service"] == "Site-BDII":
                    labels.update(
                        {"bdii_dn": "Mds-Vo-Name=%s,O=Grid" % item["group"]}
                    )
                    labels.update({"bdii_type": "bdii_site"})
                    labels.update({
                        "glue2_bdii_dn":
                            "GLUE2DomainID=%s,o=glue" % item["group"]
                    })

                if "info_HOSTDN" in item["tags"]:
                    labels.update({"info_hostdn": item["tags"]["info_HOSTDN"]})

                types.append(item["service"])
                for metric in self.metrics4servicetypes[item["service"]]:
                    if metric not in self.internal_metrics:
                        key = self._create_label(metric)

                        if key not in labels:
                            labels.update({key: metric})

                    if metric in self.metric_parameter_overrides and \
                            item["hostname"] in \
                            self.metric_parameter_overrides[metric]["hostname"]:
                        labels.update({
                            self.metric_parameter_overrides[metric]["label"]:
                                self.metric_parameter_overrides[metric]["value"]
                        })

                    if metric in self.metrics_attr_override:
                        overrides = [
                            entry for entry in self.host_attribute_overrides if
                            entry["hostname"] == item["hostname"]
                        ]
                        if len(overrides) > 0:
                            for override in overrides:
                                override_value = self._create_attribute_env(
                                    override["value"]
                                )
                                labels.update({
                                    override["label"]: f"${override_value}"
                                })

                        else:
                            for attribute in self.metrics_attr_override[metric]:
                                label = \
                                    f"${self._create_attribute_env(attribute)}"
                                labels.update({
                                    self._create_label(attribute): label
                                })

                    if metric == "generic.ssh.connect" and "port" not in labels:
                        labels.update({"port": "22"})

                for tag, value in item["tags"].items():
                    if tag.startswith("info_ext_"):
                        if tag.lower() == "info_ext_port":
                            labels.update({"port": value})

                        else:
                            if self._is_extension_present_in_all_endpoints(
                                services=[item["service"]], extension=tag
                            ) or tag.endswith("_URL"):
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
                                        if tag[9:] in \
                                                configuration["attribute"]:
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

                labels.update({
                    "service": item["service"], "site": item["group"]
                })

                site_entries = [
                    i for i in self.topology if i["group"] == item["group"]
                ]
                site_bdii_entries = [
                    i for i in site_entries if i["service"] == "Site-BDII"
                ]
                if len(site_bdii_entries) > 0:
                    labels.update({
                        "site_bdii": site_bdii_entries[0]["hostname"]
                    })

                entity_name = f"{item['service']}__{item['hostname']}"

                entities.append({
                    "entity_class": "proxy",
                    "metadata": {
                        "name": entity_name,
                        "namespace": namespace,
                        "labels": labels
                    },
                    "subscriptions": types
                })

            return entities

        except KeyError:
            self.logger.error(
                f"{self.tenant}: Skipping entities generation: faulty topology"
            )

            raise GeneratorException(
                f"{self.tenant}: Error generating entities: faulty topology"
            )

    def generate_subscriptions(self):
        return self.servicetypes
