import json
import logging

import requests
from argo_scg.exceptions import SensuException


class Sensu:
    def __init__(self, url, token):
        self.url = url
        self.token = token
        self.logger = logging.getLogger("argo-scg.sensu")

    def _get_namespaces(self):
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces",
            headers={
                "Authorization": f"Key {self.token}",
                "Content-Type": "application/json"
            }
        )

        if not response.ok:
            msg = f"Namespaces fetch error: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.error(msg)
            self.logger.warning("Unable to proceed")
            raise SensuException(msg)

        else:
            return [namespace["name"] for namespace in response.json()]

    def handle_namespaces(self, tenants):
        for tenant in tenants:
            namespace = tenant

            if namespace not in self._get_namespaces():
                response = requests.put(
                    f"{self.url}/api/core/v2/namespaces/{namespace}",
                    headers={
                        "Authorization": f"Key {self.token}",
                        "Content-Type": "application/json"
                    },
                    data=json.dumps({"name": namespace})
                )

                if not response.ok:
                    msg = f"Namespace {namespace} create error: " \
                          f"{response.status_code} {response.reason}"

                    try:
                        msg = f"{msg}: {response.json()['message']}"

                    except (ValueError, TypeError, KeyError):
                        pass

                    self.logger.error(msg)
                    self.logger.warning("Unable to proceed")
                    raise SensuException(msg)

                else:
                    self.logger.info(f"Namespace {namespace} created")

    def _get_checks(self, namespace):
        response = requests.get(
            "{}/api/core/v2/namespaces/{}/checks".format(self.url, namespace),
            headers={
                "Authorization": "Key {}".format(self.token),
                "Content-Type": "application/json"
            }
        )

        if not response.ok:
            msg = f"{namespace}: Checks fetch error: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.error(msg)
            raise SensuException(msg)

        else:
            return response.json()

    def _get_events(self, namespace):
        response = requests.get(
            "{}/api/core/v2/namespaces/{}/events".format(
                self.url, namespace
            ),
            headers={
                "Authorization": "Key {}".format(self.token),
                "Content-Type": "application/json"
            }
        )

        if not response.ok:
            msg = f"{namespace}: Events fetch error: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.warning(msg)
            raise SensuException(msg)

        else:
            return response.json()

    def _delete_checks(self, checks, namespace):
        for check in checks:
            response = requests.delete(
                "{}/api/core/v2/namespaces/{}/checks/{}".format(
                    self.url, namespace, check
                ),
                headers={"Authorization": "Key {}".format(self.token)}
            )

            if not response.ok:
                msg = f"{namespace}: Check {check} not removed: " \
                      f"{response.status_code} {response.reason}"

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, TypeError, KeyError):
                    pass

                self.logger.warning(msg)
                continue

            else:
                self.logger.info(f"{namespace}: Check {check} removed")

    def _delete_events(self, events, namespace):
        for entity, checks in events.items():
            for check in checks:
                response = requests.delete(
                    f"{self.url}/api/core/v2/namespaces/{namespace}/events/"
                    f"{entity}/{check}",
                    headers={
                        "Authorization": f"Key {self.token}"
                    }

                )

                if not response.ok:
                    msg = f"{namespace}: Event " \
                          f"{entity}/{check} not removed: " \
                          f"{response.status_code} {response.reason}"

                    try:
                        msg = f"{msg}: {response.json()['message']}"

                    except (ValueError, TypeError, KeyError):
                        pass

                    self.logger.warning(msg)

                else:
                    self.logger.info(
                        f"{namespace}: Event {entity}/{check} removed"
                    )

    @staticmethod
    def _compare_checks(check1, check2):
        def proxy_equality(c1, c2):
            proxy_equal = False
            key1 = "proxy_requests"
            key2 = "entity_attributes"
            condition1 = key1 in c1 and key1 in c2
            condition2 = key1 not in c1 and key1 not in c2
            condition3 = False
            if condition1:
                condition3 = c1[key1][key2] == c2[key1][key2]
            if (condition1 and condition3) or condition2:
                proxy_equal = True

            return proxy_equal

        def annotations_equality(c1, c2):
            annotations_equal = False
            key1 = "metadata"
            key2 = "annotations"
            condition1 = key2 in c1[key1] and key2 in c2[key1]
            condition2 = key2 not in c1[key1] and key2 not in c2[key1]

            condition3 = False
            if condition1:
                condition3 = c1[key1][key2] == c2[key1][key2]

            if (condition1 and condition3) or condition2:
                annotations_equal = True

            return annotations_equal

        equal = False
        if check1["command"] == check2["command"] and \
                sorted(check1["subscriptions"]) == \
                sorted(check2["subscriptions"]) and \
                sorted(check1["handlers"]) == sorted(check2["handlers"]) and \
                proxy_equality(check1, check2) and \
                check1["interval"] == check2["interval"] and \
                check1["timeout"] == check2["timeout"] and \
                check1["publish"] == check2["publish"] and \
                check1["metadata"]["name"] == check2["metadata"]["name"] and \
                check1["metadata"]["namespace"] == \
                check2["metadata"]["namespace"] and \
                check1["round_robin"] == check2["round_robin"] and \
                check1["pipelines"] == check2["pipelines"] and \
                annotations_equality(check1, check2):
            equal = True

        return equal

    def _get_proxy_entities(self, namespace):
        response = requests.get(
            "{}/api/core/v2/namespaces/{}/entities".format(self.url, namespace),
            headers={
                "Authorization": "Key {}".format(self.token),
                "Content-Type": "application/json"
            }
        )

        if not response.ok:
            msg = f"{namespace}: Entity fetch error: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.error(msg)
            raise SensuException(msg)

        else:
            data = response.json()
            return [
                entity for entity in data if entity["entity_class"] == "proxy"
            ]

    def _delete_entities(self, entities, namespace):
        for entity in entities:
            response = requests.delete(
                "{}/api/core/v2/namespaces/{}/entities/{}".format(
                    self.url, namespace, entity
                ),
                headers={"Authorization": f"Key {self.token}"}
            )

            if not response.ok:
                msg = f"{namespace}: Entity {entity} not removed: " \
                      f"{response.status_code} {response.reason}"

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, TypeError, KeyError):
                    pass

                self.logger.warning(msg)

            else:
                self.logger.info(f"{namespace}: Entity {entity} removed")

    @staticmethod
    def _compare_entities(entity1, entity2):
        equal = False

        try:
            entity2["metadata"]["labels"].pop("sensu.io/managed_by")

        except KeyError:
            pass

        if entity1["metadata"]["name"] == entity2["metadata"]["name"] and \
                entity1["metadata"]["namespace"] == \
                entity2["metadata"]["namespace"] and \
                entity1["metadata"]["labels"] == \
                entity2["metadata"]["labels"] and \
                entity1["subscriptions"] == \
                entity2["subscriptions"]:
            equal = True

        return equal

    def handle_checks(self, checks, namespace="default"):
        existing_checks = self._get_checks(namespace=namespace)

        for check in checks:
            existing_check = [
                ec for ec in existing_checks if
                ec["metadata"]["name"] == check["metadata"]["name"]
            ]

            if len(existing_check) == 0:
                word = "created"

            else:
                word = "updated"

            if len(existing_check) == 0 or \
                    not self._compare_checks(check, existing_check[0]):
                response = requests.put(
                    "{}/api/core/v2/namespaces/{}/checks/{}".format(
                        self.url, namespace, check["metadata"]["name"]
                    ),
                    headers={
                        "Authorization": "Key {}".format(self.token),
                        "Content-Type": "application/json"
                    },
                    data=json.dumps(check)
                )

                if not response.ok:
                    msg = f"{namespace}: " \
                          f"Check {check['metadata']['name']} not {word}: " \
                          f"{response.status_code} {response.reason}"
                    try:
                        msg = f"{msg}: {response.json()['message']}"

                    except (ValueError, TypeError, KeyError):
                        pass

                    self.logger.warning(msg)

                else:
                    self.logger.info(
                        f"{namespace}: Check {check['metadata']['name']} {word}"
                    )

        updated_existing_checks = self._get_checks(namespace=namespace)
        checks_tobedeleted = sorted(list(set(
            [check["metadata"]["name"] for check in updated_existing_checks]
        ).difference(set(
            [check["metadata"]["name"] for check in checks]
        ))))

        if len(checks_tobedeleted) > 0:
            self._delete_checks(checks=checks_tobedeleted, namespace=namespace)

            after_delete_checks = [
                check["metadata"]["name"] for check in self._get_checks(
                    namespace=namespace
                )
            ]
            try:
                existing_events = self._get_events(namespace=namespace)
                events_tobedeleted = dict()
                for event in existing_events:
                    check = event["check"]["metadata"]["name"]
                    if check not in after_delete_checks:
                        entity = event["entity"]["metadata"]["name"]
                        if entity not in events_tobedeleted.keys():
                            events_tobedeleted.update({entity: [check]})

                        else:
                            entity_checks = events_tobedeleted[entity]
                            entity_checks.append(check)
                            events_tobedeleted.update({entity: entity_checks})

                self._delete_events(
                    events=events_tobedeleted, namespace=namespace
                )

            except SensuException:
                pass

    def handle_proxy_entities(self, entities, namespace="default"):
        existing_entities = self._get_proxy_entities(namespace=namespace)
        for entity in entities:
            existing_entity = [
                ent for ent in existing_entities if
                ent["metadata"]["name"] == entity["metadata"]["name"]
            ]

            if len(existing_entity) == 0:
                word = "created"

            else:
                word = "updated"

            if len(existing_entity) == 0 or \
                    not self._compare_entities(entity, existing_entity[0]):
                response = requests.put(
                    "{}/api/core/v2/namespaces/{}/entities/{}".format(
                        self.url, namespace, entity["metadata"]["name"]
                    ),
                    data=json.dumps(entity),
                    headers={
                        "Authorization": "Key {}".format(self.token),
                        "Content-Type": "application/json"
                    }
                )

                if not response.ok:
                    msg = f"{namespace}: Proxy entity " \
                          f"{entity['metadata']['name']} not {word}: " \
                          f"{response.status_code} {response.reason}"

                    try:
                        msg = f"{msg}: {response.json()['message']}"

                    except (ValueError, TypeError, KeyError):
                        pass

                    self.logger.warning(msg)

                else:
                    self.logger.info(
                        f"{namespace}: Entity {entity['metadata']['name']} "
                        f"{word}"
                    )

        entities_tobedeleted = list(set(
            [entity["metadata"]["name"] for entity in existing_entities]
        ).difference(set(
            [entity["metadata"]["name"] for entity in entities]
        )))

        if len(entities_tobedeleted):
            self._delete_entities(
                entities=entities_tobedeleted, namespace=namespace
            )

    def add_subscriptions_to_agents(self, subscriptions, namespace="default"):
        response = requests.get(
            "{}/api/core/v2/namespaces/{}/entities".format(self.url, namespace),
            headers={
                "Authorization": "Key {}".format(self.token),
                "Content-Type": "application/json"
            }
        )

        if not response.ok:
            msg = f"{namespace}: Entity fetch error: " \
                  f"{response.status_code} {response.reason}"
            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, TypeError, KeyError):
                pass

            self.logger.error(msg)
            self.logger.warning(
                f"{namespace}: Agents' subscriptions not updated"
            )

        else:
            entities = response.json()
            agents = [
                entity for entity in entities
                if entity["entity_class"] == "agent"
            ]

            for agent in agents:
                new_subscriptions = agent["subscriptions"].copy()
                for subscription in subscriptions:
                    if subscription not in agent["subscriptions"]:
                        new_subscriptions.append(subscription)

                if not set(new_subscriptions) == set(agent["subscriptions"]):
                    response = requests.patch(
                        "{}/api/core/v2/namespaces/{}/entities/{}".format(
                            self.url, namespace, agent["metadata"]["name"]
                        ),
                        data=json.dumps({"subscriptions": new_subscriptions}),
                        headers={
                            "Authorization": "Key {}".format(self.token),
                            "Content-Type": "application/merge-patch+json"
                        }
                    )

                    if not response.ok:
                        msg = f"{namespace}: {agent['metadata']['name']} " \
                              f"subscriptions not updated: " \
                              f"{response.status_code} {response.reason}"
                        try:
                            msg = f"{msg}: {response.json()['message']}"

                        except (ValueError, TypeError, KeyError):
                            pass

                        self.logger.error(msg)

                    else:
                        self.logger.info(
                            f"{namespace}: {agent['metadata']['name']} "
                            f"subscriptions updated"
                        )

    def _get_handlers(self, namespace):
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces/{namespace}/handlers",
            headers={
                "Authorization": f"Key {self.token}",
                "Content-Type": "application/json"
            }
        )

        if not response.ok:
            msg = f"{namespace}: Handlers fetch error: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.error(msg)
            raise SensuException(msg)

        else:
            return response.json()

    def _handle_handler(self, name, data, namespace="default"):
        existing_handler = [
            handler for handler in self._get_handlers(namespace=namespace)
            if handler["metadata"]["name"] == name
        ]

        print_name = name if name.endswith("handler") else f"{name}-handler"
        if len(existing_handler) == 0:
            response = requests.post(
                f"{self.url}/api/core/v2/namespaces/{namespace}/handlers",
                headers={
                    "Authorization": f"Key {self.token}",
                    "Content-Type": "application/json"
                },
                data=json.dumps(data)
            )

            if not response.ok:
                msg = f"{namespace}: {print_name} create error: " \
                      f"{response.status_code} {response.reason}"

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, KeyError, TypeError):
                    pass

                self.logger.error(msg)
                raise SensuException(msg)

            else:
                self.logger.info(f"{namespace}: {print_name} created")

        else:
            if existing_handler[0]["command"] != data["command"]:
                response = requests.patch(
                    f"{self.url}/api/core/v2/namespaces/{namespace}/handlers/"
                    f"{name}",
                    headers={
                        "Authorization": f"Key {self.token}",
                        "Content-Type": "application/merge-patch+json"
                    },
                    data=json.dumps({"command": data["command"]})
                )

                if not response.ok:
                    msg = f"{namespace}: {print_name} not updated: " \
                          f"{response.status_code} {response.reason}"

                    try:
                        msg = f"{msg}: {response.json()['message']}"

                    except (ValueError, KeyError, TypeError):
                        pass

                    self.logger.warning(msg)

                else:
                    self.logger.info(f"{namespace}: {print_name} updated")

    def handle_publisher_handler(self, namespace="default"):
        self._handle_handler(
            name="publisher-handler",
            data={
                "metadata": {
                    "name": "publisher-handler",
                    "namespace": namespace
                },
                "type": "pipe",
                "command": "/bin/sensu2publisher.py"
            },
            namespace=namespace
        )

    def handle_slack_handler(self, secrets_file, namespace="default"):
        self._handle_handler(
            name="slack",
            data={
                "metadata": {
                    "name": "slack",
                    "namespace": namespace
                },
                "type": "pipe",
                "command": f"source {secrets_file} ; "
                           f"export $(cut -d= -f1 {secrets_file}) ; "
                           f"sensu-slack-handler --channel '#monitoring'",
                "runtime_assets": ["sensu-slack-handler"]
            },
            namespace=namespace
        )

    def _get_filters(self, namespace):
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces/{namespace}/filters",
            headers={
                "Authorization": f"Key {self.token}"
            }
        )

        if not response.ok:
            msg = f"{namespace}: Filters fetch error: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.error(msg)
            raise SensuException(msg)

        else:
            return response.json()

    def _add_filter(self, name, expressions, namespace="default"):
        filters = self._get_filters(namespace=namespace)
        filters_names = [f["metadata"]["name"] for f in filters]

        response = None
        added = False
        if name not in filters_names:
            added = True
            response = requests.post(
                f"{self.url}/api/core/v2/namespaces/{namespace}/filters",
                headers={
                    "Authorization": f"Key {self.token}",
                    "Content-Type": "application/json"
                },
                data=json.dumps({
                    "metadata": {
                        "name": name,
                        "namespace": namespace
                    },
                    "action": "allow",
                    "expressions": expressions
                })
            )

        else:
            the_filter = [
                f for f in filters if f["metadata"]["name"] == name
            ][0]
            if the_filter["expressions"] != expressions:
                response = requests.patch(
                    f"{self.url}/api/core/v2/namespaces/{namespace}/"
                    f"filters/{name}",
                    headers={
                        "Authorization": f"Key {self.token}",
                        "Content-Type": "application/merge-patch+json"
                    },
                    data=json.dumps({"expressions": expressions})
                )

        if response:
            if not response.ok:
                if added:
                    intra_msg = f"{name} filter create error"

                else:
                    intra_msg = f"{name} filter not updated"

                msg = f"{namespace}: {intra_msg}: " \
                      f"{response.status_code} {response.reason}"

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, KeyError, TypeError):
                    pass

                if added:
                    self.logger.error(msg)
                    raise SensuException(msg)

                else:
                    self.logger.warning(msg)

            else:
                if added:
                    operation = "created"

                else:
                    operation = "updated"
                self.logger.info(
                    f"{namespace}: {name} filter {operation}"
                )

    def add_daily_filter(self, namespace="default"):
        expressions = [
            "((event.check.occurrences == 1 && event.check.status == 0 "
            "&& event.check.occurrences_watermark >= "
            "Number(event.check.annotations.attempts)) || "
            "(event.check.occurrences == "
            "Number(event.check.annotations.attempts) "
            "&& event.check.status != 0)) || "
            "event.check.occurrences % (86400 / event.check.interval) == 0"
        ]

        self._add_filter(
            name="daily", expressions=expressions, namespace=namespace
        )

    def add_hard_state_filter(self, namespace="default"):
        expressions = [
            "((event.check.status == 0) || (event.check.occurrences >= "
            "Number(event.check.annotations.attempts) "
            "&& event.check.status != 0))"
        ]

        self._add_filter(
            name="hard-state", expressions=expressions, namespace=namespace
        )

    def _get_pipelines(self, namespace):
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces/{namespace}/pipelines",
            headers={
                "Authorization": f"Key {self.token}"
            }
        )

        if not response.ok:
            msg = f"{namespace}: Pipelines fetch error: " \
                  f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.error(msg)
            raise SensuException(msg)

        else:
            return response.json()

    def _add_pipeline(self, name, workflows, namespace="default"):
        pipelines = [
            f["metadata"]["name"] for f in self._get_pipelines(
                namespace=namespace
            )
        ]

        if name not in pipelines:
            response = requests.post(
                f"{self.url}/api/core/v2/namespaces/{namespace}/pipelines",
                headers={
                    "Authorization": f"Key {self.token}",
                    "Content-Type": "application/json"
                },
                data=json.dumps({
                    "metadata": {
                        "name": name,
                        "namespace": namespace
                    },
                    "workflows": workflows
                })
            )

            if not response.ok:
                msg = f"{namespace}: {name} pipeline create error: " \
                      f"{response.status_code} {response.reason}"

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, KeyError, TypeError):
                    pass

                self.logger.error(msg)
                raise SensuException(msg)

            else:
                self.logger.info(f"{namespace}: {name} pipeline created")

    def add_reduce_alerts_pipeline(self, namespace="default"):
        workflows = [
            {
                "name": "slack_alerts",
                "filters": [
                    {
                        "name": "is_incident",
                        "type": "EventFilter",
                        "api_version": "core/v2"
                    },
                    {
                        "name": "daily",
                        "type": "EventFilter",
                        "api_version": "core/v2"
                    }
                ],
                "handler": {
                    "name": "slack",
                    "type": "Handler",
                    "api_version": "core/v2"
                }
            }
        ]

        self._add_pipeline(
            name="reduce_alerts", workflows=workflows, namespace=namespace
        )

    def add_hard_state_pipeline(self, namespace="default"):
        workflows = [
            {
                "name": "mimic_hard_state",
                "filters": [
                    {
                        "name": "hard-state",
                        "type": "EventFilter",
                        "api_version": "core/v2"
                    }
                ],
                "handler": {
                    "name": "publisher-handler",
                    "type": "Handler",
                    "api_version": "core/v2"
                }
            }
        ]

        self._add_pipeline(
            name="hard_state", workflows=workflows, namespace=namespace
        )


class MetricOutput:
    def __init__(self, data):
        self.data = data

    def get_service(self):
        return self.data["entity"]["metadata"]["labels"]["service"]

    def get_hostname(self):
        return self.data["entity"]["metadata"]["labels"]["hostname"]

    def get_metric_name(self):
        return self.data["check"]["metadata"]["name"]

    def get_status(self):
        status_code = self.data["check"]["status"]
        if status_code == 0:
            status = "OK"

        elif status_code == 1:
            status = "WARNING"

        elif status_code == 2:
            status = "CRITICAL"

        else:
            status = "UNKNOWN"

        return status

    def _get_output(self):
        return self.data["check"]["output"]

    def _get_output_lines(self):
        return self._get_output().split("\n")

    def _get_output_firstline(self):
        return self._get_output_lines()[0]

    def _get_output_firstline_split(self):
        return self._get_output_firstline().split("|")

    def get_summary(self):
        return self._get_output_firstline_split()[0].strip()

    def get_perfdata(self):
        firstline = self._get_output_firstline_split()
        perfdata = ""
        if len(firstline) > 1:
            perfdata = firstline[1].strip()

        all_lines = self._get_output_lines()

        if len(all_lines) > 1:
            other_lines = "\n".join(all_lines[1:])
            perfdata2 = other_lines.split("|")

            if len(perfdata2) > 1:
                perfdata2 = perfdata2[1].strip().replace("\n", " ")

                perfdata = f"{perfdata} {perfdata2}"

        return perfdata

    def get_site(self):
        return self.data["entity"]["metadata"]["labels"]["site"]

    def get_namespace(self):
        return self.data["check"]["metadata"]["namespace"]
