# ARGO-SCG

## Description

ARGO-SCG is a component of ARGO monitoring engine that creates configuration for Sensu based on main sources of truth: ARGO Web-API for topology and metric profiles, and ARGO POEM for metric configurations.

## Installation

Component is supported on CentOS 7. RPM package and its dependencies are available in ARGO repositories, and it is simply installed using yum:

```
yum install -y argo-scg
```

## Configuration

Configuration is stored in file `/etc/argo-scg/scg.conf`. It consists of minimum of two sections: `[GENERAL]` section and at least one tenant section `[<tenant_name>]`. It is possible to have multiple tenant sections, one per each tenant you need to configure, each with tenant name set as section name. Tool will set up one namespace for each tenant in the configuration file.

### GENERAL section

```
[GENERAL]
sensu_url = https://sensu.backend.url
sensu_token = sensu-api-token
webapi_url = https://api.devel.argo.grnet.gr
```

* `sensu_url` - URL of the Sensu API,
* `sensu_token` - token for the Sensu API,
* `webapi_url` - URL of the ARGO Web-API.

### Tenant section

```
[tenant2]
poem_url = https://tenant2.poem.devel.argo.grnet.gr
poem_token = tenant2-poem-token
webapi_token = tenant2-webapi-token
attributes = /etc/argo-scg/attributes/attributes-tenant2.conf
metricprofiles = PROFILE1, PROFILE2
publish = true
publisher_queue = /var/spool/argo-nagios-ams-publisher/metrics
subscription = servicetype
agents_configuration = /path/to/config-file
```

* `poem_url` - POEM URL for the given tenant,
* `poem_token` - POEM token for the given tenant,
* `webapi_token` - Web-API token for the given tenant,
* `attributes` - path to the file containing the attributes for the given tenant,
* `metricprofile` - comma separated list of metric profiles for the given tenant,
* `publish` - flag that marks if the metrics results should be sent to publisher,
* `publisher_queue` - publisher queue; this entry can be left out if `publish` is set to `False`,
* `subscription` - type of subscription to use. There are three possible values:
  * `hostname` - hostname is used as a subscription (this is a default value),
  * `servicetype` - service types are used as subscription,
  * `hostname_with_id` - hostname with id is used as subscription,
* `agents_configuration` - path to configuration file for custom agents' subscriptions (optional).

#### Agents configuration

If `agents_configuration` setting exists, `scg-reload.py` tool will use only subscription set in the configuration file for the agents listed in the file. The configuration file must have the following form:

```
[AGENTS]
sensu-agent1.argo.eu = webdav, xrootd
sensu-agent2.argo.eu = ARC-CE
```

The configuration file has only one section, `[AGENTS]`. The options are simply agents' names, and values are service types which are to be tested on listed agents. All the other service types are going to be run on remaining agents, and they do not need to be listed explicitly.

## Tools

ARGO-SCG consists of several tools:

* `scg-reload.py` - configures Sensu for use with ARGO monitoring; details of configuration are described in section [Sensu backend operations](#sensu-backend-operations),
* `scg-ack.py` - tool used for acknowledgement of errors (creation of silencing entries),
* `scg-run-check` - tool for displaying commands run for the given entity and given check,
* `sensu-events` - formatted display of events,
* `sensu2publisher.py` - prepares Sensu event output data for ARGO AMS Publisher.

### `scg-reload.py`

`scg-reload.py` is simply invoked without any arguments if you want to run it with the default location of the configuration file `/etc/argo-scg/scg.conf` and for all the tenants defined in the configuration file. If you wish to override the configuration file location, it can be done using `-c` parameter with `scg-reload.py` script. 

```
# scg-reload.py 
INFO - Configuration file /etc/argo-scg/scg.conf read successfully
INFO - default: Metrics fetched successfully
INFO - default: Metric profiles fetched successfully
INFO - default: Metric overrides fetched successfully
INFO - default: Default ports fetched successfully
INFO - TENANT: Topology endpoints fetched successfully
INFO - TENANT: Metrics fetched successfully
INFO - TENANT: Metric profiles fetched successfully
INFO - TENANT: Metric overrides fetched successfully
INFO - TENANT: Default ports fetched successfully
INFO - Done
```

If you wish to run `scg-reload.py` script for a single tenant, you can do it by passing the tenant name using `-t` parameter.

```
# scg-reload.py -t TENANT
INFO - Configuration file /etc/argo-scg/scg.conf read successfully
INFO - TENANT: Topology endpoints fetched successfully
INFO - TENANT: Metrics fetched successfully
INFO - TENANT: Metric profiles fetched successfully
INFO - TENANT: Metric overrides fetched successfully
INFO - TENANT: Default ports fetched successfully
INFO - Done
```

Tool's logs are written to the file `/var/log/argo-scg/argo-scg.log`.

### `scg-ack.py`

This tool is used to acknowledge an event, and it does not return any output. The event will be silenced until it is resolved, after that it will send notifications normally without any user input. 

The tool takes two required arguments: check name `-c`, and entity name `-e`. By default, it uses the `default` namespace, you can override that with the namespace argument (`-n`). You can also override the configuration file it uses, by default it uses configuration file `/etc/argo-scg/scg.conf`.

```
# scg-ack.py -h
usage: Acknowledge an event so it does not send any more notifications
       [-h] -c CHECK -e ENTITY [-n NAMESPACE] [--conf CONF]

optional arguments:
  -h, --help            show this help message and exit
  -c CHECK, --check CHECK
                        check name
  -e ENTITY, --entity ENTITY
                        entity name
  -n NAMESPACE, --namespace NAMESPACE
                        namespace
  --conf CONF           configuration file

```

Example:

```
scg-ack.py -c argo.POEM-CERT-MON -e argo.poem__poem.argo.grnet.gr -n internal
```

### `scg-run-check`

This tool is used to check how the given check is called for given entity. You should supply entity name, check name and namespace as input arguments, and the tool will return how exactly the check is run for the given entity:

```
# scg-run-check -h
usage: Check how the probe is invoked for a given entity [-h] -e ENTITY -c
                                                         CHECK [-n NAMESPACE]
                                                         [--config CONFIG]
                                                         [--execute]

optional arguments:
  -h, --help            show this help message and exit
  -e ENTITY, --entity ENTITY
                        entity
  -c CHECK, --check CHECK
                        check
  -n NAMESPACE, --namespace NAMESPACE
                        namespace
  --config CONFIG       configuration file
  --execute             run the command
```

Example: 

```
# scg-run-check -e argo.webui__neanias.ui.argo.grnet.gr -c generic.certificate.validity -n internal
Executing command:
/usr/lib64/nagios/plugins/check_ssl_cert -H neanias.ui.argo.grnet.gr -t 60 -w 30 -c 0 -N --altnames --rootcert-dir /etc/grid-security/certificates --rootcert-file /etc/pki/tls/certs/ca-bundle.crt -C /etc/sensu/certs/hostcert.pem -K /etc/sensu/certs/hostkey.pem
```

It is also possible to include `--execute` flag, in which case the check will be run, and the result will be printed to terminal:

```
# scg-run-check -e argo.webui__neanias.ui.argo.grnet.gr -c generic.certificate.validity -n internal --execute
Executing command:
/usr/lib64/nagios/plugins/check_ssl_cert -H neanias.ui.argo.grnet.gr -t 60 -w 30 -c 0 -N --altnames --rootcert-dir /etc/grid-security/certificates --rootcert-file /etc/pki/tls/certs/ca-bundle.crt -C /etc/sensu/certs/hostcert.pem -K /etc/sensu/certs/hostkey.pem

SSL_CERT OK - x509 certificate '*.devel.argo.grnet.gr' (neanias.ui.argo.grnet.gr) from 'GEANT OV RSA CA 4' valid until May 26 23:59:59 2023 GMT (expires in 37 days)|days=37;30;0;;
```

### `sensu-events`

This tool is used to display events that have been run. It takes four optional arguments. The one that has a default value, `--namespace`, to denote for which namespace you wish events displayed (`default` namespace by default). The other three (`--status`, `--service` and `--agent`) are used for view filtering. If none of the arguments used for filtering is used, all the events are shown for the given namespace.

```
sensu-events -h
usage: Get event data [-h] [--namespace NAMESPACE] [--status STATUS]
                      [--service SERVICE_TYPE] [--agent]

optional arguments:
  -h, --help            show this help message and exit
  --namespace NAMESPACE
                        namespace
  --status STATUS       status to filter; must be integer code 0, 1, 2 or 3
  --service SERVICE_TYPE
                        service type to filter
  --agent               show only agent events
```

Example with all the events:

```
# sensu-events 
Host                    Metric                                   Status    Executed             Output
_________________________________________________________________________________________________________
sensu-devel.cro-ngi.hr  argo.AMSPublisher-Check                  OK        2023-04-18 11:21:06  OK - Worker metricsni4os published 5190 (threshold 10 in 180 minutes) / Worker metricseoscprobe published 17600 (threshold 10 in 180 minutes) / Worker metricseosccore published 1089 (threshold 10 in 180 minutes) / Worker metricseosc published 9100 (threshold 10 in 180 minutes)


sensu-devel.cro-ngi.hr  argo.poem-tools.check                    OK        2023-04-18 11:55:23  OK - The run finished successfully.


sensu-devel.cro-ngi.hr  argo.scg.check                           OK        2023-04-18 11:51:42  OK - Done


sensu-devel.cro-ngi.hr  keepalive                                OK        2023-04-18 13:32:41  Keepalive last sent from sensu-devel.cro-ngi.hr at 2023-04-18 13:32:41 +0200 CEST


sensu-devel.cro-ngi.hr  org.nagios.AmsDirSize                    OK        2023-04-18 13:03:26  OK - /var/spool/ams-publisher size: 680 KB


sensu-devel.cro-ngi.hr  org.nagios.DiskCheck-Local               OK        2023-04-18 13:11:57  DISK OK - free space: /dev 3900 MiB (100.00% inode=100%); /dev/shm 3909 MiB (99.98% inode=100%); /run 3543 MiB (90.61% inode=100%); /sys/fs/cgroup 3910 MiB (100.00% inode=100%); / 83534 MiB (81.61% inode=100%); /run/user/35838 782 MiB (100.00% inode=100%);


sensu-devel.cro-ngi.hr  srce.certificate.validity-sensu-backend  OK        2023-04-18 12:21:39  CERT LIFETIME OK - Certificate will expire in 341.06 days (Mar 24 11:51:28 2024 GMT)
```

The three arguments used for filtering are as follows:

* `--status` - used for filtering events by status. E.g. if you wish to see only events with `CRITICAL` status, you would call the tool as `sensu-events --status 2`.
* `--service` - used for filtering events by service type. E.g. if you wish to see only events run for service type `argo.mon`, you would call the tool as `sensu-events --service argo.mon`.
* `--agent` - the flag used for filtering events run for Sensu agent. E.g., if you want to display only events run for Sensu agent on the given tenant: `sensu-events --namespace INTERNAL --agent`.

All the arguments used for filtering can also be combined.

### `sensu2publisher.py`

`sensu2publisher.py` is not meant to be run by a user, it is run by Sensu as a handler. It takes Sensu check output as input, and then prepares data to be sent to the publisher.

## Sensu backend operations

### Namespaces

Multi-tenancy in Sensu is achieved by using namespaces - each tenant has its own namespace with isolated definitions of checks (metrics), entities (endpoints), events, handlers, filters, and pipelines. For each tenant defined in the configuration file, the `scg-reload.py` tool creates namespace if it does not exist. Also, if a namespace exists for which there is no tenant definition in the configuration file, that namespace is deleted.

### Entities

Entity represents anything that needs to be monitored. In ARGO monitoring service we differentiate between agent entities and proxy entities. Agent entities are the ones having Sensu agents installed. Agent entity registers with the Sensu backend service, sends keepalive messages and executes checks. 

Proxy entities, on the other hand, allow Sensu to monitor external resources on systems where you cannot install Sensu agent.

#### Agent entity

For each tenant, we create a single agent entity which runs the checks for the given tenant. Sensu is scheduling checks based on subscriptions: the subscriptions specified in the Sensu agent definition control which checks the agent will execute. In our system, such subscriptions are actually hostnames of proxy entities configured (and one additional, `internal`, for the internal checks which are executed directly on the agent). The list of subscriptions for agent are handled by `scg-reload.py` tool.

#### Proxy entity

Proxy entities are created based on the data defined in the topology. The name of the entity is defined as `<service>__<hostname>`.

All the other information from the topology needed by Sensu are stored in `labels` bucket. This includes minimally hostname, service, and site information, which are always defined in the topology. 

If there is `info_URL` entry defined in the topology, the tool will map its value to `info_url` entry in labels bucket. It will also try to get `PATH` and `PORT` from it, and add them to labels bucket. In case [generic.http.connect](https://poem.argo.grnet.gr/ui/public_metrictemplates/generic.http.connect) metric is to be executed for the given entity, tool will also check if `info_URL` schema is `https://` - if so, it will create `ssl` label with value `-S --sni`.

If there is `info_service_endpoint_URL` entry defined in the topology, the tool will create entry `endpoint_url` in labels bucket. If `endpoint_url` is required by the metric and is not defined in the topology, the tool will first look for attribute and metric parameter overrides for possible entries. If they are missing, the tool will log a warning message.

Topology entry `info_HOSTDN` is mapped to `info_hostdn` entry in the labels bucket if it exists.

Any defined extension in the topology (entry starting with `info_ext_`) will be mapped to label with `info_ext_` prefix removed, and all capital letters replaced with lower letters.

The tool is also checking if there are host attribute or metric parameter overrides which might affect the entity, and creates labels accordingly (both for entities and checks).

##### EGI-specific configuration

There are several EGI-specific service types which require special labels in the entity definition:

1. if service type is either `org.openstack.nova` or `org.openstack.swift`:
   - `os_keystone_port` with value of port only if there is port defined in `info_URL` entry in the topology,
   - `os_keystone_host` with value of hostname derived from `info_URL` entry in the topology,
   - `os_keystone_url` which maps `info_URL` entry from the topology;
2. if service type is `Top-BDII`:
   - `bdii_dn` with fixed value of `Mds-Vo-Name=local,O=Grid`,
   - `bdii_type` with fixed value of `bdii_top`,
   - `glue2_bdii_dn` with value of `GLUE2DomainID=<SITENAME>,o=glue` (`<SITENAME>` is site name defined in the topology);
3. if service type is `Site-BDII`:
   - `bdii_dn` - with value of `Mds-Vo-Name=<SITENAME>,O=Grid` (`<SITENAME>` is site name defined in the topology),
   - `bdii_type` - with fixed value `bdii_site`,
   - `glue2_bdii_dn` with value `GLUE2DomainID=<SITENAME>,o=glue` (`<SITENAME>` is site name defined in the topology).

For proxy entities it is important to define `entity_class` as `proxy`, and add entity's hostname in the list of subscriptions.

### Checks

The `scg-reload.py` tool fetches metric profiles from ARGO WEB-API, and fetches configuration of metrics defined in the metric profiles from ARGO POEM. It then creates checks from the fetched configurations and deletes the ones no longer used. Each time the tool is run, it also checks if there have been any changes in the metric configurations, and updates checks definitions accordingly.

If we take [generic.tcp.connect](https://poem.argo.grnet.gr/ui/public_metrictemplates/generic.tcp.connect) metric as an example, the check command would look like this:

```
/usr/lib64/nagios/plugins/check_tcp -H {{ .labels.hostname }} -t 120 -p 443
```

Checks can fetch information from entities' labels buckets, and they are generated accordingly (case of attributes, special values from topology and/or overrides). The parameters are simply mapped to command if there are no overrides. 

Tool also creates a list of hostnames which are going to run the check, and adds them to subscriptions list. It calculates the check interval (in POEM it is defined in minutes, in check definition it needs to be defined in seconds). A fixed timeout of 900 s (15 min) is created for each check - this is in case the probe is left hanging, so that it does not clutter the system. 

In metadata bucket the tool stores the metric name, namespace in which it is defined, and in annotations we define attempts, which is the number defined as `maxCheckAttempts` in POEM. This number is used by `hard-state` filter.

Depending on which pipeline should process the metric, the correct one is defined in check configuration. As a rule, all the metrics with `NOPUBLISH` flag (internal metrics) are processed with `reduce_alerts` pipeline (and their results sent to ARGO Slack channel). Also, if the tenant has set `publish = false` in the configuration file, all the checks defined for that namespace are processed by the same pipeline. In case configuration for tenant is set to `publish = true`, checks are processed by `hard_state` pipeline.

#### Flags

`scg-reload.py` tool takes into account `NOHOSTNAME`, `NOTIMEOUT`, `NOPUBLISH`, and `PASSIVE` flags.

* `NOHOSTNAME` - `{{ .labels.hostname }}` is left out from the check command.
* `NOTIMEOUT` - `-t <TIMEOUT>` parameter is left out from the check command.
* `NOPUBLISH` - pipeline defined for this check is `reduce_alerts`. Its results are sent to Slack channel instead of AMS Publisher.
* `PASSIVE` - marks passive metric. These are handled slightly differently. They are not actively running, but generated by results written to fifo file by their active parents. When a metric has this flag, the generated check looks as follows:

```json
{
  "command": "PASSIVE",
  "subscriptions": [
    "hostname.example.com"
  ],
  "handlers": ["publisher-handler"],
  "pipelines": [],
  "cron": "CRON_TZ=Europe/Zagreb 0 0 31 2 *",
  "timeout": 900,
  "publish": false,
  "metadata": {
    "name": "eu.egi.SRM-VOGet",
    "namespace": "TENANT1"
  },
  "round_robin": false
}
```

Command is just a placeholder, since the check is never going to be executed by the scheduler. That is ensured by the cron definition that is never going to happen (31 Feb). Publish must be set to `false`, and, instead of pipeline, here we only define `publisher-handler` to handle the check.

#### Attributes

There are some specifics on how the tool handles attributes. If attribute name ends with `_TOKEN`, `_LOGIN`, `_SALT`, `_ID`, `_PASSWORD`, `_USER`, `_SECRET`, `_USERNAME`, or `_CREDENTIALS`, it assumes its value is secret and expects it to be defined in the secrets file defined in the configuration file. It is then defined in the check configuration with `$` prefix and all capital letters. For example:

```
/usr/libexec/argo/probes/webapi/web-api -H {{ .labels.hostname }} -t 120 --rtype ar --day 1 -k $ARGO_API_TOKEN
```

Some attributes have default values, and can be overridden in POEM. These are:

| Attribute name   | Default value                  |
|------------------|--------------------------------|
| NAGIOS_HOST_CERT | /etc/sensu/certs/hostcert.pem  |
| NAGIOS_HOST_KEY  | /etc/sensu/certs/hostkey.pem   |
| KEYSTORE         | /etc/sensu/certs/keystore.jks  |
| TRUSTSTORE       | /etc/sensu/certs/truststore.ts |

If `ROBOT_CERT` and `ROBOT_KEY` are defined, their values are overriding the value of `NAGIOS_HOST_CERT` and `NAGIOS_HOST_KEY` respectively.

If metric is using `NAGIOS_ACTUAL_HOST_CERT` and `NAGIOS_ACTUAL_HOST_KEY`, it uses default `NAGIOS_HOST_CERT` and `NAGIOS_HOST_KEY`, regardless of whether `ROBOT_CERT` and `ROBOT_KEY` are defined.

Default ports are defined in Super POEM. If metric has any of the default ports in its configuration, the tool will check if any endpoint has that port defined as an extension in topology or as overridden value in POEM. If there is, the configuration would look like this (e.g. `GRAM_PORT` with default value 2119):

```
-p {{ .labels.gram_port | default "2119" }}
```

That way endpoints with overrides will use their values, and those that do not, will use the default value of 2119.

In case of extensions, special values from the topology (e.g. `info_hostdn`), overridden attributes and/or parameters, the checks are configured so that they can make use of all the labels created in entities' definitions.

If an attribute that is extension has a value of `0` or `1`, attribute's value is considered to be a flag: the value than marks that the flag should be used in probe execution. If it is not defined, the flag is simply not used.

Any extension ending in `_URL`, if not defined in the topology, would fall back to value defined in `info_URL`, except for two attributes used for webdav/xrootd endpoints: `ARGO_WEBDAV_OPS_URL` and `ARGO_XROOTD_OPS_URL`, which **must** be defined in the topology.

### Events

In Sensu, event is the context containing information about the entity running the check and the corresponding check result. Sensu scheduler runs checks on certain entities based on their subscriptions. Events are automatically processed by Sensu using handlers, filters and pipelines.

### Handlers, filters and pipelines

Tenants with `publish` flag in the configuration file send the metric results to ARGO AMS Publisher. For those tenant, `scg-reload.py` tool creates `publisher-handler` which takes care of that. Handlers consume event data via stdin. The definition of the said handler looks like this:

```json
{
  "metadata": {
    "name": "publisher-handler",
    "namespace": "TENANT1"
  },
  "type": "pipe",
  "command": "/bin/sensu2publisher.py"
}
```

`publisher-handler` takes in event output data and sends it further to `sensu2publisher.py` tool, which then prepares it for ARGO AMS Publisher.

In addition to the handler, there is also a `hard-state` filter created. The filter allows (`action = allow`) either passing results (`status = 0`) or non-ok results which have occurred more than `maxCheckAttempts` number of times (defined in metric configuration in ARGO POEM, and stored in check configuration in `annotations` bucket as `attempts` key) to the `publisher-handler`. The filter is created in order to reduce flapping results. Filter definition looks like this:

```json
{
  "metadata": {
    "name": "hard-state",
    "namespace": "TENANT1"
  },
  "action": "allow",
  "expressions": [
    "((event.check.status == 0) || (event.check.occurrences >= Number(event.check.annotations.attempts) && event.check.status != 0))"
  ]
}
```

The `publisher-handler` and `hard-state` filter are used by checks as `hard_state` pipeline defined as follows:

```json
{
  "metadata": {
    "name": "hard_state",
    "namespace": "TENANT1"
  },
  "workflows": [
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
}
```

Workflow is as follows: event results are first filtered using `hard-state` filter, and then handled by `publisher-handler` and sent to ARGO AMS Publisher.

All the tenants have `slack` handler, which is used internally to send results of internal metrics to ARGO team Slack. In order for it to work, you need to have registered [sensu/sensu-slack-handler](https://bonsai.sensu.io/assets/sensu/sensu-slack-handler) dynamic runtime asset. It also requires environmental variable `SLACK_WEBHOOK_URL` to be able to send data to Slack. In ARGO, we define it in a file in the filesystem. The Slack handler definition looks like this:

```json
{
  "metadata": {
    "name": "slack",
    "namespace": "TENANT1"
  },
  "type": "pipe",
  "command": "source /etc/sensu/secrets ; export $(cut -d= -f1 /etc/sensu/secrets) ; sensu-slack-handler --channel '#monitoring'",
  "runtime_assets": ["sensu-slack-handler"]
}
```

In addition to `slack` handler, there is also `daily` filter, which takes care that notifications for non-ok statuses are sent once a day after they are first raised, instead of each time the check is run. That way we avoid notification spamming in the Slack channel. Filter's definition looks like this:

```json
{
  "metadata": {
    "name": "daily",
    "namespace": "TENANT1"
  },
  "action": "allow",
  "expressions": [
    "((event.check.occurrences == 1 && event.check.status == 0 && event.check.occurrences_watermark >= Number(event.check.annotations.attempts)) || (event.check.occurrences == Number(event.check.annotations.attempts) && event.check.status != 0)) || event.check.occurrences % (86400 / event.check.interval) == 0"
  ]
}
```

`slack` handler and `daily` filtered are used in checks as `reduce_alerts` pipeline:

```json
{
  "metadata": {
    "name": "reduce_alerts",
    "namespace": "TENANT1"
  },
  "workflows": [
    {
      "name": "slack_alerts",
      "filters": [
        {
          "name": "is_incident",
          "type": "EventFilter",
          "api_version": "core/v2"
        },
        {
          "name": "not_silenced",
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
}
```

This pipeline, in addition to filter and handler defined by the tool, uses two built-in filters. `is_incident` filter allows non-ok (1, 2, 3) statuses and resolution events to be processed. That way the events with OK status are not passed to the handler (only in case of resolution). There is also `not_silenced` filter - that one allows only events which have not been silenced.

