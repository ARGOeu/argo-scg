# ARGO-SCG

## Description

The ARGO SCG is a component of ARGO monitoring engine that creates configuration for Sensu based on main sources of truth: ARGO Web-API for topology and metric profiles and ARGO POEM for metric configurations.

## Installation

Component is supported on CentOS 7. RPM package and its dependencies are available in ARGO repositories, and it is simply installed using yum:

```
yum install -y argo-scg
```

## Configuration

Configuration is stored in file `/etc/argo-scg/scg.conf`. It consists of minimum two sections: `[GENERAL]` section and one section per tenant `[<tenant_name>]`. Tool will set up one namespace for each tenant in the configuration file.

### GENERAL section

```
[GENERAL]
sensu_url = https://sensu.backend.url
sensu_token = sensu-api-token
webapi_url = https://api.devel.argo.grnet.gr
```

* `sensu_url` - URL of the Sensu API
* `sensu_token` - token for the Sensu API
* `webapi_url` - URL of the ARGO Web-API

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
```

* `poem_url` - POEM URL for the given tenant
* `poem_token` - POEM token for the given tenant
* `webapi_token` - Web-API token for the given tenant
* `attributes` - path to the file containing the attributes for the given tenant
* `metricprofile` - comma separated list of metric profiles for the given tenant
* `publish` - flag that marks if the metrics results should be sent to publisher
* `publisher_queue` - publisher queue; this entry can be left out if `publish` is set to False

## Tools

ARGO SCG consists of several tools:

* `scg-reload.py` configures Sensu for use with ARGO monitoring; details of configuration are described in section [Sensu configuration](#sensu-configuration)
* `scg-ack.py` for acknowledgement of errors
* `sensu2publisher.py` prepares Sensu event output data for ARGO AMS Publisher

### `scg-reload.py`

`scg-reload.py` is simply invoked without any arguments if we are going to use the default location of the configuration file `/etc/argo-scg/scg.conf`. If you wish to override the configuration file location, it can be done using `-c` parameter with `scg-reload.py` script. 

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

The tool also writes to a logfile, located in `/var/log/argo-scg/argo-scg.log`.

### `sensu-ack.py`

This tool is used to acknowledge an event, so it does not send any more notifications. The event will be silenced until it is resolved, after that it will send notifications normally without any user input. 

The tool takes two required arguments: check name `-c`, and entity name `-e`. By default, it uses the `default` namespace, you can override that with the namespace argument (`-n`). You can also override the configuration file it uses, by default it uses configuration file `/etc/argo-scg/scg.conf`.

Example:

```
scg-ack.py -c argo.POEM-CERT-MON -e argo.poem__poem.argo.grnet.gr -n internal
```
### `sensu2publisher.py`

`sensu2publisher.py` is not meant to be run by a user, it is run by Sensu as a handler. It takes Sensu check output as input, and then prepares data to be sent to the publisher.

## Sensu configuration

### Namespaces

Multi-tenancy in Sensu is achieved by using namespaces - each tenant has its own namespace with isolated definitions of checks (metrics), entities (endpoints), events, handlers, and filters. For each tenant defined in the configuration file, the `scg-reload.py` tool creates namespace if it does not exist. Also, if a namespace exists for which there is no tenant definition in the configuration file, that namespace is deleted.

### Handlers and filters

Tenants with `publish` flag in the configuration file send the metric results to ARGO AMS Publisher. For those tenant, `scg-reload.py` tool creates `publisher-handler` which takes care of that. In addition to the handler, there is also a `hard-state` filter created, which passes only the non-ok results which have occurred more than `maxCheckAttempts` number of times (defined in metric configuration in ARGO POEM) to the `publisher-handler`. That way we avoid flapping results.

All the tenants have `slack` handler, which is used internally to send results of internal metrics to ARGO team Slack. There is also `daily` filter, which takes care that notifications for non-ok statuses are sent once a day after they are first raised, instead of each time the check is run. That way we avoid notification spamming in the Slack channel.

### Checks

Checks are created for each tenant in their own namespace based on information from metric profiles defined in the configuration files. The `scg-reload.py` tool fetches metric profiles from ARGO WEB-API, and fetches configuration of metrics defined in the metric profiles from ARGO POEM. It then creates checks from the fetched configurations and deletes the ones no longer used. Each time the tool is run, it also checks if there have been any changes in the metric configurations, and updates Sensu checks accordingly.

#### Attributes

There are some specifics on how the tool handles attributes. If attribute name ends with `_TOKEN`, `_LOGIN`, `_SALT`, `_ID`, `_PASSWORD`, `_USER`, `_SECRET`, `_USERNAME`, or `_CREDENTIALS`, it assumes its value is secret and expects it to be defined in the secrets file defined in the configuration file. It is then defined in the check configuration with `$` prefix and all capital letters. For example:

```
/usr/libexec/argo/probes/webapi/web-api -H {{ .labels.hostname }} -t 120 --rtype ar --day 1 -k $ARGO_API_TOKEN
```

If there is a metric parameter override defined in the ARGO POEM, it is stored in entity label bucket and fetched as such. Given that the overrides are defined per hostname, there is possibility that there are hostnames (i.e. entities in Sensu world) that do not have such labels defined. Therefore, we keep the default value as is defined in ARGO POEM. Example:

```
/usr/libexec/argo/probes/ams-publisher/ams-publisher-probe -s /var/run/ams-publisher/sock -q {{ .labels.argo_amspublisher_check_q | default "'w:metrics+g:published180' -c 10" }}
```

If attribute is defined as extension in topology, it is defined in entity's labels bucket. In the check definition, it looks as follows:

```
/usr/lib64/nagios/plugins/check_http -H {{ .labels.hostname }} -t 60 --link --ssl -u {{ .labels.argo_oidc_authorisation_endpoint }}
```

### Entities

Entities are created based on the data defined in the topology. The name of the entity is defined as `<service>__<hostname>`. 

Hostnames used in the metric runs are stored per-entity in the entity's hostname label.

```json
{
  "metadata": {
    "labels": {
      "hostname": "api.devel.argo.grnet.gr"
    }
  }
}
```

If there is a `info_URL` tag defined in the topology, it is automatically added to entity's labels. If there are checks run for that entity which require `PATH` or `PORT` attribute, they are defined based on the `info_URL` tag.

```json
{
  "metadata": {
    "labels": {
      "info_url": "https://argoeu.github.io/argo-web-api/docs/",
      "hostname": "argoeu.github.io",
      "port": "443",
      "path": "/argo-web-api/docs/"
    }
  }
}
```

Keep in mind that if any of the attributes is defined as an extension in the topology, it overrides the ones described above. Also, if there is an attribute override defined in ARGO POEM, it takes precedence over the values derived from `info_URL` or extension defined in the topology.

Otherwise, extensions defined in the topology are added as labels in the entity configuration.

In addition to attributes, there are also site and service defined in the labels bucket of each entity configuration.

```json
{
  "metadata": {
    "labels": {
      "hostname": "api.devel.argo.grnet.gr",
      "service": "argo.api",
      "site": "ARGO"
    }
  }
}
```
