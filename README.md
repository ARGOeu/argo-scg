# ARGO-SCG

## Description (sensu)

The ARGO SCG is a component of ARGO monitoring engine that creates configuration for Sensu based on main sources of truth: ARGO Web-API for topology and metric profiles and ARGO POEM for metric configurations.

It consists of two tools: 

* scg-reload.py which creates or updates Sensu entities, checks and namespaces
* sensu2publisher.py which prepares Sensu event output data for ARGO AMS Publisher

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

## Running

`scg-reload.py` is simply invoked without any arguments if we are going to use the default location of the configuration file `/etc/argo-scg/scg.conf`. If you wish to override the configuration file, it can be done using `-c` parameter with `scg-reload.py` script. 

`sensu2publisher.py` is not meant to be run by a user, it is run by Sensu as a handler. It takes Sensu check output as input, and then prepares data to be sent to the publisher.
