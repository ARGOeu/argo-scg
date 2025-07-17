# Changelog

## [0.7.3-1] - 2025-03-07

### Fixed

* ARGO-5022 URL path not passed properly

## [0.7.2-1] - 2025-04-02

### Changed

* ARGO-4940 Ability to have optional attributes

## [0.7.1-1] - 2024-09-13

### Added 

* ARGO-4827 Send tags bucket with extra information to AMS Publisher

## [0.7.0-1] - 2024-09-02

### Changed

* ARGO-4824 Improve checks subscriptions
* ARGO-4748 Remove silenced entries associated to deleted entities

## [0.6.3-1] - 2024-08-08

### Changed

* ARGO-4791 Take into account possibility of not having site_bdii defined for a site

## [0.6.2-1] - 2024-07-25

### Added

* ARGO-4747 Introduce SILENCED flag

## [0.6.1-1] - 2024-07-04

### Fixed

* ARGO-4564 When clearing namespace for deletion, remove all the silenced entries

## [0.6.0-1] - 2024-06-17

### Added

* ARGO-4618 Add tenant name in entity labels
* ARGO-4554 Create entities from multiple tenants in single namespace
* ARGO-4553 Create checks from multiple tenants in single namespace
* ARGO-4551 Add tenant name in check labels

### Changed

* ARGO-4601 Implement the changes in the executables
* ARGO-4616 Improve agent handling to include case with multiple tenants in single namespace
* ARGO-4550 Use tenant name instead of namespace in tools

### Fixed

* ARGO-4555 Display only events for the given tenant
* ARGO-4663 Fix wrongly referenced variable
* ARGO-4563 Fix error when trying to execute check on agent ad hoc

## [0.5.2-1] - 2024-04-04

### Changed

* ARGO-4523 Change filtering of Sensu events
* ARGO-4509 Add attempts annotation to sensu.cpu.usage and sensu.memory.usage checks
* AO-919 Prepare argo-scg Jenkinsfile for Rocky 9

## [0.5.1-1] - 2024-03-07

### Added

* ARGO-4467 Create checks for CPU and memory

### Changed

* ARGO-4480 Take into account parent's maxCheckAttempts for passive metrics

## [0.5.0-1] - 2024-02-01

### Added

* ARGO-4465 Option to exclude some metrics from running
* ARGO-4460 Handle variable _SERVICEVO_FQAN in metric configuration
* ARGO-4454 Add entity as subscription option
* ARGO-4452 Dedicate agents to certain service type

### Changed

* ARGO-4464 Improve message sent to AMS from Sensu
* ARGO-4453 Improve messages that are being logged
* ARGO-4455 Beautify sensu-events output

### Fixed

* ARGO-4463 Error filtering events by service type
* ARGO-4459 Fix wrong label for attribute if it exists in all endpoints

## [0.4.1-1] - 2024-01-03

### Added

* ARGO-4449 Add multiple subscription options

### Changed

* ARGO-4450 Do not use URL for webdav/xrootd checks
* ARGO-4448 Treat certain attribute values as flags

## [0.4.0-1] - 2023-12-07

### Added

* ARGO-4442 Add quotation marks to URLs that contain ampersand
* ARGO-4436 Use info_bdii_* tags as extensions
* ARGO-4435 Have default value for OS_KEYSTONE_PORT attribute
* ARGO-4421 Use event timestamp for display of events
* ARGO-3947 Handle passive metrics

### Changed

* ARGO-4427 Change values of hard-coded attributes
* ARGO-4423 Use hostnames as subscriptions

## [0.3.0-1] - 2023-11-02

### Added

* ARGO-4415 Handle $_SERVICEVO$ variable in metric configuration
* ARGO-4403 Option to run scg-reload for one tenant
* ARGO-4402 Filter events testing the agent
* ARGO-4392 Filter events by service type
* ARGO-4395 Handle dashes in attribute names
* ARGO-4393 Handle situations when endpoint URL is not defined
* ARGO-4391 Handle parameters with $_SERVICESITE_NAME$ variable
* ARGO-4388 Handle non-existing attributes

### Changed

* ARGO-4399 Use ROBOT_CERT for authentication if it is defined instead of NAGIOS_HOST_CERT
* ARGO-4400 Handle HOSTDN attribute properly

## [0.2.3-1] - 2023-07-02

### Added

* ARGO-4339 Handle overrides of default ports
* ARGO-4338 Handle generic.http.connect for endpoints without defined info_URL
* ARGO-4336 Handle endpoints without URL when using metric with URL
* ARGO-4220 Handle hostnames assigned to multiple sites in topology

### Fixed

* ARGO-4335 Host attributes overrides not working properly

## [0.2.2-1] - 2023-06-01

### Added

* ARGO-4325 Have separate filters for groups and endpoints
* ARGO-4324 Handle parameters with $HOSTALIAS$
* ARGO-4323 Send performance data to AMS

## [0.2.1-1] - 2023-05-04

### Added

* ARGO-4272 Handle checks with timeout
* ARGO-4238 Possibility to change slack pipeline
* ARGO-4234 Create custom display of events
* ARGO-4231 Handle overrides for the same metric, but different hostnames

### Changed

* ARGO-4269 Refactor sensu-events tool to display entity names instead of hostnames

### Fixed

* ARGO-4270 Filtering OK events not working
* ARGO-4254 scg-run-check.py not working as expected

## [0.1.1-1] - 2023-03-02

### Added

* ARGO-4228 Create tool to acknowledge alerts
* ARGO-4223 Create a tool that is going to force run check for an entity
* ARGO-4222 Create a tool that is going to display how exactly the probe is invoked
* ARGO-4193 Log calls to ams-metric-to-queue tool
* ARGO-4203 Send hostname_id in metric result
* ARGO-4189 Send metric output to ams
* ARGO-4139 Possibility to override default arguments
* ARGO-4092 Add topology filtering
* ARGO-4047 Create tool for ad hoc check execution request
* ARGO-4003 Handle hostnames in tags
* ARGO-3956 Include filter mimicking hard/soft state to non-internal checks
* ARGO-3945 Include internal checks for sensu agent
* ARGO-3917 Handle attribute names which are not all capital letters
* ARGO-3913 Add extra filter to mimic hard/soft state for some metrics
* ARGO-3801 Add feature to override parameters from POEM
* ARGO-3761 Handle filters and handlers for tenants not using the publisher

### Changed

* ARGO-4235 Remove regex validation of entity names
* ARGO-4224 Skip configuration in case of data fetch error
* ARGO-4091 Delete all the resources in the namespace when it is no longer used
* ARGO-4215 Send entire metric output message to publisher
* ARGO-4197 Skip creation of improperly formatted entities
* ARGO-4002 Remove hard-coded default ports
* ARGO-3999 Remove hard-coded list of secrets
* ARGO-3944 Improve filter for internal events
* ARGO-3910 Improve logging when setting up the configuration
* ARGO-3760 Treat "default" namespace differently

### Fixed

* ARGO-4137 Tool not creating "path" label for entity
* ARGO-4090 The tool not creating labels for agent
* ARGO-4098 Bug with metric parameter overrides
* ARGO-4079 The tool not reporting missing metric configuration
* ARGO-3986 Tool not handling *_URL attributes properly

## [0.1.0-1] - 2022-05-05

### Added

* ARGO-3606 Investigate Sensu as replacement for Nagios
