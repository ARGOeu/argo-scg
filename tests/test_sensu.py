import copy
import json
import logging
import subprocess
import unittest
from unittest.mock import patch, call

from argo_scg.exceptions import SensuException
from argo_scg.sensu import Sensu, MetricOutput

from utils import MockResponse

mock_entities = [
    {
        "entity_class": "proxy",
        "system": {
            "network": {
                "interfaces": None
            },
            "libc_type": "",
            "vm_system": "",
            "vm_role": "",
            "cloud_provider": "",
            "processes": None
        },
        "subscriptions": None,
        "last_seen": 0,
        "deregister": False,
        "deregistration": {},
        "metadata": {
            "name": "argo-devel.ni4os.eu",
            "namespace": "TENANT1",
            "labels": {
                "sensu.io/managed_by": "sensuctl",
                "hostname": "argo-devel.ni4os.eu",
                "argo_webui": "argo.webui"
            }
        },
        "sensu_agent_version": ""
    },
    {
        "entity_class": "proxy",
        "system": {
            "network": {
                "interfaces": None
            },
            "libc_type": "",
            "vm_system": "",
            "vm_role": "",
            "cloud_provider": "",
            "processes": None
        },
        "subscriptions": ["argo.webui"],
        "last_seen": 0,
        "deregister": False,
        "deregistration": {},
        "metadata": {
            "name": "argo.ni4os.eu",
            "namespace": "TENANT1",
            "labels": {
                "sensu.io/managed_by": "sensuctl",
                "hostname": "argo.ni4os.eu",
                "generic_http_connect": "generic.http.connect"
            }
        },
        "sensu_agent_version": ""
    },
    {
        "entity_class": "proxy",
        "system": {
            "network": {
                "interfaces": None
            },
            "libc_type": "",
            "vm_system": "",
            "vm_role": "",
            "cloud_provider": "",
            "processes": None
        },
        "subscriptions": ["argo.webui"],
        "last_seen": 0,
        "deregister": False,
        "deregistration": {},
        "metadata": {
            "name": "gocdb.ni4os.eu",
            "namespace": "TENANT1",
            "labels": {
                "hostname": "gocdb.ni4os.eu",
                "sensu.io/managed_by": "sensuctl",
                "eu_ni4os_ops_gocdb": "eu.ni4os.ops.gocdb"
            }
        },
        "sensu_agent_version": ""
    },
    {
        "entity_class": "agent",
        "system": {
            "hostname": "sensu-agent1",
            "os": "linux",
            "platform": "centos",
            "platform_family": "rhel",
            "platform_version": "7.8.2003",
            "network": {
                "interfaces": [
                    {
                        "name": "lo",
                        "addresses": ["xxx.x.x.x/x"]
                    },
                    {
                        "name": "eth0",
                        "mac": "xx:xx:xx:xx:xx:xx",
                        "addresses": ["xx.x.xxx.xxx/xx"]
                    }
                ]
            },
            "arch": "amd64",
            "libc_type": "glibc",
            "vm_system": "",
            "vm_role": "guest",
            "cloud_provider": "",
            "processes": None
        },
        "subscriptions": [
            "entity:sensu-agent1",
            "argo.webui",
            "eu.ni4os.ops.gocdb"
        ],
        "last_seen": 1645005291,
        "deregister": False,
        "deregistration": {},
        "user": "agent",
        "redact": [
            "password",
            "passwd",
            "pass",
            "api_key",
            "api_token",
            "access_key",
            "secret_key",
            "private_key",
            "secret"
        ],
        "metadata": {
            "name": "sensu-agent1",
            "namespace": "TENANT1",
            "labels": {
                "hostname": "sensu-agent1"
            }
        },
        "sensu_agent_version": "6.6.3"
    },
    {
        "entity_class": "agent",
        "system": {
            "hostname": "sensu-agent2",
            "os": "linux",
            "platform": "centos",
            "platform_family": "rhel",
            "platform_version": "7.9.2009",
            "network": {
                "interfaces": [
                    {
                        "name": "lo",
                        "addresses": ["xxx.x.x.x/x"]
                    },
                    {
                        "name": "eth0",
                        "mac": "xx:xx:xx:xx:xx:xx",
                        "addresses": ["xx.x.xxx.xxx/xx"]
                    }
                ]
            },
            "arch": "amd64",
            "libc_type": "glibc",
            "vm_system": "",
            "vm_role": "guest",
            "cloud_provider": "",
            "processes": None
        },
        "subscriptions": [
            "argo.webui",
            "entity:sensu-agent2",
            "eu.ni4os.ops.gocdb"
        ],
        "last_seen": 1645005284,
        "deregister": False,
        "deregistration": {},
        "user": "agent",
        "redact": [
            "password",
            "passwd",
            "pass",
            "api_key",
            "api_token",
            "access_key",
            "secret_key",
            "private_key",
            "secret"
        ],
        "metadata": {
            "name": "sensu-agent2",
            "namespace": "TENANT1"
        },
        "sensu_agent_version": "6.6.5"
    }
]

mock_checks = [
    {
        "command": "/usr/lib64/nagios/plugins/check_http "
                   "-H {{ .labels.hostname }} -t 30 -r argo.eu "
                   "-u /ni4os/report-ar/Critical/NGI?accept=csv --ssl  "
                   "--onredirect follow",
        "handlers": ["publisher-handler"],
        "high_flap_threshold": 0,
        "interval": 300,
        "low_flap_threshold": 0,
        "publish": True,
        "runtime_assets": None,
        "subscriptions": ["argo.webui"],
        "proxy_entity_name": "",
        "check_hooks": None,
        "stdin": False,
        "subdue": None,
        "ttl": 0,
        "timeout": 30,
        "proxy_requests": {
            "entity_attributes": [
                "entity.entity_class == 'proxy'",
                "entity.labels.generic_http_ar_argoui_ni4os == "
                "'generic.http.ar-argoui-ni4os'"
            ],
            "splay": False,
            "splay_coverage": 0
        },
        "round_robin": False,
        "output_metric_format": "",
        "output_metric_handlers": None,
        "env_vars": None,
        "metadata": {
            "name": "generic.http.ar-argoui-ni4os",
            "namespace": "TENANT1",
            "created_by": "root",
            "annotations": {
                "attempts": "2"
            }
        },
        "secrets": None,
        "pipelines": []
    },
    {
        "command": "/usr/lib64/nagios/plugins/check_http "
                   "-H {{ .labels.hostname }} -t 30 -r SRCE "
                   "-u /ni4os/report-status/Critical/SITES?accept=csv --ssl  "
                   "--onredirect follow",
        "handlers": ["publisher-handler"],
        "high_flap_threshold": 0,
        "interval": 300,
        "low_flap_threshold": 0,
        "publish": True,
        "runtime_assets": None,
        "subscriptions": ["argo.webui"],
        "proxy_entity_name": "",
        "check_hooks": None,
        "stdin": False,
        "subdue": None,
        "ttl": 0,
        "timeout": 30,
        "proxy_requests": {
            "entity_attributes": [
                "entity.entity_class == 'proxy'",
                "entity.labels.generic_http_status_argoui_ni4os == "
                "'generic.http.status-argoui-ni4os'"
            ],
            "splay": False,
            "splay_coverage": 0
        },
        "round_robin": False,
        "output_metric_format": "",
        "output_metric_handlers": None,
        "env_vars": None,
        "metadata": {
            "name": "generic.http.status-argoui-ni4os",
            "namespace": "TENANT1",
            "created_by": "root",
            "annotations": {
                "attempts": "2"
            }
        },
        "secrets": None,
        "pipelines": []
    },
    {
        "command": "/usr/lib64/nagios/plugins/check_tcp "
                   "-H {{ .labels.hostname }} -t 120 -p 443",
        "handlers": [],
        "high_flap_threshold": 0,
        "interval": 300,
        "low_flap_threshold": 0,
        "publish": True,
        "runtime_assets": None,
        "subscriptions": ["argo.webui"],
        "proxy_entity_name": "",
        "check_hooks": None,
        "stdin": False,
        "subdue": None,
        "ttl": 0,
        "timeout": 120,
        "proxy_requests": {
            "entity_attributes": [
                "entity.entity_class == 'proxy'",
                "entity.labels.generic_tcp_connect == 'generic.tcp.connect'"
            ],
            "splay": False,
            "splay_coverage": 0
        },
        "round_robin": True,
        "output_metric_format": "",
        "output_metric_handlers": None,
        "env_vars": None,
        "metadata": {
            "name": "generic.tcp.connect",
            "namespace": "TENANT1",
            "created_by": "root",
            "annotations": {
                "attempts": "3"
            }
        },
        "secrets": None,
        "pipelines": []
    }
]

mock_events = [
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "sequence": 5242,
        "pipelines": None,
        "timestamp": 1645518791,
        "entity": {
            "entity_class": "proxy",
            "system": {
                "network": {
                    "interfaces": None
                },
                "libc_type": "",
                "vm_system": "",
                "vm_role": "",
                "cloud_provider": "",
                "processes": None
            },
            "subscriptions": ["argo.webui"],
            "last_seen": 0,
            "deregister": False,
            "deregistration": {},
            "metadata": {
                "name": "argo.ni4os.eu",
                "namespace": "TENANT1",
                "labels": {
                    "generic_http_ar_argoui_ni4os":
                        "generic.http.ar-argoui-ni4os",
                    "hostname": "argo.ni4os.eu"
                }
            },
            "sensu_agent_version": ""},
        "check": {
            "command": "/usr/lib64/nagios/plugins/check_http "
                       "-H argo.ni4os.eu -t 30 -r argo.eu "
                       "-u /ni4os/report-ar/Critical/NGI?accept=csv "
                       "--ssl  --onredirect follow",
            "handlers": [],
            "high_flap_threshold": 0,
            "interval": 300,
            "low_flap_threshold": 0,
            "publish": True,
            "runtime_assets": None,
            "subscriptions": ["argo.webui"],
            "proxy_entity_name": "argo.ni4os.eu",
            "check_hooks": None,
            "stdin": False,
            "subdue": None, "ttl": 0,
            "timeout": 30,
            "proxy_requests": {
                "entity_attributes": [
                    "entity.entity_class == 'proxy'",
                    "entity.labels.generic_http_ar_argoui_ni4os == "
                    "'generic.http.ar-argoui-ni4os'"
                ],
                "splay": False,
                "splay_coverage": 0
            },
            "round_robin": False,
            "duration": 0.393113841,
            "executed": 1645518791,
            "history": [
                {
                    "status": 0,
                    "executed": 1645515791
                },
                {
                    "status": 0,
                    "executed": 1645516091
                },
                {
                    "status": 0,
                    "executed": 1645516091
                },
                {
                    "status": 0,
                    "executed": 1645516391
                }
            ],
            "issued": 1645518791,
            "output": "HTTP OK: HTTP/1.1 200 OK - 28895 bytes in 0.379 "
                      "second response time |time=0.379190s;;;0.000000 "
                      "size=28895B;;;0\n",
            "state": "passing",
            "status": 0,
            "total_state_change": 0,
            "last_ok": 1645518791,
            "occurrences": 2084,
            "occurrences_watermark": 2084,
            "output_metric_format": "",
            "output_metric_handlers": None,
            "env_vars": None,
            "metadata": {
                "name": "generic.http.ar-argoui-ni4os",
                "namespace": "TENANT1"
            },
            "secrets": None,
            "is_silenced": False,
            "scheduler": "",
            "processed_by": "agent2",
            "pipelines": []
        },
        "metadata": {
            "namespace": "TENANT1"
        }
    },
    {
        "pipelines": None,
        "timestamp": 1645518534,
        "entity": {
            "entity_class": "proxy",
            "system": {
                "network": {
                    "interfaces": None
                },
                "libc_type": "",
                "vm_system": "",
                "vm_role": "",
                "cloud_provider": "",
                "processes": None
            },
            "subscriptions": ["eu.ni4os.ops.gocdb"],
            "last_seen": 0,
            "deregister": False,
            "deregistration": {},
            "metadata": {
                "name": "gocdb.ni4os.eu",
                "namespace": "TENANT1",
                "labels": {
                    "generic_tcp_connect": "generic.tcp.connect",
                    "hostname":
                        "gocdb.ni4os.eu"
                }
            },
            "sensu_agent_version": ""
        },
        "check": {
            "command": "/usr/lib64/nagios/plugins/check_tcp "
                       "-H gocdb.ni4os.eu -t 120 -p 443",
            "handlers": [],
            "high_flap_threshold": 0,
            "interval": 300,
            "low_flap_threshold": 0,
            "publish": True,
            "runtime_assets": None,
            "subscriptions": ["eu.ni4os.ops.gocdb"],
            "proxy_entity_name": "gocdb.ni4os.eu",
            "check_hooks": None,
            "stdin": False,
            "subdue": None,
            "ttl": 0,
            "timeout": 120,
            "proxy_requests": {
                "entity_attributes": [
                    "entity.entity_class == 'proxy'",
                    "entity.labels.generic_tcp_connect == "
                    "'generic.tcp.connect'"
                ],
                "splay": False,
                "splay_coverage": 0
            },
            "round_robin": False,
            "duration": 0.059516622,
            "executed": 1645518534,
            "history": [],
            "issued": 1645518534,
            "output": "TCP OK - 0.045 second response time on "
                      "gocdb.ni4os.eu port 443|time=0.044729s;;;"
                      "0.000000;120.000000\n",
            "state": "passing",
            "status": 0,
            "total_state_change": 0,
            "last_ok": 1645518534,
            "occurrences": 1699,
            "occurrences_watermark": 1699,
            "output_metric_format": "",
            "output_metric_handlers": None,
            "env_vars": None,
            "metadata": {
                "name": "generic.tcp.connect",
                "namespace": "TENANT1"
            },
            "secrets": None,
            "is_silenced": False,
            "scheduler": "",
            "processed_by": "agent2",
            "pipelines": []
        },
        "metadata": {
            "namespace": "TENANT1"
        },
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "sequence": 1531
    },
    {
        "sequence": "xxxx",
        "pipelines": None,
        "timestamp": 1645521136,
        "entity": {
            "entity_class": "proxy",
            "system": {
                "network": {
                    "interfaces": None
                },
                "libc_type": "",
                "vm_system": "",
                "vm_role": "",
                "cloud_provider": "",
                "processes": None
            },
            "subscriptions": ["argo.webui"],
            "last_seen": 0,
            "deregister": False,
            "deregistration": {},
            "metadata": {
                "name": "argo.ni4os.eu",
                "namespace": "TENANT1",
                "labels": {
                    "hostname": "argo.ni4os.eu",
                    "generic_http_ar_argoui_ni4os":
                        "generic.http.ar-argoui-ni4os",
                    "generic_http_status_argoui_ni4os":
                        "generic.http.status-argoui-ni4os"
                }
            },
            "sensu_agent_version": ""
        },
        "check": {
            "command": "/usr/lib64/nagios/plugins/check_http "
                       "-H argo.ni4os.eu -t 30 -r SRCE "
                       "-u /ni4os/report-status/Critical/SITES?accept=csv "
                       "--ssl  --onredirect follow",
            "handlers": [],
            "high_flap_threshold": 0,
            "interval": 300,
            "low_flap_threshold": 0,
            "publish": True,
            "runtime_assets": None,
            "subscriptions": ["argo.webui"],
            "proxy_entity_name": "argo.ni4os.eu",
            "check_hooks": None,
            "stdin": False,
            "subdue": None,
            "ttl": 0,
            "timeout": 30,
            "proxy_requests": {
                "entity_attributes": [
                    "entity.entity_class == 'proxy'",
                    "entity.labels.generic_http_status_argoui_ni4os == "
                    "'generic.http.status-argoui-ni4os'"
                ],
                "splay": False,
                "splay_coverage": 0
            },
            "round_robin": False,
            "duration": 0.799173492,
            "executed": 1645521135,
            "history": [],
            "issued": 1645521135,
            "output": "HTTP OK: HTTP/1.1 200 OK - 74359 bytes in 0.795 second "
                      "response time |time=0.795143s;;;0.000000 size=74359B;;;"
                      "0\n",
            "state": "passing",
            "status": 0,
            "total_state_change": 0,
            "last_ok": 1645521135,
            "occurrences": 2,
            "occurrences_watermark": 2,
            "output_metric_format": "",
            "output_metric_handlers": None,
            "env_vars": None,
            "metadata": {
                "name": "generic.http.status-argoui-ni4os",
                "namespace": "TENANT1"
            },
            "secrets": None,
            "is_silenced": False,
            "scheduler": "",
            "processed_by": "agent2",
            "pipelines": []
        },
        "metadata": {
            "namespace": "TENANT1"
        },
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    }
]

mock_metrics = [
    {
        "generic.http.ar-argoui-ni4os": {
            "tags": [
                "argo.webui",
                "harmonized"
            ],
            "probe": "check_http",
            "config": {
                "timeout": "30",
                "retryInterval": "3",
                "path": "/usr/lib64/nagios/plugins",
                "maxCheckAttempts": "3",
                "interval": "5"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-r": "argo.eu",
                "-u": "/ni4os/report-ar/Critical/NGI?accept=csv",
                "--ssl": "0",
                "--onredirect": "follow"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http."
                      "html"
        }
    },
    {
        "generic.tcp.connect": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_tcp",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "path": "/usr/lib64/nagios/plugins/",
                "retryInterval": "3",
                "timeout": "120"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-p": "443"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_tcp.html"
        }
    },
    {
        "generic.certificate.validity": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_ssl_cert",
            "config": {
                "timeout": "60",
                "retryInterval": "30",
                "path": "/usr/lib64/nagios/plugins",
                "maxCheckAttempts": "2",
                "interval": "240"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "NAGIOS_HOST_CERT": "-C",
                "NAGIOS_HOST_KEY": "-K"
            },
            "parameter": {
                "-w": "30 -c 0 -N --altnames",
                "--rootcert-dir": "/etc/grid-security/certificates",
                "--rootcert-file": "/etc/pki/tls/certs/ca-bundle.crt"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/matteocorti/check_ssl_cert/"
                      "blob/master/README.md"
        }
    }
]

mock_namespaces = [
    {
        "name": "default"
    },
    {
        "name": "TENANT1"
    },
    {
        "name": "TENANT2"
    },
    {
        "name": "sensu-system"
    }
]

mock_metrics_hardcoded_attributes = [
    {
        "org.activemq.OpenWireSSL": {
            "tags": [],
            "probe": "check_activemq_openwire",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "path": "/usr/libexec/argo-monitoring/probes/activemq",
                "retryInterval": "3",
                "timeout": "30"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "KEYSTORE": "-K",
                "TRUSTSTORE": "-T"
            },
            "parameter": {
                "--keystoretype": "jks",
                "-s": "monitor.test.$_SERVICESERVER$.$HOSTALIAS$.openwiressl"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://wiki.egi.eu/wiki/OPS-MONITOR_profile_SAM_tests"
        }
    },
    {
        "org.nagiosexchange.Broker-BDII": {
            "tags": [],
            "probe": "check_bdii_entries_num",
            "config": {
                "interval": "360",
                "maxCheckAttempts": "3",
                "path": "/usr/libexec/argo-monitoring/probes/midmon",
                "retryInterval": "15",
                "timeout": "30"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "BDII_PORT": "-p",
                "TOP_BDII": "-H"
            },
            "parameter": {
                "-b": "Mds-Vo-Name=local,O=grid",
                "-c": "4:4",
                "-f": "\"(GlueServiceEndpoint=*$HOSTALIAS$*)\""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://wiki.egi.eu/wiki/MW_Nagios_tests"
        }
    },
]

mock_metrics_file_defined_attributes = [
    {
        "eudat.b2access.unity.login-local": {
            "tags": [
                "aai",
                "auth",
                "harmonized",
                "login",
                "sso"
            ],
            "probe": "check_b2access_simple.py",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "3",
                "path": "/usr/libexec/argo-monitoring/probes/eudat-b2access/",
                "retryInterval": "3",
                "timeout": "120"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1",
                "NOTIMEOUT": "1",
            },
            "dependency": {},
            "attribute": {
                "NAGIOS_B2ACCESS_LOGIN": "--username",
                "NAGIOS_B2ACCESS_PASSWORD": "--password"
            },
            "parameter": {
                "--url": "https://b2access.fz-juelich.de:8443"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/EUDAT-B2ACCESS/b2access-probe/"
                      "blob/master/README.md"
        }
    },
    {
        "pl.plgrid.QCG-Computing": {
            "tags": [],
            "probe": "org.qoscosgrid/computing/check_qcg_comp",
            "config": {
                "interval": "30",
                "maxCheckAttempts": "3",
                "path": "/usr/libexec/grid-monitoring/probes",
                "retryInterval": "10",
                "timeout": "600"
            },
            "flags": {
                "NRPE": "1",
                "OBSESS": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "1",
                "hr.srce.QCG-Computing-CertLifetime": "1"
            },
            "attribute": {
                "QCG-COMPUTING_PORT": "-p",
                "X509_USER_PROXY": "-x"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://www.qoscosgrid.org/trac/qcg-computing/wiki"
        }
    }
]

mock_handlers1 = [
    {
        "metadata": {
            "name": "simple_handler",
            "namespace": "TENANT1",
            "labels": {
                "sensu.io/managed_by": "sensuctl"
            },
            "created_by": "root"
        },
        "type": "pipe",
        "command": "jq '{header: {hostname: .entity.labels.hostname, "
                   "metric: .check.metadata.name, status: .check.status}, "
                   "body: .check.output}' \u003e\u003e /tmp/events.json",
        "timeout": 0,
        "handlers": None,
        "filters": None,
        "env_vars": None,
        "runtime_assets": None,
        "secrets": None
    }
]

mock_handlers2 = [
    {
        "metadata": {
            "name": "simple_handler",
            "namespace": "TENANT1",
            "labels": {
                "sensu.io/managed_by": "sensuctl"
            },
            "created_by": "root"
        },
        "type": "pipe",
        "command": "jq '{header: {hostname: .entity.labels.hostname, "
                   "metric: .check.metadata.name, status: .check.status}, "
                   "body: .check.output}' \u003e\u003e /tmp/events.json",
        "timeout": 0,
        "handlers": None,
        "filters": None,
        "env_vars": None,
        "runtime_assets": None,
        "secrets": None
    },
    {
        "metadata": {
            "name": "publisher-handler",
            "namespace": "TENANT1"
        },
        "type": "pipe",
        "command": "/bin/sensu2publisher.py",
        "timeout": 0,
        "handlers": None,
        "filters": None,
        "env_vars": None,
        "runtime_assets": None,
        "secrets": None
    },
    {
        "metadata": {
            "name": "slack",
            "namespace": "TENANT1",
            "created_by": "root"
        },
        "type": "pipe",
        "command": "source /etc/sensu/secrets ; "
                   "export $(cut -d= -f1 /etc/sensu/secrets) ; "
                   "sensu-slack-handler --channel '#monitoring'",
        "timeout": 0,
        "handlers": None,
        "filters": None,
        "env_vars": [],
        "runtime_assets": ["sensu-slack-handler"],
        "secrets": None
    }
]

mock_handlers3 = [
    {
        "metadata": {
            "name": "simple_handler",
            "namespace": "TENANT1",
            "labels": {
                "sensu.io/managed_by": "sensuctl"
            },
            "created_by": "root"
        },
        "type": "pipe",
        "command": "jq '{header: {hostname: .entity.labels.hostname, "
                   "metric: .check.metadata.name, status: .check.status}, "
                   "body: .check.output}' \u003e\u003e /tmp/events.json",
        "timeout": 0,
        "handlers": None,
        "filters": None,
        "env_vars": None,
        "runtime_assets": None,
        "secrets": None
    },
    {
        "metadata": {
            "name": "publisher-handler",
            "namespace": "TENANT1"
        },
        "type": "pipe",
        "command": "/bin/sensu2publisher.py >> /tmp/test",
        "timeout": 0,
        "handlers": None,
        "filters": None,
        "env_vars": None,
        "runtime_assets": None,
        "secrets": None
    },
    {
        "metadata": {
            "name": "slack",
            "namespace": "TENANT1",
            "created_by": "root"
        },
        "type": "pipe",
        "command": "sensu-slack-handler --channel '#monitoring'",
        "timeout": 0,
        "handlers": None,
        "filters": None,
        "env_vars": [
            'SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T0000/B000/'
            'XXXXXXXX'
        ],
        "runtime_assets": ["sensu-slack-handler"],
        "secrets": None
    }
]

mock_filters1 = [
    {
        "metadata": {
            "name": "daily",
            "namespace": "default",
            "created_by": "root"
        },
        "action": "allow",
        "expressions": [
            "((event.check.occurrences == 1 && event.check.status == 0 && "
            "event.check.occurrences_watermark >= "
            "Number(event.check.annotations.attempts)) || "
            "(event.check.occurrences == "
            "Number(event.check.annotations.attempts) "
            "&& event.check.status != 0)) || "
            "event.check.occurrences % "
            "(86400 / event.check.interval) == 0"
        ],
        "runtime_assets": None
    },
    {
        "metadata": {
            "name": "hard-state",
            "namespace": "default",
            "created_by": "root"
        },
        "action": "allow",
        "expressions": [
            "((event.check.status == 0) || (event.check.occurrences >= "
            "Number(event.check.annotations.attempts) "
            "&& event.check.status != 0))"
        ],
        "runtime_assets": None
    }
]

mock_filters2 = [
    {
        "metadata": {
            "name": "daily",
            "namespace": "default",
            "created_by": "root"
        },
        "action": "allow",
        "expressions": [
            "event.check.occurrences == 1 || "
            "event.check.occurrences % (86400 / event.check.interval) == 0"
        ],
        "runtime_assets": None
    },
    {
        "metadata": {
            "name": "hard-state",
            "namespace": "default",
            "created_by": "root"
        },
        "action": "allow",
        "expressions": [
            "event.check.occurrences == 1 || "
            "event.check.occurrences % (86400 / event.check.interval) == 0"
        ],
        "runtime_assets": None
    }
]

mock_pipelines1 = [
    {
        'metadata': {
            'name': 'reduce_alerts',
            'namespace': 'default',
            'labels': {'sensu.io/managed_by': 'sensuctl'},
            'created_by': 'root'
        },
        'workflows': [
            {
                'name': 'slack_alerts',
                'filters': [
                    {
                        'name': 'is_incident',
                        'type': 'EventFilter',
                        'api_version': 'core/v2'
                    },
                    {
                        'name': 'daily',
                        'type': 'EventFilter',
                        'api_version': 'core/v2'
                    }
                ],
                'handler': {
                    'name': 'slack',
                    'type': 'Handler',
                    'api_version': 'core/v2'
                }
            }
        ]
    },
    {
        'metadata': {
            'name': 'hard_state',
            'namespace': 'default',
            'labels': {'sensu.io/managed_by': 'sensuctl'},
            'created_by': 'root'
        },
        'workflows': [
            {
                'name': 'mimic_hard_state',
                'filters': [
                    {
                        'name': 'hard-state',
                        'type': 'EventFilter',
                        'api_version': 'core/v2'
                    }
                ],
                'handler': {
                    'name': 'publisher-handler',
                    'type': 'Handler',
                    'api_version': 'core/v2'
                }
            }
        ]
    }
]

LOGNAME = "argo-scg.sensu"
DUMMY_LOGGER = logging.getLogger(LOGNAME)
DUMMY_LOG = [f"INFO:{LOGNAME}:dummy"]


def _log_dummy():
    DUMMY_LOGGER.info("dummy")


def mock_sensu_request(*args, **kwargs):
    if args[0].endswith("entities"):
        return MockResponse(mock_entities, status_code=200)

    elif args[0].endswith("checks"):
        return MockResponse(mock_checks, status_code=200)

    elif args[0].endswith("events"):
        return MockResponse(mock_events, status_code=200)

    elif args[0].endswith("namespaces"):
        return MockResponse(mock_namespaces, status_code=200)

    elif args[0].endswith("handlers"):
        return MockResponse(mock_handlers1, status_code=200)

    elif args[0].endswith("filters"):
        return MockResponse(mock_filters1, status_code=200)

    elif args[0].endswith("pipelines"):
        return MockResponse(mock_pipelines1, status_code=200)


def mock_sensu_request_entity_not_ok_with_msg(*args, **kwargs):
    if args[0].endswith("entities"):
        return MockResponse(
            {"message": "Something went wrong."}, status_code=400
        )

    elif args[0].endswith("checks"):
        return MockResponse(mock_checks, status_code=200)

    elif args[0].endswith("events"):
        return MockResponse(mock_events, status_code=200)

    elif args[0].endswith("namespaces"):
        return MockResponse(mock_namespaces, status_code=200)


def mock_sensu_request_entity_not_ok_without_msg(*args, **kwargs):
    if args[0].endswith("entities"):
        return MockResponse(None, status_code=400)

    elif args[0].endswith("checks"):
        return MockResponse(mock_checks, status_code=200)

    elif args[0].endswith("events"):
        return MockResponse(mock_events, status_code=200)

    elif args[0].endswith("namespaces"):
        return MockResponse(mock_namespaces, status_code=200)


def mock_sensu_request_check_not_ok_with_msg(*args, **kwargs):
    if args[0].endswith("entities"):
        return MockResponse(mock_entities, status_code=200)

    elif args[0].endswith("checks"):
        return MockResponse(
            {"message": "Something went wrong."}, status_code=400
        )

    elif args[0].endswith("events"):
        return MockResponse(mock_events, status_code=200)

    elif args[0].endswith("namespaces"):
        return MockResponse(mock_namespaces, status_code=200)


def mock_sensu_request_check_not_ok_without_msg(*args, **kwargs):
    if args[0].endswith("entities"):
        return MockResponse(mock_entities, status_code=200)

    elif args[0].endswith("checks"):
        return MockResponse(None, status_code=400)

    elif args[0].endswith("events"):
        return MockResponse(mock_events, status_code=200)

    elif args[0].endswith("namespaces"):
        return MockResponse(mock_namespaces, status_code=200)


def mock_sensu_request_events_not_ok_with_msg(*args, **kwargs):
    if args[0].endswith("entities"):
        return MockResponse(mock_entities, status_code=200)

    elif args[0].endswith("checks"):
        return MockResponse(mock_checks, status_code=200)

    elif args[0].endswith("events"):
        return MockResponse(
            {"message": "Something went wrong."}, status_code=400
        )

    elif args[0].endswith("namespaces"):
        return MockResponse(mock_namespaces, status_code=200)


def mock_sensu_request_events_not_ok_without_msg(*args, **kwargs):
    if args[0].endswith("entities"):
        return MockResponse(mock_entities, status_code=200)

    elif args[0].endswith("checks"):
        return MockResponse(mock_checks, status_code=200)

    elif args[0].endswith("events"):
        return MockResponse(None, status_code=400)

    elif args[0].endswith("namespaces"):
        return MockResponse(mock_namespaces, status_code=200)


def mock_sensu_request_namespaces_not_ok_with_msg(*args, **kwargs):
    if args[0].endswith("entities"):
        return MockResponse(mock_entities, status_code=200)

    elif args[0].endswith("checks"):
        return MockResponse(mock_checks, status_code=200)

    elif args[0].endswith("events"):
        return MockResponse(mock_events, status_code=200)

    elif args[0].endswith("namespaces"):
        return MockResponse(
            {"message": "Something went wrong."}, status_code=400
        )


def mock_sensu_request_namespaces_not_ok_without_msg(*args, **kwargs):
    if args[0].endswith("entities"):
        return MockResponse(mock_entities, status_code=200)

    elif args[0].endswith("checks"):
        return MockResponse(mock_checks, status_code=200)

    elif args[0].endswith("events"):
        return MockResponse(mock_events, status_code=200)

    elif args[0].endswith("namespaces"):
        return MockResponse(None, status_code=400)


def mock_sensu_request_not_ok_with_msg(*args, **kwargs):
    return MockResponse({"message": "Something went wrong."}, status_code=400)


def mock_sensu_request_not_ok_without_msg(*args, **kwargs):
    return MockResponse(None, status_code=400)


def mock_post_response(*args, **kwargs):
    return MockResponse(None, status_code=200)


def mock_post_response_not_ok_with_msg(*args, **kwargs):
    return MockResponse({"message": "Something went wrong."}, status_code=400)


def mock_post_response_not_ok_without_msg(*args, **kwargs):
    return MockResponse(None, status_code=400)


def mock_delete_response(*args, **kwargs):
    return MockResponse(None, status_code=204)


def mock_delete_response_check_not_ok_with_msg(*args, **kwargs):
    if "entities" in args[0]:
        return MockResponse(None, status_code=204)


def mock_delete_response_check_not_ok_without_msg(*args, **kwargs):
    if "entities" in args[0]:
        return MockResponse(None, status_code=204)


def mock_delete_response_event_not_ok_with_msg(*args, **kwargs):
    if "checks" in args[0]:
        return MockResponse(None, status_code=204)

    elif "events" in args[0]:
        return MockResponse(
            {"message": "Something went wrong."}, status_code=400
        )

    elif "entities" in args[0]:
        return MockResponse(None, status_code=204)


def mock_delete_response_event_not_ok_without_msg(*args, **kwargs):
    if "events" in args[0]:
        return MockResponse(None, status_code=400)

    elif "entities" in args[0]:
        return MockResponse(None, status_code=204)


def mock_delete_response_entity_not_ok_with_msg(*args, **kwargs):
    return MockResponse({"message": "Something went wrong."}, status_code=400)


def mock_delete_response_entity_not_ok_without_msg(*args, **kwargs):
    return MockResponse(None, status_code=400)


def mock_function(*args, **kwargs):
    pass


class SensuNamespaceTests(unittest.TestCase):
    def setUp(self):
        self.sensu = Sensu(url="mock-urls", token="t0k3n")

    @patch("requests.get")
    def test_get_namespaces(self, mock_get):
        mock_get.side_effect = mock_sensu_request
        with self.assertLogs(LOGNAME) as log:
            DUMMY_LOGGER.info("dummy")
            namespaces = self.sensu._get_namespaces()
        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(sorted(namespaces), ["TENANT1", "TENANT2", "default"])
        self.assertEqual(log.output, [f"INFO:{LOGNAME}:dummy"])

    @patch("requests.get")
    def test_get_namespaces_with_error_with_message(self, mock_get):
        mock_get.side_effect = mock_sensu_request_namespaces_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_namespaces()

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: Namespaces fetch error: 400 BAD REQUEST: "
            "Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:Namespaces fetch error: "
                f"400 BAD REQUEST: Something went wrong.",
                f"WARNING:{LOGNAME}:Unable to proceed"
            ]
        )

    @patch("requests.get")
    def test_get_namespaces_with_error_without_message(self, mock_get):
        mock_get.side_effect = mock_sensu_request_namespaces_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_namespaces()
        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: Namespaces fetch error: 400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:Namespaces fetch error: "
                f"400 BAD REQUEST",
                f"WARNING:{LOGNAME}:Unable to proceed"
            ]
        )

    @patch("argo_scg.sensu.Sensu._get_namespaces")
    @patch("requests.put")
    def test_handle_namespaces(self, mock_put, mock_namespace):
        mock_put.side_effect = mock_post_response
        mock_namespace.return_value = ["Tenant1", "Tenant2"]
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_namespaces(
                tenants=["Tenant1", "Tenant2", "TeNAnT3", "tenant4"]
            )
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TeNAnT3",
                data=json.dumps({"name": "TeNAnT3"}),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/tenant4",
                data=json.dumps({"name": "tenant4"}),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)
        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:Namespace TeNAnT3 created",
                f"INFO:{LOGNAME}:Namespace tenant4 created"
            }
        )

    @patch("argo_scg.sensu.Sensu._get_namespaces")
    @patch("requests.put")
    def test_handle_namespaces_with_error_with_message(
            self, mock_put, mock_namespace
    ):
        mock_namespace.return_value = ["Tenant1", "Tenant2"]
        mock_put.side_effect = mock_post_response_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.handle_namespaces(
                    tenants=["Tenant1", "Tenant2", "TeNAnT3", "tenant4"]
                )
        mock_put.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TeNAnT3",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            },
            data=json.dumps({"name": "TeNAnT3"})
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: Namespace TeNAnT3 create error: 400 BAD REQUEST: "
            "Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:Namespace TeNAnT3 create error: "
                f"400 BAD REQUEST: Something went wrong.",
                f"WARNING:{LOGNAME}:Unable to proceed"
            ]
        )

    @patch("argo_scg.sensu.Sensu._get_namespaces")
    @patch("requests.put")
    def test_handle_namespaces_with_error_without_message(
            self, mock_put, mock_namespace
    ):
        mock_namespace.return_value = ["Tenant1", "Tenant2"]
        mock_put.side_effect = mock_post_response_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.handle_namespaces(
                    tenants=["Tenant1", "Tenant2", "TeNAnT3", "tenant4"]
                )
        mock_put.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TeNAnT3",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            },
            data=json.dumps({"name": "TeNAnT3"})
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: Namespace TeNAnT3 create error: 400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:Namespace TeNAnT3 create error: "
                f"400 BAD REQUEST",
                f"WARNING:{LOGNAME}:Unable to proceed"
            ]
        )

    @patch("argo_scg.sensu.Sensu._get_namespaces")
    @patch("subprocess.check_output")
    @patch("requests.delete")
    @patch("requests.put")
    def test_handle_namespaces_with_deletion(
            self, mock_put, mock_delete, mock_subprocess, mock_namespace
    ):
        mock_put.side_effect = mock_post_response
        mock_delete.side_effect = mock_delete_response
        mock_subprocess.side_effect = mock_function
        mock_namespace.return_value = ["Tenant1", "Tenant2", "Tenant5"]
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_namespaces(
                tenants=["Tenant1", "Tenant2", "TeNAnT3", "tenant4"]
            )
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TeNAnT3",
                data=json.dumps({"name": "TeNAnT3"}),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/tenant4",
                data=json.dumps({"name": "tenant4"}),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)
        mock_subprocess.assert_called_once_with(
            "sensuctl dump entities,events,assets,checks,filters,handlers "
            "--namespace Tenant5 | sensuctl delete", shell=True
        )
        mock_delete.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/Tenant5",
            headers={"Authorization": "Key t0k3n"}
        )
        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:Namespace TeNAnT3 created",
                f"INFO:{LOGNAME}:Namespace tenant4 created",
                f"INFO:{LOGNAME}:Namespace Tenant5 emptied",
                f"INFO:{LOGNAME}:Namespace Tenant5 deleted"
            }
        )

    @patch("argo_scg.sensu.Sensu._get_namespaces")
    @patch("argo_scg.sensu.subprocess.check_output")
    @patch("requests.delete")
    @patch("requests.put")
    def test_handle_namespaces_with_deletion_subprocess_error(
            self, mock_put, mock_delete, mock_subprocess, mock_namespace
    ):
        mock_put.side_effect = mock_delete_response
        mock_delete.side_effect = mock_post_response
        mock_subprocess.side_effect = subprocess.CalledProcessError(
            returncode=2, cmd=["error"], output="There has been an error"
        )
        mock_namespace.return_value = ["Tenant1", "Tenant2", "Tenant5"]
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_namespaces(
                tenants=["Tenant1", "Tenant2", "TeNAnT3", "tenant4"]
            )
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TeNAnT3",
                data=json.dumps({"name": "TeNAnT3"}),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/tenant4",
                data=json.dumps({"name": "tenant4"}),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)
        mock_subprocess.assert_called_once_with(
            "sensuctl dump entities,events,assets,checks,filters,handlers "
            "--namespace Tenant5 | sensuctl delete", shell=True
        )
        self.assertEqual(mock_delete.call_count, 0)
        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:Namespace TeNAnT3 created",
                f"INFO:{LOGNAME}:Namespace tenant4 created",
                f"ERROR:{LOGNAME}:Error cleaning namespace Tenant5: "
                f"There has been an error"
            }
        )

    @patch("argo_scg.sensu.Sensu._get_namespaces")
    @patch("subprocess.check_output")
    @patch("requests.delete")
    @patch("requests.put")
    def test_handle_namespaces_with_deletion_error_delete_api_with_msg(
            self, mock_put, mock_delete, mock_subprocess, mock_namespace
    ):
        mock_put.side_effect = mock_post_response
        mock_delete.return_value = MockResponse(
            {"message": "Something went wrong"}, status_code=400
        )
        mock_subprocess.side_effect = mock_function
        mock_namespace.return_value = ["Tenant1", "Tenant2", "Tenant5"]
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_namespaces(
                tenants=["Tenant1", "Tenant2", "TeNAnT3", "tenant4"]
            )
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TeNAnT3",
                data=json.dumps({"name": "TeNAnT3"}),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/tenant4",
                data=json.dumps({"name": "tenant4"}),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)
        mock_subprocess.assert_called_once_with(
            "sensuctl dump entities,events,assets,checks,filters,handlers "
            "--namespace Tenant5 | sensuctl delete", shell=True
        )
        mock_delete.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/Tenant5",
            headers={"Authorization": "Key t0k3n"}
        )
        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:Namespace TeNAnT3 created",
                f"INFO:{LOGNAME}:Namespace tenant4 created",
                f"INFO:{LOGNAME}:Namespace Tenant5 emptied",
                f"ERROR:{LOGNAME}:Error deleting Tenant5: 400 BAD REQUEST: "
                f"Something went wrong"
            }
        )

    @patch("argo_scg.sensu.Sensu._get_namespaces")
    @patch("subprocess.check_output")
    @patch("requests.delete")
    @patch("requests.put")
    def test_handle_namespaces_with_deletion_error_delete_api_without_msg(
            self, mock_put, mock_delete, mock_subprocess, mock_namespace
    ):
        mock_put.side_effect = mock_post_response
        mock_delete.return_value = MockResponse(None, status_code=400)
        mock_subprocess.side_effect = mock_function
        mock_namespace.return_value = ["Tenant1", "Tenant2", "Tenant5"]
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_namespaces(
                tenants=["Tenant1", "Tenant2", "TeNAnT3", "tenant4"]
            )
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TeNAnT3",
                data=json.dumps({"name": "TeNAnT3"}),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/tenant4",
                data=json.dumps({"name": "tenant4"}),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)
        mock_subprocess.assert_called_once_with(
            "sensuctl dump entities,events,assets,checks,filters,handlers "
            "--namespace Tenant5 | sensuctl delete", shell=True
        )
        mock_delete.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/Tenant5",
            headers={"Authorization": "Key t0k3n"}
        )
        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:Namespace TeNAnT3 created",
                f"INFO:{LOGNAME}:Namespace tenant4 created",
                f"INFO:{LOGNAME}:Namespace Tenant5 emptied",
                f"ERROR:{LOGNAME}:Error deleting Tenant5: 400 BAD REQUEST"
            }
        )


class SensuCheckTests(unittest.TestCase):
    def setUp(self):
        self.sensu = Sensu(url="mock-urls", token="t0k3n")
        self.checks = [
            {
                "command": "/usr/lib64/nagios/plugins/check_http "
                           "-H {{ .labels.hostname }} -t 30 "
                           "-r argo.eu "
                           "-u /ni4os/report-ar/Critical/"
                           "NGI?accept=csv "
                           "--ssl --onredirect follow",
                "subscriptions": ["argo.webui", "argo.test"],
                "handlers": ["publisher-handler"],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_http_ar_argoui_ni4os == "
                        "'generic.http.ar-argoui-ni4os'"
                    ]
                },
                "interval": 300,
                "timeout": 30,
                "publish": True,
                "metadata": {
                    "name": "generic.http.ar-argoui-ni4os",
                    "namespace": "TENANT1",
                    "annotations": {
                        "attempts": "3"
                    }
                },
                "round_robin": True,
                "pipelines": []
            },
            {
                "command": "/usr/lib64/nagios/plugins/check_tcp "
                           "-H {{ .labels.hostname }} -t 120 -p 443",
                "subscriptions": ["argo.webui"],
                "handlers": [],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_tcp_connect == "
                        "'generic.tcp.connect'"
                    ]
                },
                "interval": 300,
                "timeout": 120,
                "publish": True,
                "metadata": {
                    "name": "generic.tcp.connect",
                    "namespace": "TENANT1",
                    "annotations": {
                        "attempts": "3"
                    }
                },
                "round_robin": True,
                "pipelines": []
            },
            {
                "command": "/usr/lib64/nagios/plugins/check_ssl_cert -H "
                           "{{ .labels.hostname }} -t 60 -w 30 -c 0 -N "
                           "--altnames "
                           "--rootcert-dir /etc/grid-security/certificates"
                           " --rootcert-file "
                           "/etc/pki/tls/certs/ca-bundle.crt "
                           "-C {{ .labels.ROBOT_CERT | "
                           "default /etc/nagios/globus/hostcert.pem }} "
                           "-K {{ .labels.ROBOT_KEY | "
                           "default /etc/nagios/globus/hostkey.pem }}",
                "subscriptions": ["argo.webui"],
                "handlers": ["publisher-handler"],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_certificate_validity == "
                        "'generic.certificate.validity'"
                    ]
                },
                "interval": 14400,
                "timeout": 60,
                "publish": True,
                "metadata": {
                    "name": "generic.certificate.validity",
                    "namespace": "TENANT1",
                    "annotations": {
                        "attempts": "2"
                    }
                },
                "round_robin": True,
                "pipelines": []
            }
        ]

    @patch("requests.get")
    def test_get_checks(self, mock_get):
        mock_get.side_effect = mock_sensu_request
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = self.sensu._get_checks(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/checks",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(checks, mock_checks)
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.get")
    def test_get_checks_with_error_with_messsage(self, mock_get):
        mock_get.side_effect = mock_sensu_request_check_not_ok_with_msg

        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_checks(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/checks",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Checks fetch error: 400 BAD REQUEST: "
            "Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Checks fetch error: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.get")
    def test_get_checks_with_error_without_messsage(self, mock_get):
        mock_get.side_effect = mock_sensu_request_check_not_ok_without_msg

        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_checks(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/checks",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Checks fetch error: 400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Checks fetch error: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.delete")
    def test_delete_checks(self, mock_delete):
        mock_delete.side_effect = mock_delete_response
        with self.assertLogs(LOGNAME) as log:
            self.sensu._delete_checks(
                checks=[
                    "generic.tcp.connect",
                    "generic.http.connect",
                    "generic.certificate.validity"
                ],
                namespace="TENANT1"
            )
        self.assertEqual(mock_delete.call_count, 3)
        mock_delete.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.tcp.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.http.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.certificate.validity",
                headers={
                    "Authorization": "Key t0k3n"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: "
                f"Check generic.tcp.connect removed",
                f"INFO:{LOGNAME}:TENANT1: "
                f"Check generic.http.connect removed",
                f"INFO:{LOGNAME}:TENANT1: "
                f"Check generic.certificate.validity removed"
            }
        )

    @patch("requests.delete")
    def test_delete_checks_with_error_with_message(self, mock_delete):
        mock_delete.side_effect = [
            MockResponse({"message": "Something went wrong."}, status_code=400),
            MockResponse(None, status_code=204)
        ]
        with self.assertLogs(LOGNAME) as log:
            self.sensu._delete_checks(
                checks=["generic.tcp.connect", "generic.http.connect"],
                namespace="TENANT1"
            )

        self.assertEqual(mock_delete.call_count, 2)
        mock_delete.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.tcp.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.http.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"WARNING:{LOGNAME}:TENANT1: "
                f"Check generic.tcp.connect not removed: "
                f"400 BAD REQUEST: Something went wrong.",
                f"INFO:{LOGNAME}:TENANT1: "
                f"Check generic.http.connect removed"
            }
        )

    @patch("requests.delete")
    def test_delete_checks_with_error_without_message(self, mock_delete):
        mock_delete.side_effect = [
            MockResponse(None, status_code=400),
            MockResponse(None, status_code=204)
        ]
        with self.assertLogs(LOGNAME) as log:
            self.sensu._delete_checks(
                checks=["generic.tcp.connect", "generic.http.connect"],
                namespace="TENANT1"
            )

        self.assertEqual(mock_delete.call_count, 2)
        mock_delete.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.tcp.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.http.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"WARNING:{LOGNAME}:TENANT1: "
                f"Check generic.tcp.connect not removed: "
                f"400 BAD REQUEST",
                f"INFO:{LOGNAME}:TENANT1: "
                f"Check generic.http.connect removed"
            }
        )

    @patch("requests.put")
    @patch("argo_scg.sensu.Sensu._delete_events")
    @patch("argo_scg.sensu.Sensu._delete_checks")
    @patch("argo_scg.sensu.Sensu._get_events")
    @patch("argo_scg.sensu.Sensu._get_checks")
    def test_handle_check(
            self, mock_get_checks, mock_get_events, mock_delete_checks,
            mock_delete_events, mock_put
    ):
        checks2 = [
            mock_checks[0], mock_checks[1], mock_checks[2], self.checks[2]
        ]
        checks3 = [checks2[0], checks2[2], checks2[3]]
        mock_get_checks.side_effect = [mock_checks, checks2, checks3]
        mock_get_events.return_value = mock_events
        mock_delete_checks.side_effect = mock_delete_response
        mock_delete_events.side_effect = mock_delete_response
        mock_put.side_effect = mock_post_response

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_checks(self.checks, namespace="TENANT1")

        self.assertEqual(mock_get_checks.call_count, 3)
        mock_get_checks.assert_called_with(namespace="TENANT1")
        mock_get_events.assert_called_once_with(namespace="TENANT1")
        mock_delete_checks.assert_called_once_with(
            checks=["generic.http.status-argoui-ni4os"],
            namespace="TENANT1"
        )
        mock_delete_events.assert_called_once_with(
            events={
                "argo.ni4os.eu": ["generic.http.status-argoui-ni4os"]
            },
            namespace="TENANT1"
        )
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.http.ar-argoui-ni4os",
                data=json.dumps(self.checks[0]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.certificate.validity",
                data=json.dumps(self.checks[2]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Check generic.certificate.validity "
                f"created",
                f"INFO:{LOGNAME}:TENANT1: Check generic.http.ar-argoui-ni4os "
                f"updated"
            }
        )

    @patch("requests.put")
    @patch("argo_scg.sensu.Sensu._delete_events")
    @patch("argo_scg.sensu.Sensu._delete_checks")
    @patch("argo_scg.sensu.Sensu._get_events")
    @patch("argo_scg.sensu.Sensu._get_checks")
    def test_handle_check_with_changing_handler(
            self, mock_get_checks, mock_get_events, mock_delete_checks,
            mock_delete_events, mock_put
    ):
        check1 = mock_checks[0].copy()
        check1.pop("high_flap_threshold")
        check1.pop("low_flap_threshold")
        check1.pop("runtime_assets")
        check1.pop("proxy_entity_name")
        check1.pop("check_hooks")
        check1.pop("stdin")
        check1.pop("subdue")
        check1.pop("ttl")
        check2 = self.checks[1].copy()
        check2.update({"handlers": ["publisher-handler"]})
        checks = [check1, check2]
        checks2 = [mock_checks[0], mock_checks[1], check2]
        checks3 = [mock_checks[0], check2]
        mock_get_checks.side_effect = [mock_checks, checks2, checks3]
        mock_get_events.return_value = mock_events
        mock_delete_checks.side_effect = mock_delete_response
        mock_delete_events.side_effect = mock_delete_response
        mock_put.side_effect = mock_post_response

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_checks(checks=checks, namespace="TENANT1")

        self.assertEqual(mock_get_checks.call_count, 3)
        mock_get_checks.assert_called_with(namespace="TENANT1")
        mock_get_events.assert_called_once_with(namespace="TENANT1")
        mock_delete_checks.assert_called_once_with(
            checks=["generic.http.status-argoui-ni4os"],
            namespace="TENANT1"
        )
        mock_put.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
            "generic.tcp.connect",
            data=json.dumps(check2),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            log.output, [
                f"INFO:{LOGNAME}:TENANT1: Check generic.tcp.connect updated"
            ]
        )

    @patch("requests.put")
    @patch("argo_scg.sensu.Sensu._delete_events")
    @patch("argo_scg.sensu.Sensu._delete_checks")
    @patch("argo_scg.sensu.Sensu._get_events")
    @patch("argo_scg.sensu.Sensu._get_checks")
    def test_handle_check_with_hardcoded_attributes(
            self, mock_get_checks, mock_get_events, mock_delete_checks,
            mock_delete_events, mock_put
    ):
        checks = [
            {
                "command": "/usr/libexec/argo-monitoring/probes/activemq/"
                           "check_activemq_openwire "
                           "-t 30 --keystoretype jks "
                           "-s monitor.test.$_SERVICESERVER$.$HOSTALIAS$."
                           "openwiressl "
                           "-K {{ .labels.KEYSTORE | default "
                           "/etc/nagios/globus/keystore.jks }} "
                           "-T {{ .labels.TRUSTSTORE | default "
                           "/etc/nagios/globus/truststore.ts }}",
                "subscriptions": ["argo.webui", "argo.test"],
                "handlers": ["publisher-handler"],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.org_activemq_openwiressl == "
                        "'org.activemq.OpenWireSSL'"
                    ]
                },
                "interval": 300,
                "timeout": 30,
                "publish": True,
                "metadata": {
                    "name": "org.activemq.OpenWireSSL",
                    "namespace": "TENANT1"
                },
                "round_robin": True
            },
            {
                "command": "/usr/libexec/argo-monitoring/probes/midmon/"
                           "check_bdii_entries_num "
                           "-t 30 -b Mds-Vo-Name=local,O=grid -c 4:4 "
                           "-f \"(GlueServiceEndpoint=*$HOSTALIAS$*)\" "
                           "-p {{ .labels.BDII_PORT | default 2170 }} "
                           "-H {{ .labels.BDII_HOST }}",
                "subscriptions": ["argo.webui"],
                "handlers": ["publisher-handler"],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.org_nagiosexchange_broker_bdii == "
                        "'org.nagiosexchange.Broker-BDII'"
                    ]
                },
                "interval": 21600,
                "timeout": 30,
                "publish": True,
                "metadata": {
                    "name": "org.nagiosexchange.Broker-BDII",
                    "namespace": "TENANT1"
                },
                "round_robin": True
            }
        ]

        checks2 = [
            mock_checks[0], mock_checks[1], mock_checks[2], checks[0], checks[1]
        ]

        mock_get_checks.side_effect = [mock_checks, checks2, checks]
        mock_get_events.return_value = mock_events
        mock_delete_checks.side_effect = mock_delete_response
        mock_delete_events.side_effect = mock_delete_response
        mock_put.side_effect = mock_post_response

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_checks(checks=checks, namespace="TENANT1")
        self.assertEqual(mock_get_checks.call_count, 3)
        mock_get_checks.assert_called_with(namespace="TENANT1")
        mock_get_events.assert_called_once_with(namespace="TENANT1")
        mock_delete_checks.assert_called_once_with(
            checks=[
                "generic.http.ar-argoui-ni4os",
                "generic.http.status-argoui-ni4os",
                "generic.tcp.connect"
            ],
            namespace="TENANT1"
        )
        mock_delete_events.assert_called_once_with(
            events={
                "argo.ni4os.eu": [
                    "generic.http.ar-argoui-ni4os",
                    "generic.http.status-argoui-ni4os"
                ],
                "gocdb.ni4os.eu": [
                    "generic.tcp.connect"
                ]
            },
            namespace="TENANT1"
        )
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "org.activemq.OpenWireSSL",
                data=json.dumps(checks[0]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "org.nagiosexchange.Broker-BDII",
                data=json.dumps(checks[1]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Check org.activemq.OpenWireSSL "
                f"created",
                f"INFO:{LOGNAME}:TENANT1: Check org.nagiosexchange.Broker-BDII "
                f"created"
            }
        )

    @patch("requests.put")
    @patch("argo_scg.sensu.Sensu._delete_events")
    @patch("argo_scg.sensu.Sensu._delete_checks")
    @patch("argo_scg.sensu.Sensu._get_events")
    @patch("argo_scg.sensu.Sensu._get_checks")
    def test_handle_check_with_file_defined_attributes(
            self, mock_get_checks, mock_get_events, mock_delete_checks,
            mock_delete_events, mock_put
    ):
        checks = [
            {
                "command": "/usr/libexec/argo-monitoring/probes/"
                           "eudat-b2access/check_b2access_simple.py "
                           "-H {{ .labels.hostname }} "
                           "--url https://b2access.fz-juelich.de:8443 "
                           "--username username --password pa55w0rD",
                "subscriptions": ["argo.webui", "argo.test"],
                "handlers": ["publisher-handler"],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.eudat_b2access_unity_login_local == "
                        "'eudat.b2access.unity.login-local'"
                    ]
                },
                "interval": 900,
                "timeout": 120,
                "publish": True,
                "metadata": {
                    "name": "eudat.b2access.unity.login-local",
                    "namespace": "TENANT1"
                },
                "round_robin": True
            },
            {
                "command": "/usr/libexec/grid-monitoring/probes/"
                           "org.qoscosgrid/computing/check_qcg_comp "
                           "-H {{ .labels.hostname }} -t 600 "
                           "-p {{ .labels.QCG-COMPUTING_PORT | "
                           "default 19000 }} -x",
                "subscriptions": ["argo.webui"],
                "handlers": ["publisher-handler"],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.pl_plgrid_qcg_computing == "
                        "'pl.plgrid.QCG-Computing'"
                    ]
                },
                "interval": 1800,
                "timeout": 600,
                "publish": True,
                "metadata": {
                    "name": "pl.plgrid.QCG-Computing",
                    "namespace": "TENANT1"
                },
                "round_robin": True
            }
        ]

        checks2 = [
            mock_checks[0], mock_checks[1], mock_checks[2], checks[0], checks[1]
        ]

        mock_get_checks.side_effect = [mock_checks, checks2, checks]
        mock_get_events.return_value = mock_events
        mock_delete_checks.side_effect = mock_delete_response
        mock_delete_events.side_effect = mock_delete_response
        mock_put.side_effect = mock_post_response

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_checks(checks=checks, namespace="TENANT1")

        self.assertEqual(mock_get_checks.call_count, 3)
        mock_get_checks.assert_called_with(namespace="TENANT1")
        mock_get_events.assert_called_once_with(namespace="TENANT1")
        mock_delete_checks.assert_called_once_with(
            checks=[
                "generic.http.ar-argoui-ni4os",
                "generic.http.status-argoui-ni4os",
                "generic.tcp.connect"
            ],
            namespace="TENANT1"
        )
        mock_delete_events.assert_called_once_with(
            events={
                "argo.ni4os.eu": [
                    "generic.http.ar-argoui-ni4os",
                    "generic.http.status-argoui-ni4os"
                ],
                "gocdb.ni4os.eu": [
                    "generic.tcp.connect"
                ]
            },
            namespace="TENANT1"
        )
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "eudat.b2access.unity.login-local",
                data=json.dumps(checks[0]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "pl.plgrid.QCG-Computing",
                data=json.dumps(checks[1]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ],
            any_order=True
        )

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Check "
                f"eudat.b2access.unity.login-local created",
                f"INFO:{LOGNAME}:TENANT1: Check pl.plgrid.QCG-Computing created"
            }
        )

    @patch("requests.put")
    @patch("argo_scg.sensu.Sensu._delete_events")
    @patch("argo_scg.sensu.Sensu._delete_checks")
    @patch("argo_scg.sensu.Sensu._get_events")
    @patch("argo_scg.sensu.Sensu._get_checks")
    def test_handle_check_with_removing_proxy_requests(
            self, mock_get_checks, mock_get_events, mock_delete_checks,
            mock_delete_events, mock_put
    ):
        mock_checks_small = [mock_checks[0], mock_checks[2]]
        no_proxy_checks = [
            {
                "command": "/usr/lib64/nagios/plugins/check_tcp "
                           "-H {{ .labels.hostname }} -t 120 -p 443",
                "handlers": [],
                "high_flap_threshold": 0,
                "interval": 300,
                "low_flap_threshold": 0,
                "publish": True,
                "runtime_assets": None,
                "subscriptions": ["argo.webui"],
                "proxy_entity_name": "",
                "check_hooks": None,
                "stdin": False,
                "subdue": None,
                "ttl": 0,
                "timeout": 120,
                "round_robin": True,
                "output_metric_format": "",
                "output_metric_handlers": None,
                "env_vars": None,
                "metadata": {
                    "name": "generic.tcp.connect",
                    "namespace": "TENANT1",
                    "created_by": "root"
                },
                "secrets": None,
                "pipelines": []
            }
        ]

        checks2 = [mock_checks[0], no_proxy_checks[0]]
        mock_get_checks.side_effect = [
            mock_checks_small, checks2, no_proxy_checks
        ]
        mock_get_events.return_value = [mock_events[0], mock_events[1]]
        mock_delete_checks.side_effect = mock_delete_response
        mock_delete_events.side_effect = mock_delete_response
        mock_put.side_effect = mock_post_response

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_checks([no_proxy_checks[0]], namespace="TENANT1")

        self.assertEqual(mock_get_checks.call_count, 3)
        mock_get_checks.assert_called_with(namespace="TENANT1")
        mock_get_events.assert_called_once_with(namespace="TENANT1")
        mock_delete_checks.assert_called_once_with(
            checks=["generic.http.ar-argoui-ni4os"],
            namespace="TENANT1"
        )
        mock_delete_events.assert_called_once_with(
            events={
                "argo.ni4os.eu": ["generic.http.ar-argoui-ni4os"]
            },
            namespace="TENANT1"
        )
        mock_put.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
            "generic.tcp.connect",
            data=json.dumps(no_proxy_checks[0]),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            log.output, [
                f"INFO:{LOGNAME}:TENANT1: Check generic.tcp.connect updated"
            ]
        )

    @patch("requests.put")
    @patch("argo_scg.sensu.Sensu._delete_events")
    @patch("argo_scg.sensu.Sensu._delete_checks")
    @patch("argo_scg.sensu.Sensu._get_events")
    @patch("argo_scg.sensu.Sensu._get_checks")
    def test_handle_check_with_changing_handler(
            self, mock_get_checks, mock_get_events, mock_delete_checks,
            mock_delete_events, mock_put
    ):
        check1 = mock_checks[0].copy()
        check1.pop("high_flap_threshold")
        check1.pop("low_flap_threshold")
        check1.pop("runtime_assets")
        check1.pop("proxy_entity_name")
        check1.pop("check_hooks")
        check1.pop("stdin")
        check1.pop("subdue")
        check1.pop("ttl")
        check2 = self.checks[1].copy()
        check2.update({"handlers": ["publisher-handler"]})
        checks = [check1, check2]
        checks2 = [mock_checks[0], mock_checks[1], check2]
        checks3 = [mock_checks[0], check2]
        mock_get_checks.side_effect = [mock_checks, checks2, checks3]
        mock_get_events.return_value = mock_events
        mock_delete_checks.side_effect = mock_delete_response
        mock_delete_events.side_effect = mock_delete_response
        mock_put.side_effect = mock_post_response

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_checks(checks=checks, namespace="TENANT1")

        self.assertEqual(mock_get_checks.call_count, 3)
        mock_get_checks.assert_called_with(namespace="TENANT1")
        mock_get_events.assert_called_once_with(namespace="TENANT1")
        mock_delete_checks.assert_called_once_with(
            checks=["generic.http.status-argoui-ni4os"],
            namespace="TENANT1"
        )
        mock_put.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
            "generic.tcp.connect",
            data=json.dumps(check2),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            log.output, [
                f"INFO:{LOGNAME}:TENANT1: Check generic.tcp.connect updated"
            ]
        )

    @patch("requests.put")
    @patch("argo_scg.sensu.Sensu._delete_events")
    @patch("argo_scg.sensu.Sensu._delete_checks")
    @patch("argo_scg.sensu.Sensu._get_events")
    @patch("argo_scg.sensu.Sensu._get_checks")
    def test_handle_checks_with_error_in_put_check_with_msg(
            self, mock_get_checks, mock_get_events, mock_delete_checks,
            mock_delete_events, mock_put
    ):
        checks2 = [
            mock_checks[0], mock_checks[1], mock_checks[2], self.checks[2]
        ]
        checks3 = [checks2[0], checks2[2], checks2[3]]
        mock_get_checks.side_effect = [mock_checks, checks2, checks3]
        mock_get_events.return_value = mock_events
        mock_delete_checks.side_effect = mock_delete_response
        mock_delete_events.side_effect = mock_delete_response
        mock_put.side_effect = [
            MockResponse(None, status_code=200),
            MockResponse({"message": "Something went wrong."}, status_code=400)
        ]

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_checks(checks=self.checks, namespace="TENANT1")

        self.assertEqual(mock_get_checks.call_count, 3)
        mock_get_checks.assert_called_with(namespace="TENANT1")
        mock_get_events.assert_called_once_with(namespace="TENANT1")
        mock_delete_checks.assert_called_once_with(
            checks=["generic.http.status-argoui-ni4os"],
            namespace="TENANT1"
        )
        mock_delete_events.assert_called_once_with(
            events={
                "argo.ni4os.eu": ["generic.http.status-argoui-ni4os"]
            },
            namespace="TENANT1"
        )
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.http.ar-argoui-ni4os",
                data=json.dumps(self.checks[0]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.certificate.validity",
                data=json.dumps(self.checks[2]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"WARNING:{LOGNAME}:TENANT1: Check "
                f"generic.certificate.validity not created: "
                f"400 BAD REQUEST: Something went wrong.",
                f"INFO:{LOGNAME}:TENANT1: Check generic.http.ar-argoui-ni4os "
                f"updated"
            }
        )

    @patch("requests.put")
    @patch("argo_scg.sensu.Sensu._delete_events")
    @patch("argo_scg.sensu.Sensu._delete_checks")
    @patch("argo_scg.sensu.Sensu._get_events")
    @patch("argo_scg.sensu.Sensu._get_checks")
    def test_handle_checks_with_error_in_put_check_without_msg(
            self, mock_get_checks, mock_get_events, mock_delete_checks,
            mock_delete_events, mock_put
    ):
        checks2 = [
            mock_checks[0], mock_checks[1], mock_checks[2], self.checks[2]
        ]
        checks3 = [checks2[0], checks2[2], checks2[3]]
        mock_get_checks.side_effect = [mock_checks, checks2, checks3]
        mock_get_events.return_value = mock_events
        mock_delete_checks.side_effect = mock_delete_response
        mock_delete_events.side_effect = mock_delete_response
        mock_put.side_effect = [
            MockResponse(None, status_code=200),
            MockResponse(None, status_code=400)
        ]

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_checks(checks=self.checks, namespace="TENANT1")

        self.assertEqual(mock_get_checks.call_count, 3)
        mock_get_checks.assert_called_with(namespace="TENANT1")
        mock_get_events.assert_called_once_with(namespace="TENANT1")
        mock_delete_checks.assert_called_once_with(
            checks=["generic.http.status-argoui-ni4os"],
            namespace="TENANT1"
        )
        mock_delete_events.assert_called_once_with(
            events={
                "argo.ni4os.eu": ["generic.http.status-argoui-ni4os"]
            },
            namespace="TENANT1"
        )
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.http.ar-argoui-ni4os",
                data=json.dumps(self.checks[0]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/checks/"
                "generic.certificate.validity",
                data=json.dumps(self.checks[2]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"WARNING:{LOGNAME}:TENANT1: Check "
                f"generic.certificate.validity not created: "
                f"400 BAD REQUEST",
                f"INFO:{LOGNAME}:TENANT1: Check generic.http.ar-argoui-ni4os "
                f"updated"
            }
        )


class SensuEventsTests(unittest.TestCase):
    def setUp(self):
        self.sensu = Sensu(url="mock-urls", token="t0k3n")

    @patch("requests.get")
    def test_get_events(self, mock_get):
        mock_get.side_effect = mock_sensu_request
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = self.sensu._get_events(namespace="TENANT1")
        self.assertEqual(checks, mock_events)
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.get")
    def test_get_events_with_error_with_messsage(self, mock_get):
        mock_get.side_effect = mock_sensu_request_events_not_ok_with_msg

        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_events(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/events",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Events fetch error: 400 BAD REQUEST: "
            "Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"WARNING:{LOGNAME}:TENANT1: Events fetch error: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.get")
    def test_get_events_with_error_without_messsage(self, mock_get):
        mock_get.side_effect = mock_sensu_request_events_not_ok_without_msg

        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_events(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/events",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Events fetch error: 400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"WARNING:{LOGNAME}:TENANT1: Events fetch error: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.delete")
    def test_delete_events(self, mock_delete):
        mock_delete.side_effect = mock_delete_response
        with self.assertLogs(LOGNAME) as log:
            self.sensu._delete_events(
                events={
                    "argo.ni4os.eu": [
                        "generic.tcp.connect",
                        "generic.http.connect"
                    ],
                    "argo-devel.ni4os.eu": ["generic.certificate.validation"]
                },
                namespace="TENANT1"
            )

        self.assertEqual(mock_delete.call_count, 3)
        mock_delete.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/events/argo.ni4os.eu/"
                "generic.tcp.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/events/argo.ni4os.eu/"
                "generic.http.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/events/"
                "argo-devel.ni4os.eu/generic.certificate.validation",
                headers={
                    "Authorization": "Key t0k3n"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Event "
                f"argo-devel.ni4os.eu/generic.certificate.validation removed",
                f"INFO:{LOGNAME}:TENANT1: Event "
                f"argo.ni4os.eu/generic.http.connect removed",
                f"INFO:{LOGNAME}:TENANT1: Event "
                f"argo.ni4os.eu/generic.tcp.connect removed"
            }
        )

    @patch("requests.delete")
    def test_delete_events_with_error_with_message(self, mock_delete):
        mock_delete.side_effect = [
            MockResponse(None, status_code=204),
            MockResponse({"message": "Something went wrong."}, status_code=400)
        ]
        with self.assertLogs(LOGNAME) as log:
            self.sensu._delete_events(
                events={
                    "argo.ni4os.eu": [
                        "generic.tcp.connect",
                        "generic.http.connect"
                    ]
                },
                namespace="TENANT1"
            )

        self.assertEqual(mock_delete.call_count, 2)
        mock_delete.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/events/argo.ni4os.eu/"
                "generic.tcp.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/events/argo.ni4os.eu/"
                "generic.http.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Event "
                f"argo.ni4os.eu/generic.tcp.connect removed",
                f"WARNING:{LOGNAME}:TENANT1: Event "
                f"argo.ni4os.eu/generic.http.connect not removed: "
                f"400 BAD REQUEST: Something went wrong."
            }
        )

    @patch("requests.delete")
    def test_delete_events_with_error_without_message(self, mock_delete):
        mock_delete.side_effect = [
            MockResponse(None, status_code=204),
            MockResponse(None, status_code=400)
        ]
        with self.assertLogs(LOGNAME) as log:
            self.sensu._delete_events(
                events={
                    "argo.ni4os.eu": [
                        "generic.tcp.connect",
                        "generic.http.connect"
                    ]
                },
                namespace="TENANT1"
            )

        self.assertEqual(mock_delete.call_count, 2)
        mock_delete.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/events/argo.ni4os.eu/"
                "generic.tcp.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/events/argo.ni4os.eu/"
                "generic.http.connect",
                headers={
                    "Authorization": "Key t0k3n"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Event "
                f"argo.ni4os.eu/generic.tcp.connect removed",
                f"WARNING:{LOGNAME}:TENANT1: Event "
                f"argo.ni4os.eu/generic.http.connect not removed: "
                f"400 BAD REQUEST"
            }
        )


class SensuEntityTests(unittest.TestCase):
    def setUp(self):
        self.sensu = Sensu(url="mock-urls", token="t0k3n")
        self.entities = [
            {
                "entity_class": "proxy",
                "metadata": {
                    "name": "argo-devel.ni4os.eu",
                    "namespace": "TENANT1",
                    "labels": {
                        "generic_http_ar_argoui_ni4os":
                            "generic.http.ar-argoui-ni4os",
                        "generic_http_connect": "generic.http.connect",
                        "generic_certificate_validity":
                            "generic.certificate.validity",
                        "generic_tcp_connect": "generic.tcp.connect",
                        "hostname": "argo-devel.ni4os.eu"
                    },
                },
                "subscriptions": [
                    "argo.webui",
                    "argo-test.web"
                ]
            },
            {
                "entity_class": "proxy",
                "metadata": {
                    "name": "argo.ni4os.eu",
                    "namespace": "TENANT1",
                    "labels": {
                        "generic_http_connect": "generic.http.connect",
                        "hostname": "argo.ni4os.eu"
                    }
                },
                "subscriptions": [
                    "argo.webui"
                ]
            },
            {
                "entity_class": "proxy",
                "metadata": {
                    "name": "argo-mon.ni4os.eu",
                    "namespace": "TENANT1",
                    "labels": {
                        "generic_tcp_connect": "generic.tcp.connect",
                        "hostname": "argo-mon.ni4os.eu"
                    }
                },
                "subscriptions": [
                    "argo.mon"
                ]
            }
        ]

    @patch("requests.get")
    def test_get_proxy_entities(self, mock_get):
        mock_get.side_effect = mock_sensu_request
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = self.sensu._get_proxy_entities(namespace="TENANT1")
        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/entities",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            mock_entities[:-2]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.get")
    def test_get_proxy_entities_with_error_with_message(self, mock_get):
        mock_get.side_effect = mock_sensu_request_entity_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_proxy_entities(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/entities",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Error fetching proxy entities: "
            "400 BAD REQUEST: Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Error fetching proxy entities: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.get")
    def test_get_proxy_entities_with_error_without_message(self, mock_get):
        mock_get.side_effect = mock_sensu_request_entity_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_proxy_entities(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/entities",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Error fetching proxy entities: "
            "400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Error fetching proxy entities: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.delete")
    def test_delete_entities(self, mock_delete):
        mock_delete.side_effect = mock_delete_response
        entities = ["argo.ni4os.eu", "argo-devel.ni4os.eu", "gocdb.ni4os.eu"]

        with self.assertLogs(LOGNAME) as log:
            self.sensu._delete_entities(entities=entities, namespace="TENANT1")

        self.assertEqual(mock_delete.call_count, 3)
        mock_delete.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo.ni4os.eu",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo-devel.ni4os.eu",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "gocdb.ni4os.eu",
                headers={
                    "Authorization": "Key t0k3n"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Entity argo.ni4os.eu removed",
                f"INFO:{LOGNAME}:TENANT1: Entity argo-devel.ni4os.eu removed",
                f"INFO:{LOGNAME}:TENANT1: Entity gocdb.ni4os.eu removed"
            }
        )

    @patch("requests.delete")
    def test_delete_entities_with_error_with_message(self, mock_delete):
        mock_delete.side_effect = [
            MockResponse(None, status_code=204),
            MockResponse({"message": "Something went wrong."}, status_code=400),
            MockResponse(None, status_code=204)
        ]
        entities = ["argo.ni4os.eu", "argo-devel.ni4os.eu", "gocdb.ni4os.eu"]
        with self.assertLogs(LOGNAME) as log:
            self.sensu._delete_entities(entities=entities, namespace="TENANT1")

        self.assertEqual(mock_delete.call_count, 3)
        mock_delete.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo.ni4os.eu",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo-devel.ni4os.eu",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "gocdb.ni4os.eu",
                headers={
                    "Authorization": "Key t0k3n"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Entity argo.ni4os.eu removed",
                f"WARNING:{LOGNAME}:TENANT1: Entity argo-devel.ni4os.eu "
                f"not removed: 400 BAD REQUEST: Something went wrong.",
                f"INFO:{LOGNAME}:TENANT1: Entity gocdb.ni4os.eu removed"
            }
        )

    @patch("requests.delete")
    def test_delete_entities_with_error_without_message(self, mock_delete):
        mock_delete.side_effect = [
            MockResponse(None, status_code=204),
            MockResponse(None, status_code=400),
            MockResponse(None, status_code=204)
        ]
        entities = ["argo.ni4os.eu", "argo-devel.ni4os.eu", "gocdb.ni4os.eu"]
        with self.assertLogs(LOGNAME) as log:
            self.sensu._delete_entities(entities=entities, namespace="TENANT1")

        self.assertEqual(mock_delete.call_count, 3)
        mock_delete.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo.ni4os.eu",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo-devel.ni4os.eu",
                headers={
                    "Authorization": "Key t0k3n"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "gocdb.ni4os.eu",
                headers={
                    "Authorization": "Key t0k3n"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Entity argo.ni4os.eu removed",
                f"WARNING:{LOGNAME}:TENANT1: Entity argo-devel.ni4os.eu not "
                f"removed: 400 BAD REQUEST",
                f"INFO:{LOGNAME}:TENANT1: Entity gocdb.ni4os.eu removed"
            }
        )

    @patch("requests.put")
    @patch("argo_scg.sensu.Sensu._delete_entities")
    @patch("argo_scg.sensu.Sensu._get_proxy_entities")
    def test_handle_proxy_entities(
            self, mock_get_entities, mock_delete_entities, mock_put
    ):
        mock_get_entities.return_value = mock_entities[:-2]
        mock_delete_entities.side_effect = mock_delete_response
        mock_put.side_effect = mock_post_response

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_proxy_entities(
                entities=self.entities, namespace="TENANT1"
            )

        mock_get_entities.assert_called_once_with(namespace="TENANT1")
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo-devel.ni4os.eu",
                data=json.dumps(self.entities[0]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo-mon.ni4os.eu",
                data=json.dumps(self.entities[2]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)

        mock_delete_entities.assert_called_once_with(
            entities=["gocdb.ni4os.eu"],
            namespace="TENANT1"
        )

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Entity argo-mon.ni4os.eu created",
                f"INFO:{LOGNAME}:TENANT1: Entity argo-devel.ni4os.eu updated"
            }
        )

    @patch("requests.put")
    @patch("argo_scg.sensu.Sensu._delete_entities")
    @patch("argo_scg.sensu.Sensu._get_proxy_entities")
    def test_handle_proxy_entities_with_error_with_msg(
            self, mock_get_entities, mock_delete_entities, mock_put
    ):
        mock_get_entities.return_value = mock_entities[:-2]
        mock_delete_entities.side_effect = mock_delete_response
        mock_put.side_effect = [
            MockResponse(None, status_code=201),
            MockResponse({"message": "Something went wrong."}, status_code=400)
        ]

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_proxy_entities(
                entities=self.entities, namespace="TENANT1"
            )

        mock_get_entities.assert_called_once_with(namespace="TENANT1")
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo-devel.ni4os.eu",
                data=json.dumps(self.entities[0]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo-mon.ni4os.eu",
                data=json.dumps(self.entities[2]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)

        mock_delete_entities.assert_called_once_with(
            entities=["gocdb.ni4os.eu"],
            namespace="TENANT1"
        )

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Entity argo-devel.ni4os.eu updated",
                f"WARNING:{LOGNAME}:TENANT1: Proxy entity argo-mon.ni4os.eu "
                f"not created: 400 BAD REQUEST: Something went wrong."
            }
        )

    @patch("requests.put")
    @patch("argo_scg.sensu.Sensu._delete_entities")
    @patch("argo_scg.sensu.Sensu._get_proxy_entities")
    def test_handle_proxy_entities_with_error_without_msg(
            self, mock_get_entities, mock_delete_entities, mock_put
    ):
        mock_get_entities.return_value = mock_entities[:-2]
        mock_delete_entities.side_effect = mock_delete_response
        mock_put.side_effect = [
            MockResponse(None, status_code=201),
            MockResponse(None, status_code=400)
        ]

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_proxy_entities(
                entities=self.entities, namespace="TENANT1"
            )

        mock_get_entities.assert_called_once_with(namespace="TENANT1")
        self.assertEqual(mock_put.call_count, 2)
        mock_put.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo-devel.ni4os.eu",
                data=json.dumps(self.entities[0]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/"
                "argo-mon.ni4os.eu",
                data=json.dumps(self.entities[2]),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/json"
                }
            )
        ], any_order=True)

        mock_delete_entities.assert_called_once_with(
            entities=["gocdb.ni4os.eu"],
            namespace="TENANT1"
        )

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: Entity argo-devel.ni4os.eu updated",
                f"WARNING:{LOGNAME}:TENANT1: Proxy entity argo-mon.ni4os.eu "
                f"not created: 400 BAD REQUEST"
            }
        )


class SensuAgentsTests(unittest.TestCase):
    def setUp(self):
        self.sensu = Sensu(url="mock-urls", token="t0k3n")

    @patch("requests.get")
    def test_get_agents(self, mock_get):
        mock_get.side_effect = mock_sensu_request
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            agents = self.sensu._get_agents(namespace="TENANT1")
        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/entities",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            agents, [mock_entities[3], mock_entities[4]]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.get")
    def test_get_agents_with_error_with_message(self, mock_get):
        mock_get.side_effect = mock_sensu_request_entity_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_agents(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/entities",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Error fetching agents: 400 BAD REQUEST: "
            "Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Error fetching agents: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.get")
    def test_get_agents_with_error_without_message(self, mock_get):
        mock_get.side_effect = mock_sensu_request_entity_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_agents(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/entities",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Error fetching agents: 400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Error fetching agents: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.patch")
    @patch("argo_scg.sensu.Sensu._get_agents")
    def test_handle_agents_with_only_subscriptions(self, mock_get, mock_patch):
        mock_get.return_value = [mock_entities[3], mock_entities[4]]
        mock_patch.side_effect = mock_post_response

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_agents(
                metric_parameters_overrides=dict(),
                host_attributes_overrides=list(),
                subscriptions=["argo.webui", "argo.test"],
                namespace="TENANT1"
            )

        self.assertEqual(mock_patch.call_count, 2)
        mock_patch.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/sensu-"
                "agent1",
                data=json.dumps({
                    "subscriptions": [
                        "entity:sensu-agent1",
                        "argo.webui",
                        "eu.ni4os.ops.gocdb",
                        "argo.test"
                    ]
                }),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/merge-patch+json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/sensu-"
                "agent2",
                data=json.dumps({
                    "subscriptions": [
                        "argo.webui",
                        "entity:sensu-agent2",
                        "eu.ni4os.ops.gocdb",
                        "argo.test"
                    ],
                    "metadata": {
                        "labels": {
                            "hostname": "sensu-agent2"
                        }
                    }
                }),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/merge-patch+json"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: sensu-agent1 subscriptions updated",
                f"INFO:{LOGNAME}:TENANT1: sensu-agent2 subscriptions updated",
                f"INFO:{LOGNAME}:TENANT1: sensu-agent2 labels updated"
            }
        )

    @patch("requests.patch")
    @patch("argo_scg.sensu.Sensu._get_agents")
    def test_add_subscriptions_to_agents_with_error_in_patch_with_msg(
            self, mock_get, mock_patch
    ):
        mock_get.return_value = [mock_entities[3], mock_entities[4]]
        mock_patch.side_effect = [
            MockResponse(None, status_code=200),
            MockResponse({"message": "Something went wrong."}, status_code=400)
        ]

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_agents(
                metric_parameters_overrides=dict(),
                host_attributes_overrides=list(),
                subscriptions=["argo.webui", "argo.test"],
                namespace="TENANT1"
            )

        self.assertEqual(mock_patch.call_count, 2)
        mock_patch.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/sensu-"
                "agent1",
                data=json.dumps({
                    "subscriptions": [
                        "entity:sensu-agent1",
                        "argo.webui",
                        "eu.ni4os.ops.gocdb",
                        "argo.test"
                    ]
                }),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/merge-patch+json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/sensu-"
                "agent2",
                data=json.dumps({
                    "subscriptions": [
                        "argo.webui",
                        "entity:sensu-agent2",
                        "eu.ni4os.ops.gocdb",
                        "argo.test"
                    ],
                    "metadata": {
                        "labels": {
                            "hostname": "sensu-agent2"
                        }
                    }
                }),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/merge-patch+json"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: sensu-agent1 subscriptions updated",
                f"ERROR:{LOGNAME}:TENANT1: sensu-agent2 not updated: "
                f"400 BAD REQUEST: Something went wrong."
            }
        )

    @patch("requests.patch")
    @patch("argo_scg.sensu.Sensu._get_agents")
    def test_add_subscriptions_to_agents_with_error_in_patch_without_msg(
            self, mock_get, mock_patch
    ):
        mock_get.return_value = [mock_entities[3], mock_entities[4]]
        mock_patch.side_effect = [
            MockResponse(None, status_code=200),
            MockResponse(None, status_code=400)
        ]

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_agents(
                metric_parameters_overrides=dict(),
                host_attributes_overrides=list(),
                subscriptions=["argo.webui", "argo.test"],
                namespace="TENANT1"
            )

        self.assertEqual(mock_patch.call_count, 2)
        mock_patch.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/sensu-"
                "agent1",
                data=json.dumps({
                    "subscriptions": [
                        "entity:sensu-agent1",
                        "argo.webui",
                        "eu.ni4os.ops.gocdb",
                        "argo.test"
                    ]
                }),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/merge-patch+json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/sensu-"
                "agent2",
                data=json.dumps({
                    "subscriptions": [
                        "argo.webui",
                        "entity:sensu-agent2",
                        "eu.ni4os.ops.gocdb",
                        "argo.test"
                    ],
                    "metadata": {
                        "labels": {
                            "hostname": "sensu-agent2"
                        }
                    }
                }),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/merge-patch+json"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: sensu-agent1 subscriptions updated",
                f"ERROR:{LOGNAME}:TENANT1: sensu-agent2 not updated: "
                f"400 BAD REQUEST"
            }
        )

    @patch("requests.patch")
    @patch("argo_scg.sensu.Sensu._get_agents")
    def test_handle_agents_with_metric_parameter_overrides(
            self, mock_get, mock_patch
    ):
        mock_get.return_value = [mock_entities[3], mock_entities[4]]
        mock_patch.side_effect = mock_post_response

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_agents(
                metric_parameters_overrides={
                    "generic.tcp.connect": {
                        "hostname": "sensu-agent1",
                        "label": "generic_tcp_connect_p",
                        "value": "80"
                    }
                },
                host_attributes_overrides=list(),
                subscriptions=["argo.webui", "argo.test"],
                namespace="TENANT1"
            )

        self.assertEqual(mock_patch.call_count, 2)
        mock_patch.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/sensu-"
                "agent1",
                data=json.dumps({
                    "subscriptions": [
                        "entity:sensu-agent1",
                        "argo.webui",
                        "eu.ni4os.ops.gocdb",
                        "argo.test"
                    ],
                    "metadata": {
                        "labels": {
                            "hostname": "sensu-agent1",
                            "generic_tcp_connect_p": "80"
                        }
                    }
                }),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/merge-patch+json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/sensu-"
                "agent2",
                data=json.dumps({
                    "subscriptions": [
                        "argo.webui",
                        "entity:sensu-agent2",
                        "eu.ni4os.ops.gocdb",
                        "argo.test"
                    ],
                    "metadata": {
                        "labels": {
                            "hostname": "sensu-agent2"
                        }
                    }
                }),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/merge-patch+json"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: sensu-agent1 subscriptions updated",
                f"INFO:{LOGNAME}:TENANT1: sensu-agent1 labels updated",
                f"INFO:{LOGNAME}:TENANT1: sensu-agent2 subscriptions updated",
                f"INFO:{LOGNAME}:TENANT1: sensu-agent2 labels updated"
            }
        )

    @patch("requests.patch")
    @patch("argo_scg.sensu.Sensu._get_agents")
    def test_handle_agents_with_host_attributes(self, mock_get, mock_patch):
        mock_get.return_value = [mock_entities[3], mock_entities[4]]
        mock_patch.side_effect = mock_post_response

        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_agents(
                metric_parameters_overrides=dict(),
                host_attributes_overrides=[{
                    "hostname": "sensu-agent1",
                    "attribute": "NAGIOS_FRESHNESS_USERNAME",
                    "value": "$NI4OS_NAGIOS_FRESHNESS_USERNAME"
                }, {
                    "hostname": "sensu-agent1",
                    "attribute": "NAGIOS_FRESHNESS_PASSWORD",
                    "value": "NI4OS_NAGIOS_FRESHNESS_PASSWORD"
                }],
                subscriptions=["argo.webui", "argo.test"],
                namespace="TENANT1"
            )

        self.assertEqual(mock_patch.call_count, 2)

        mock_patch.assert_has_calls([
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/sensu-"
                "agent1",
                data=json.dumps({
                    "subscriptions": [
                        "entity:sensu-agent1",
                        "argo.webui",
                        "eu.ni4os.ops.gocdb",
                        "argo.test"
                    ],
                    "metadata": {
                        "labels": {
                            "hostname": "sensu-agent1",
                            "nagios_freshness_username":
                                "$NI4OS_NAGIOS_FRESHNESS_USERNAME",
                            "nagios_freshness_password":
                                "$NI4OS_NAGIOS_FRESHNESS_PASSWORD",
                        }
                    }
                }),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/merge-patch+json"
                }
            ),
            call(
                "mock-urls/api/core/v2/namespaces/TENANT1/entities/sensu-"
                "agent2",
                data=json.dumps({
                    "subscriptions": [
                        "argo.webui",
                        "entity:sensu-agent2",
                        "eu.ni4os.ops.gocdb",
                        "argo.test"
                    ],
                    "metadata": {
                        "labels": {
                            "hostname": "sensu-agent2"
                        }
                    }
                }),
                headers={
                    "Authorization": "Key t0k3n",
                    "Content-Type": "application/merge-patch+json"
                }
            )
        ], any_order=True)

        self.assertEqual(
            set(log.output), {
                f"INFO:{LOGNAME}:TENANT1: sensu-agent1 subscriptions updated",
                f"INFO:{LOGNAME}:TENANT1: sensu-agent1 labels updated",
                f"INFO:{LOGNAME}:TENANT1: sensu-agent2 subscriptions updated",
                f"INFO:{LOGNAME}:TENANT1: sensu-agent2 labels updated"
            }
        )


class SensuHandlersTests(unittest.TestCase):
    def setUp(self):
        self.sensu = Sensu(url="mock-urls", token="t0k3n")
        self.publisher_handler = {
            "metadata": {
                "name": "publisher-handler",
                "namespace": "TENANT1"
            },
            "type": "pipe",
            "command": "/bin/sensu2publisher.py"
        }
        self.slack_handler = {
            "metadata": {
                "name": "slack",
                "namespace": "TENANT1"
            },
            "type": "pipe",
            "command": "source /etc/sensu/secrets ; "
                       "export $(cut -d= -f1 /etc/sensu/secrets) ; "
                       "sensu-slack-handler --channel '#monitoring'",
            "runtime_assets": ["sensu-slack-handler"]
        }

    @patch("requests.get")
    def test_get_handlers(self, mock_get):
        mock_get.side_effect = mock_sensu_request
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            handlers = self.sensu._get_handlers(namespace="TENANT1")
        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(handlers, mock_handlers1)
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.get")
    def test_get_handlers_with_error_with_message(self, mock_get):
        mock_get.side_effect = mock_sensu_request_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_handlers(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Handlers fetch error: 400 BAD REQUEST: "
            "Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Handlers fetch error: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.get")
    def test_get_handlers_with_error_without_message(self, mock_get):
        mock_get.side_effect = mock_sensu_request_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_handlers(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers",
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Handlers fetch error: 400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Handlers fetch error: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_publisher_handler(self, mock_get_handlers, mock_post):
        mock_get_handlers.return_value = mock_handlers1
        mock_post.side_effect = mock_post_response
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_publisher_handler(namespace="TENANT1")

        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers",
            data=json.dumps(self.publisher_handler),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            log.output, [f"INFO:{LOGNAME}:TENANT1: publisher-handler created"]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_publisher_handler_with_error_with_msg(
            self, mock_get_handlers, mock_post
    ):
        mock_get_handlers.return_value = mock_handlers1
        mock_post.side_effect = mock_post_response_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.handle_publisher_handler(namespace="TENANT1")

        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers",
            data=json.dumps(self.publisher_handler),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: publisher-handler create error: "
            "400 BAD REQUEST: Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: publisher-handler create error: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_publisher_handler_with_error_without_msg(
            self, mock_get_handlers, mock_post
    ):
        mock_get_handlers.return_value = mock_handlers1
        mock_post.side_effect = mock_post_response_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.handle_publisher_handler(namespace="TENANT1")

        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers",
            data=json.dumps(self.publisher_handler),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: publisher-handler create error: "
            "400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: publisher-handler create error: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_publisher_handler_if_exists_and_same(
            self, mock_get_handlers, mock_post
    ):
        mock_get_handlers.return_value = mock_handlers2
        mock_post.side_effect = mock_post_response
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            self.sensu.handle_publisher_handler(namespace="TENANT1")
        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        self.assertFalse(mock_post.called)
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.patch")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_publisher_handler_if_exists_and_different(
            self, mock_get_handlers, mock_patch
    ):
        mock_get_handlers.return_value = mock_handlers3
        mock_patch.side_effect = mock_post_response
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_publisher_handler(namespace="TENANT1")
        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_patch.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers/"
            "publisher-handler",
            data=json.dumps({
                "command": "/bin/sensu2publisher.py"
            }),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/merge-patch+json"
            }
        )
        self.assertEqual(
            log.output, [
                f"INFO:{LOGNAME}:TENANT1: publisher-handler updated"
            ]
        )

    @patch("requests.patch")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_publisher_handler_if_exists_and_different_with_err_with_msg(
            self, mock_get_handlers, mock_patch
    ):
        mock_get_handlers.return_value = mock_handlers3
        mock_patch.side_effect = mock_post_response_not_ok_with_msg
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_publisher_handler(namespace="TENANT1")
        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_patch.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers/"
            "publisher-handler",
            data=json.dumps({
                "command": "/bin/sensu2publisher.py"
            }),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/merge-patch+json"
            }
        )
        self.assertEqual(
            log.output, [
                f"WARNING:{LOGNAME}:TENANT1: publisher-handler not updated: "
                f"400 BAD REQUEST: Something went wrong.",
            ]
        )

    @patch("requests.patch")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_publisher_handler_if_exists_and_different_with_err_no_msg(
            self, mock_get_handlers, mock_patch
    ):
        mock_get_handlers.return_value = mock_handlers3
        mock_patch.side_effect = mock_post_response_not_ok_without_msg
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_publisher_handler(namespace="TENANT1")
        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_patch.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers/"
            "publisher-handler",
            data=json.dumps({
                "command": "/bin/sensu2publisher.py"
            }),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/merge-patch+json"
            }
        )
        self.assertEqual(
            log.output, [
                f"WARNING:{LOGNAME}:TENANT1: publisher-handler not updated: "
                f"400 BAD REQUEST",
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_slack_handler(self, mock_get_handlers, mock_post):
        mock_get_handlers.return_value = mock_handlers1
        mock_post.side_effect = mock_post_response
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_slack_handler(
                secrets_file="/etc/sensu/secrets", namespace="TENANT1"
            )
        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers",
            data=json.dumps(self.slack_handler),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            log.output, [f"INFO:{LOGNAME}:TENANT1: slack-handler created"]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_slack_handler_with_error_with_msg(
            self, mock_get_handlers, mock_post
    ):
        mock_get_handlers.return_value = mock_handlers1
        mock_post.side_effect = mock_post_response_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.handle_slack_handler(
                    secrets_file="/etc/sensu/secrets", namespace="TENANT1"
                )
        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers",
            data=json.dumps(self.slack_handler),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: slack-handler create error: "
            "400 BAD REQUEST: Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: slack-handler create error: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_slack_handler_with_error_without_msg(
            self, mock_get_handlers, mock_post
    ):
        mock_get_handlers.return_value = mock_handlers1
        mock_post.side_effect = mock_post_response_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.handle_slack_handler(
                    secrets_file="/etc/sensu/secrets", namespace="TENANT1"
                )
        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers",
            data=json.dumps(self.slack_handler),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: slack-handler create error: "
            "400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: slack-handler create error: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_slack_handler_if_exists_and_same(
            self, mock_get_handlers, mock_post
    ):
        mock_get_handlers.return_value = mock_handlers2
        mock_post.side_effect = mock_post_response
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            self.sensu.handle_slack_handler(
                secrets_file="/etc/sensu/secrets", namespace="TENANT1"
            )
        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        self.assertFalse(mock_post.called)
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.patch")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_slack_handler_if_exists_and_different(
            self, mock_get_handlers, mock_patch
    ):
        mock_get_handlers.return_value = mock_handlers3
        mock_patch.side_effect = mock_post_response
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_slack_handler(
                secrets_file="/etc/sensu/secrets", namespace="TENANT1"
            )
        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_patch.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers/slack",
            data=json.dumps({
                "command": "source /etc/sensu/secrets ; "
                           "export $(cut -d= -f1 /etc/sensu/secrets) ; "
                           "sensu-slack-handler --channel '#monitoring'"
            }),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/merge-patch+json"
            }
        )
        self.assertEqual(
            log.output, [f"INFO:{LOGNAME}:TENANT1: slack-handler updated"]
        )

    @patch("requests.patch")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_slack_handler_if_exists_and_different_with_err_with_msg(
            self, mock_get_handlers, mock_patch
    ):
        mock_get_handlers.return_value = mock_handlers3
        mock_patch.side_effect = mock_post_response_not_ok_with_msg
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_slack_handler(
                secrets_file="/etc/sensu/secrets", namespace="TENANT1"
            )
        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_patch.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers/slack",
            data=json.dumps({
                "command": "source /etc/sensu/secrets ; "
                           "export $(cut -d= -f1 /etc/sensu/secrets) ; "
                           "sensu-slack-handler --channel '#monitoring'"
            }),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/merge-patch+json"
            }
        )
        self.assertEqual(
            log.output, [
                f"WARNING:{LOGNAME}:TENANT1: slack-handler not updated: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.patch")
    @patch("argo_scg.sensu.Sensu._get_handlers")
    def test_handle_slack_handler_if_exists_and_different_with_err_without_msg(
            self, mock_get_handlers, mock_patch
    ):
        mock_get_handlers.return_value = mock_handlers3
        mock_patch.side_effect = mock_post_response_not_ok_without_msg
        with self.assertLogs(LOGNAME) as log:
            self.sensu.handle_slack_handler(
                secrets_file="/etc/sensu/secrets", namespace="TENANT1"
            )
        mock_get_handlers.assert_called_once_with(namespace="TENANT1")
        mock_patch.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/handlers/slack",
            data=json.dumps({
                "command": "source /etc/sensu/secrets ; "
                           "export $(cut -d= -f1 /etc/sensu/secrets) ; "
                           "sensu-slack-handler --channel '#monitoring'"
            }),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/merge-patch+json"
            }
        )
        self.assertEqual(
            log.output, [
                f"WARNING:{LOGNAME}:TENANT1: slack-handler not updated: "
                "400 BAD REQUEST"
            ]
        )


class SensuFiltersTests(unittest.TestCase):
    def setUp(self):
        self.sensu = Sensu(url="mock-urls", token="t0k3n")
        self.daily = {
            "metadata": {
                "name": "daily",
                "namespace": "TENANT1"
            },
            "action": "allow",
            "expressions": [
                "((event.check.occurrences == 1 && event.check.status == 0 && "
                "event.check.occurrences_watermark >= "
                "Number(event.check.annotations.attempts)) || "
                "(event.check.occurrences == "
                "Number(event.check.annotations.attempts) "
                "&& event.check.status != 0)) || "
                "event.check.occurrences % "
                "(86400 / event.check.interval) == 0"
            ]
        }
        self.hard = {
            "metadata": {
                "name": "hard-state",
                "namespace": "TENANT1"
            },
            "action": "allow",
            "expressions": [
                "((event.check.status == 0) || (event.check.occurrences >= "
                "Number(event.check.annotations.attempts) "
                "&& event.check.status != 0))"
            ]
        }

    @patch("requests.get")
    def test_get_filters(self, mock_get):
        mock_get.side_effect = mock_sensu_request
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            filters = self.sensu._get_filters(namespace="TENANT1")
        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/filters",
            headers={
                "Authorization": "Key t0k3n"
            }
        )
        self.assertEqual(filters, mock_filters1)
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.get")
    def test_get_filters_with_error_with_msg(self, mock_get):
        mock_get.side_effect = mock_sensu_request_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_filters(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/filters",
            headers={
                "Authorization": "Key t0k3n"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Filters fetch error: 400 BAD REQUEST: "
            "Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Filters fetch error: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.get")
    def test_get_filters_with_error_without_msg(self, mock_get):
        mock_get.side_effect = mock_sensu_request_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_filters(namespace="TENANT1")

        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/filters",
            headers={
                "Authorization": "Key t0k3n"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Filters fetch error: 400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Filters fetch error: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_filters")
    def test_add_daily_filter(self, mock_filters, mock_post):
        mock_filters.return_value = []
        mock_post.side_effect = mock_post_response
        with self.assertLogs(LOGNAME) as log:
            self.sensu.add_daily_filter(namespace="TENANT1")

        mock_filters.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/filters",
            data=json.dumps(self.daily),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            log.output, [f"INFO:{LOGNAME}:TENANT1: daily filter created"]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_filters")
    def test_add_daily_filter_with_err_with_msg(self, mock_filters, mock_post):
        mock_filters.return_value = []
        mock_post.side_effect = mock_post_response_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.add_daily_filter(namespace="TENANT1")

        mock_filters.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/filters",
            data=json.dumps(self.daily),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: daily filter create error: "
            "400 BAD REQUEST: Something went wrong."
        )

        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: daily filter create error: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_filters")
    def test_add_daily_filter_with_err_no_msg(self, mock_filters, mock_post):
        mock_filters.return_value = []
        mock_post.side_effect = mock_post_response_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.add_daily_filter(namespace="TENANT1")

        mock_filters.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/filters",
            data=json.dumps(self.daily),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: daily filter create error: 400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: daily filter create error: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_filters")
    def test_add_daily_filter_if_exists_and_same(self, mock_filters, mock_post):
        mock_filters.return_value = mock_filters1
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            self.sensu.add_daily_filter(namespace="TENANT1")
        mock_filters.assert_called_once_with(namespace="TENANT1")
        self.assertFalse(mock_post.called)
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.patch")
    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_filters")
    def test_add_daily_filter_if_exists_and_different(
            self, mock_filters, mock_post, mock_patch
    ):
        mock_filters.return_value = mock_filters2
        with self.assertLogs(LOGNAME) as log:
            self.sensu.add_daily_filter(namespace="TENANT1")
        mock_filters.assert_called_once_with(namespace="TENANT1")
        self.assertFalse(mock_post.called)
        mock_patch.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/filters/daily",
            data=json.dumps({
                "expressions": [
                    "((event.check.occurrences == 1 && event.check.status == 0 "
                    "&& event.check.occurrences_watermark >= "
                    "Number(event.check.annotations.attempts)) || "
                    "(event.check.occurrences == "
                    "Number(event.check.annotations.attempts) "
                    "&& event.check.status != 0)) || "
                    "event.check.occurrences % "
                    "(86400 / event.check.interval) == 0"
                ]
            }),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/merge-patch+json"
            }
        )

        self.assertEqual(
            log.output, [f"INFO:{LOGNAME}:TENANT1: daily filter updated"]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_filters")
    def test_add_hard_state_filter(self, mock_filters, mock_post):
        mock_filters.return_value = []
        mock_post.side_effect = mock_post_response
        with self.assertLogs(LOGNAME) as log:
            self.sensu.add_hard_state_filter(namespace="TENANT1")

        mock_filters.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/filters",
            data=json.dumps(self.hard),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            log.output, [f"INFO:{LOGNAME}:TENANT1: hard-state filter created"]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_filters")
    def test_add_hard_state_filter_with_err_with_msg(
            self, mock_filters, mock_post
    ):
        mock_filters.return_value = []
        mock_post.side_effect = mock_post_response_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.add_hard_state_filter(namespace="TENANT1")

        mock_filters.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/filters",
            data=json.dumps(self.hard),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: hard-state filter create error: "
            "400 BAD REQUEST: Something went wrong."
        )

        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: hard-state filter create error: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_filters")
    def test_add_hard_state_filter_with_err_no_msg(
            self, mock_filters, mock_post
    ):
        mock_filters.return_value = []
        mock_post.side_effect = mock_post_response_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.add_hard_state_filter(namespace="TENANT1")

        mock_filters.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/filters",
            data=json.dumps(self.hard),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )

        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: hard-state filter create error: "
            "400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: hard-state filter create error: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_filters")
    def test_add_hard_state_filter_if_exists_and_same(
            self, mock_filters, mock_post
    ):
        mock_filters.return_value = mock_filters1
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            self.sensu.add_hard_state_filter(namespace="TENANT1")
        mock_filters.assert_called_once_with(namespace="TENANT1")
        self.assertFalse(mock_post.called)
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.patch")
    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_filters")
    def test_add_hard_state_filter_if_exists_and_different(
            self, mock_filters, mock_post, mock_patch
    ):
        mock_filters.return_value = mock_filters2
        with self.assertLogs(LOGNAME) as log:
            self.sensu.add_hard_state_filter(namespace="TENANT1")
        mock_filters.assert_called_once_with(namespace="TENANT1")
        self.assertFalse(mock_post.called)
        mock_patch.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/filters/hard-state",
            data=json.dumps({
                "expressions": [
                    "((event.check.status == 0) || (event.check.occurrences >= "
                    "Number(event.check.annotations.attempts) "
                    "&& event.check.status != 0))"
                ]
            }),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/merge-patch+json"
            }
        )

        self.assertEqual(
            log.output, [f"INFO:{LOGNAME}:TENANT1: hard-state filter updated"]
        )


class SensuPipelinesTests(unittest.TestCase):
    def setUp(self):
        self.sensu = Sensu(url="mock-urls", token="t0k3n")
        self.reduce_alerts = {
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

        self.hard_state = {
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

    @patch("requests.get")
    def test_get_pipelines(self, mock_get):
        mock_get.side_effect = mock_sensu_request
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            pipelines = self.sensu._get_pipelines(namespace="TENANT1")
        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/pipelines",
            headers={
                "Authorization": "Key t0k3n"
            }
        )
        self.assertEqual(pipelines, mock_pipelines1)
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.get")
    def test_get_pipelines_with_error_with_msg(self, mock_get):
        mock_get.side_effect = mock_sensu_request_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_pipelines(namespace="TENANT1")
        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/pipelines",
            headers={
                "Authorization": "Key t0k3n"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Pipelines fetch error: 400 BAD REQUEST: "
            "Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Pipelines fetch error: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.get")
    def test_get_pipelines_with_error_without_msg(self, mock_get):
        mock_get.side_effect = mock_sensu_request_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu._get_pipelines(namespace="TENANT1")
        mock_get.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/pipelines",
            headers={
                "Authorization": "Key t0k3n"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: Pipelines fetch error: 400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: Pipelines fetch error: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_pipelines")
    def test_reduce_alerts_pipeline(self, mock_pipelines, mock_post):
        mock_pipelines.return_value = []
        mock_post.side_effect = mock_post_response
        with self.assertLogs(LOGNAME) as log:
            self.sensu.add_reduce_alerts_pipeline(namespace="TENANT1")
        mock_pipelines.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/pipelines",
            data=json.dumps(self.reduce_alerts),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            log.output,
            [f"INFO:{LOGNAME}:TENANT1: reduce_alerts pipeline created"]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_pipelines")
    def test_add_alerts_pipe_with_err_with_msg(self, mock_pipelines, mock_post):
        mock_pipelines.return_value = []
        mock_post.side_effect = mock_post_response_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.add_reduce_alerts_pipeline(namespace="TENANT1")
        mock_pipelines.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/pipelines",
            data=json.dumps(self.reduce_alerts),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: reduce_alerts pipeline create error: "
            "400 BAD REQUEST: Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: "
                f"reduce_alerts pipeline create error: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_pipelines")
    def test_add_alert_pipe_with_err_no_msg(self, mock_pipelines, mock_post):
        mock_pipelines.return_value = []
        mock_post.side_effect = mock_post_response_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.add_reduce_alerts_pipeline(namespace="TENANT1")
        mock_pipelines.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/pipelines",
            data=json.dumps(self.reduce_alerts),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: reduce_alerts pipeline create error: "
            "400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: "
                f"reduce_alerts pipeline create error: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_pipelines")
    def test_add_alert_pipe_if_exists(self, mock_pipeline, mock_post):
        mock_pipeline.return_value = mock_pipelines1
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            self.sensu.add_reduce_alerts_pipeline(namespace="TENANT1")
        mock_pipeline.assert_called_once_with(namespace="TENANT1")
        self.assertFalse(mock_post.called)
        self.assertEqual(log.output, DUMMY_LOG)

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_pipelines")
    def test_hard_state_pipeline(self, mock_pipelines, mock_post):
        mock_pipelines.return_value = []
        mock_post.side_effect = mock_post_response
        with self.assertLogs(LOGNAME) as log:
            self.sensu.add_hard_state_pipeline(namespace="TENANT1")
        mock_pipelines.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/pipelines",
            data=json.dumps(self.hard_state),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            log.output,
            [f"INFO:{LOGNAME}:TENANT1: hard_state pipeline created"]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_pipelines")
    def test_add_hard_pipe_with_err_with_msg(self, mock_pipelines, mock_post):
        mock_pipelines.return_value = []
        mock_post.side_effect = mock_post_response_not_ok_with_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.add_hard_state_pipeline(namespace="TENANT1")
        mock_pipelines.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/pipelines",
            data=json.dumps(self.hard_state),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: hard_state pipeline create error: "
            "400 BAD REQUEST: Something went wrong."
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: "
                f"hard_state pipeline create error: "
                f"400 BAD REQUEST: Something went wrong."
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_pipelines")
    def test_add_hard_pipe_with_err_no_msg(self, mock_pipelines, mock_post):
        mock_pipelines.return_value = []
        mock_post.side_effect = mock_post_response_not_ok_without_msg
        with self.assertRaises(SensuException) as context:
            with self.assertLogs(LOGNAME) as log:
                self.sensu.add_hard_state_pipeline(namespace="TENANT1")
        mock_pipelines.assert_called_once_with(namespace="TENANT1")
        mock_post.assert_called_once_with(
            "mock-urls/api/core/v2/namespaces/TENANT1/pipelines",
            data=json.dumps(self.hard_state),
            headers={
                "Authorization": "Key t0k3n",
                "Content-Type": "application/json"
            }
        )
        self.assertEqual(
            context.exception.__str__(),
            "Sensu error: TENANT1: hard_state pipeline create error: "
            "400 BAD REQUEST"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:TENANT1: "
                f"hard_state pipeline create error: "
                f"400 BAD REQUEST"
            ]
        )

    @patch("requests.post")
    @patch("argo_scg.sensu.Sensu._get_pipelines")
    def test_add_hard_pipe_if_exists(self, mock_pipeline, mock_post):
        mock_pipeline.return_value = mock_pipelines1
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            self.sensu.add_hard_state_pipeline(namespace="TENANT1")
        mock_pipeline.assert_called_once_with(namespace="TENANT1")
        self.assertFalse(mock_post.called)
        self.assertEqual(log.output, DUMMY_LOG)


class MetricOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        sample_output = {
            "check": {
                "command": "/usr/lib64/nagios/plugins/check_http -H "
                           "hostname.example.eu -t 60 --link "
                           "--onredirect follow -S --sni -p 443 -u "
                           "/index.php/services",
                "handlers": [],
                "high_flap_threshold": 0,
                "interval": 300,
                "low_flap_threshold": 0,
                "publish": True,
                "runtime_assets": None,
                "subscriptions": ["eu.eosc.portal.services.url"],
                "proxy_entity_name": "eu.eosc.portal.services.url__hostname."
                                     "example.eu_site-name",
                "check_hooks": None,
                "stdin": False,
                "subdue": None,
                "ttl": 0,
                "timeout": 900,
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_http_connect == "
                        "'generic.http.connect'"
                    ],
                    "splay": False,
                    "splay_coverage": 0
                },
                "round_robin": False,
                "duration": 8.267622018,
                "executed": 1675328305,
                "history": [
                    {"status": 0, "executed": 1675322306},
                    {"status": 0, "executed": 1675322607},
                    {"status": 0, "executed": 1675322906},
                    {"status": 0, "executed": 1675323207},
                    {"status": 0, "executed": 1675323506},
                    {"status": 0, "executed": 1675323806},
                ],
                "issued": 1675328305,
                "output": "TEXT OUTPUT|OPTIONAL PERFDATA\nLONG TEXT LINE 1\n"
                          "LONG TEXT LINE 2\nLONG TEXT LINE 3|PERFDATA LINE 2\n"
                          "PERFDATA LINE 3",
                "state": "passing",
                "status": 0,
                "total_state_change": 0,
                "last_ok": 1675328305,
                "occurrences": 1770,
                "occurrences_watermark": 1770,
                "output_metric_format": "",
                "output_metric_handlers": None,
                "env_vars": None,
                "metadata": {
                    "name": "generic.http.connect",
                    "namespace": "TENANT",
                    "annotations": {"attempts": "3"}
                },
                "secrets": None,
                "is_silenced": False,
                "scheduler": "",
                "processed_by": "sensu-agent.example.com",
                "pipelines": [{
                    "name": "hard_state",
                    "type": "Pipeline",
                    "api_version": "core/v2"
                }]
            },
            "entity": {
                "entity_class": "proxy",
                "system": {
                    "network": {"interfaces": None},
                    "libc_type": "",
                    "vm_system": "",
                    "vm_role": "",
                    "cloud_provider": "",
                    "processes": None
                },
                "subscriptions": ["eu.eosc.portal.services.url"],
                "last_seen": 0,
                "deregister": False,
                "deregistration": {},
                "metadata": {
                    "name": "eu.eosc.portal.services.url__hostname.example.eu_"
                            "site-name",
                    "namespace": "TENANT",
                    "labels": {
                        "generic_http_connect": "generic.http.connect",
                        "hostname": "hostname.example.eu",
                        "info_url":
                            "https://hostname.example.eu/index.php/services",
                        "path": "/index.php/services",
                        "port": "443",
                        "service": "eu.eosc.portal.services.url",
                        "site": "site-name",
                        "ssl": "-S --sni"
                    }
                },
                "sensu_agent_version": ""
            },
            "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "metadata": {"namespace": "TENANT"},
            "pipelines": [{
                "name": "hard_state",
                "type": "Pipeline",
                "api_version": "core/v2"
            }],
            "sequence": 7371,
            "timestamp": 1675328313
        }
        sample_output_one_line = copy.deepcopy(sample_output)
        sample_output_one_line_with_perfdata = copy.deepcopy(sample_output)
        sample_output_multiline_no_perfdata = copy.deepcopy(sample_output)
        sample_output_one_line["check"]["output"] = "TEXT OUTPUT"
        sample_output_one_line_with_perfdata["check"]["output"] = \
            "TEXT OUTPUT|OPTIONAL PERFDATA"
        sample_output_multiline_no_perfdata["check"]["output"] = \
            "TEXT OUTPUT\nLONG TEXT LINE 1\nLONG TEXT LINE 2\nLONG TEXT LINE 3"
        self.output = MetricOutput(data=sample_output)
        self.output_oneline = MetricOutput(data=sample_output_one_line)
        self.output_oneline_perfdata = MetricOutput(
            data=sample_output_one_line_with_perfdata
        )
        self.output_multiline_no_perfdata = MetricOutput(
            data=sample_output_multiline_no_perfdata
        )

    def test_get_service(self):
        self.assertEqual(
            self.output.get_service(), "eu.eosc.portal.services.url"
        )

    def test_get_hostname(self):
        self.assertEqual(
            self.output.get_hostname(), "hostname.example.eu_site-name"
        )

    def test_get_metric_name(self):
        self.assertEqual(self.output.get_metric_name(), "generic.http.connect")

    def test_get_status(self):
        self.assertEqual(self.output.get_status(), "OK")

    def test_get_message(self):
        self.assertEqual(
            self.output.get_message(),
            "LONG TEXT LINE 1\nLONG TEXT LINE 2\nLONG TEXT LINE 3"
        )
        self.assertEqual(self.output_oneline.get_message(), "")
        self.assertEqual(
            self.output_oneline_perfdata.get_message(), ""
        )
        self.assertEqual(
            self.output_multiline_no_perfdata.get_message(),
            "LONG TEXT LINE 1\nLONG TEXT LINE 2\nLONG TEXT LINE 3"
        )

    def test_get_summary(self):
        self.assertEqual(self.output.get_summary(), "TEXT OUTPUT")
        self.assertEqual(self.output_oneline.get_summary(), "TEXT OUTPUT")
        self.assertEqual(
            self.output_oneline_perfdata.get_summary(), "TEXT OUTPUT"
        )
        self.assertEqual(
            self.output_multiline_no_perfdata.get_summary(), "TEXT OUTPUT"
        )

    def test_get_perfdata(self):
        self.assertEqual(
            self.output.get_perfdata(),
            "OPTIONAL PERFDATA PERFDATA LINE 2 PERFDATA LINE 3"
        )
        self.assertEqual(self.output_oneline.get_perfdata(), "")
        self.assertEqual(
            self.output_oneline_perfdata.get_perfdata(), "OPTIONAL PERFDATA"
        )
        self.assertEqual(self.output_multiline_no_perfdata.get_perfdata(), "")

    def test_get_site(self):
        self.assertEqual(self.output.get_site(), "site-name")

    def test_get_namespace(self):
        self.assertEqual(self.output.get_namespace(), "TENANT")


class SensuCheckCallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sensu = Sensu(url="https://mock.url.com", token="t0k3n")
        self.checks = [
            {
                "command": "/usr/lib64/nagios/plugins/check_http "
                           "-H {{ .labels.hostname }} -t 60 --link "
                           "--onredirect follow "
                           "{{ .labels.ssl }} "
                           "-p {{ .labels.port }} ",
                "subscriptions": ["argo.webui"],
                "handlers": [],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_http_connect == "
                        "'generic.http.connect'"
                    ]
                },
                "interval": 300,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "generic.http.connect",
                    "namespace": "default",
                    "annotations": {
                        "attempts": "3"
                    }
                },
                "round_robin": False,
                "pipelines": [
                    {
                        "name": "hard_state",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ]
            },
            {
                "command": "/usr/lib64/nagios/plugins/check_tcp "
                           "-H {{ .labels.hostname }} -t 120 -p 443",
                "handlers": [],
                "high_flap_threshold": 0,
                "interval": 300,
                "low_flap_threshold": 0,
                "publish": True,
                "runtime_assets": None,
                "subscriptions": ["argo.webui"],
                "proxy_entity_name": "",
                "check_hooks": None,
                "stdin": False,
                "subdue": None,
                "ttl": 0,
                "timeout": 120,
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_tcp_connect == "
                        "'generic.tcp.connect'"
                    ],
                    "splay": False,
                    "splay_coverage": 0
                },
                "round_robin": True,
                "output_metric_format": "",
                "output_metric_handlers": None,
                "env_vars": None,
                "metadata": {
                    "name": "generic.tcp.connect",
                    "namespace": "default",
                    "created_by": "root",
                    "annotations": {
                        "attempts": "3"
                    }
                },
                "secrets": None,
                "pipelines": []
            }
        ]
        self.entities = [
            {
                "entity_class": "proxy",
                "system": {
                    "network": {
                        "interfaces": None
                    },
                    "libc_type": "",
                    "vm_system": "",
                    "vm_role": "",
                    "cloud_provider": "",
                    "processes": None
                },
                "subscriptions": ["argo.webui"],
                "last_seen": 0,
                "deregister": False,
                "deregistration": {},
                "metadata": {
                    "name": "argo.ni4os.eu",
                    "namespace": "default",
                    "labels": {
                        "sensu.io/managed_by": "sensuctl",
                        "hostname": "argo.ni4os.eu",
                        "ssl": "-S --sni",
                        "port": "443",
                        "generic_tcp_connect": "generic.tcp.connect",
                        "generic_http_connect": "generic.http.connect"
                    }
                },
                "sensu_agent_version": ""
            },
            {
                "entity_class": "proxy",
                "system": {
                    "network": {
                        "interfaces": None
                    },
                    "libc_type": "",
                    "vm_system": "",
                    "vm_role": "",
                    "cloud_provider": "",
                    "processes": None
                },
                "subscriptions": ["argo.webui"],
                "last_seen": 0,
                "deregister": False,
                "deregistration": {},
                "metadata": {
                    "name": "argo2.ni4os.eu",
                    "namespace": "default",
                    "labels": {
                        "sensu.io/managed_by": "sensuctl",
                        "hostname": "argo2.ni4os.eu",
                        "ssl": "-S --sni",
                        "port": "443",
                        "path": "/some/path",
                        "generic_tcp_connect": "generic.tcp.connect",
                        "generic_http_connect": "generic.http.connect"
                    }
                },
                "sensu_agent_version": ""
            }
        ]

    @patch("argo_scg.sensu.Sensu._get_entities")
    @patch("argo_scg.sensu.Sensu._get_checks")
    def test_get_check_run(self, return_checks, return_entities):
        return_checks.return_value = self.checks
        return_entities.return_value = self.entities
        run = self.sensu.get_check_run(
            entity="argo.ni4os.eu", check="generic.tcp.connect"
        )
        self.assertEqual(
            run,
            "/usr/lib64/nagios/plugins/check_tcp -H argo.ni4os.eu -t 120 -p 443"
        )

    @patch("argo_scg.sensu.Sensu._get_entities")
    @patch("argo_scg.sensu.Sensu._get_checks")
    def test_get_check_run_if_multiple_labels(
            self, return_checks, return_entities
    ):
        return_checks.return_value = self.checks
        return_entities.return_value = self.entities
        run = self.sensu.get_check_run(
            entity="argo.ni4os.eu", check="generic.http.connect"
        )
        self.assertEqual(
            run,
            "/usr/lib64/nagios/plugins/check_http -H argo.ni4os.eu "
            "-t 60 --link --onredirect follow -S --sni -p 443"
        )

    @patch("argo_scg.sensu.Sensu._get_entities")
    @patch("argo_scg.sensu.Sensu._get_checks")
    def test_get_check_run_if_labels_with_defaults(
            self, return_checks, return_entities
    ):
        self.maxDiff = None
        checks = self.checks.copy()
        checks[0]["command"] = "/usr/lib64/nagios/plugins/check_http "\
                               "-H {{ .labels.hostname }} -t 60 --link "\
                               "--onredirect follow {{ .labels.ssl }} "\
                               "-p {{ .labels.port }} " \
                               "-u {{ .labels.path | default \"/\" }}"
        return_checks.return_value = checks
        return_entities.return_value = self.entities
        run1 = self.sensu.get_check_run(
            entity="argo.ni4os.eu", check="generic.http.connect"
        )
        run2 = self.sensu.get_check_run(
            entity="argo2.ni4os.eu", check="generic.http.connect"
        )
        self.assertEqual(
            run1,
            "/usr/lib64/nagios/plugins/check_http -H argo.ni4os.eu "
            "-t 60 --link --onredirect follow -S --sni -p 443 -u /"
        )
        self.assertEqual(
            run2,
            "/usr/lib64/nagios/plugins/check_http -H argo2.ni4os.eu "
            "-t 60 --link --onredirect follow -S --sni -p 443 -u /some/path"
        )
