import os.path
import unittest

from argo_scg.generator import ConfigurationGenerator

mock_metrics = [
    {
        "argo.AMSPublisher-Check": {
            "tags": [
                "ams",
                "ams publisher",
                "argo",
                "internal",
                "messaging"
            ],
            "probe": "ams-publisher-probe",
            "config": {
                "interval": "180",
                "maxCheckAttempts": "1",
                "path": "/usr/libexec/argo-monitoring/probes/argo",
                "retryInterval": "1",
                "timeout": "120"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "NOTIMEOUT": "1",
                "NOPUBLISH": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-s": "/var/run/argo-nagios-ams-publisher/sock",
                "-q": "'w:metrics+g:published180' -c 4000 -q "
                      "'w:alarms+g:published180' -c 1 "
                      "-q 'w:metricsdevel+g:published180' -c 4000"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu/nagios-plugins-argo/blob/"
                      "master/README.md"
        }
    },
    {
        "argo.API-Check": {
            "tags": [
                "api",
                "argo",
                "monitoring"
            ],
            "probe": "web-api",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "120",
                "path": "/usr/libexec/argo-monitoring/probes/argo",
                "interval": "5",
                "retryInterval": "3"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "argo.api_TOKEN": "--token"
            },
            "parameter": {
                "--tenant": "EGI",
                "--rtype": "ar",
                "--unused-reports": "Cloud Critical-Fedcloud Fedcloud "
                                    "NGIHRTest",
                "--day": "1"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu/nagios-plugins-argo/blob/"
                      "master/README.md"
        }
    },
    {
        "ch.cern.WebDAV": {
            "tags": [],
            "probe": "check_webdav",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "15",
                "timeout": "600"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "webdav_URL": "-u",
                "X509_USER_PROXY": "-E"
            },
            "parameter": {
                "-v": "-v",
                "--no-crls": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://gitlab.cern.ch/lcgdm/nagios-plugins-webdav/"
                      "blob/master/README.md"
        }
    },
    {
        "ch.cern.WebDAV-dynafed": {
            "tags": [],
            "probe": "check_webdav",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "15",
                "timeout": "600"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "URL": "-u",
                "X509_USER_PROXY": "-E"
            },
            "parameter": {
                "-v": "-v",
                "--no-crls": "",
                "--dynafed": "",
                "--fixed-content-length": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://gitlab.cern.ch/lcgdm/nagios-plugins-webdav/blob/"
                      "master/README.md"
        }
    },
    {
        "eu.egi.AAI-OIDC-Login": {
            "tags": [
                "rciam"
            ],
            "probe": "checklogin",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "10",
                "path": " /usr/libexec/argo-monitoring/probes/rciam_probes",
                "interval": "15",
                "retryInterval": "2"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "EGISSO_USER": "-u",
                "EGISSO_PASSWORD": "-a"
            },
            "parameter": {
                "-i": "https://idp.admin.grnet.gr/idp/shibboleth,"
                      "https://www.egi.eu/idp/shibboleth",
                "-s": "https://snf-666522.vm.okeanos.grnet.gr/egi-rp/auth.php",
                "-C": "",
                "-e": "https://mon.rciam.grnet.gr/probes/results"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/rciam/rciam_probes/blob/master/"
                      "README.md"
        }
    },
    {
        "eu.egi.AAI-SAML-Login": {
            "tags": [
                "rciam"
            ],
            "probe": "checklogin",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "10",
                "path": "/usr/libexec/argo-monitoring/probes/rciam_probes",
                "interval": "15",
                "retryInterval": "2"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "EGISSO_USER": "-u",
                "EGISSO_PASSWORD": "-a"
            },
            "parameter": {
                "-i": "https://idp.admin.grnet.gr/idp/shibboleth,"
                      "https://www.egi.eu/idp/shibboleth",
                "-s": "https://snf-666522.vm.okeanos.grnet.gr/ssp/module.php/"
                      "core/authenticate.php?as=egi-sp",
                "-C": "",
                "-e": "https://mon.rciam.grnet.gr/probes/results"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/rciam/rciam_probes/blob/master/"
                      "README.md"
        }
    },
    {
        "eu.egi.cloud.DynDNS-Check": {
            "tags": [],
            "probe": "nagios-plugin-dynamic-dns.sh",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "120",
                "path": "/usr/libexec/argo-monitoring/probes/"
                        "nagios-plugin-dynamic-dns",
                "interval": "5",
                "retryInterval": "3"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "endpoint-name": "--endpoint-name"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/tdviet/DDNS-probe/blob/main/README.md"
        }
    },
    {
        "eu.egi.grycap.IM-Check": {
            "tags": [],
            "probe": "probeim.py",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "60",
                "path": "/usr/libexec/argo-monitoring/probes/es.upv.grycap.im",
                "interval": "60",
                "retryInterval": "3"
            },
            "flags": {
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "es.upv.grycap.im_GOCDB_SERVICE_URL": "--url",
                "OIDC_TOKEN_FILE": "--token"
            },
            "parameter": {
                "-l": "NONE"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/grycap/im/blob/master/monitoring/"
                      "README.md"
        }
    },
    {
        "eu.egi.cloud.InfoProvider": {
            "tags": [],
            "probe": "cloudinfo.py",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "300",
                "path": "/usr/libexec/argo-monitoring/probes/fedcloud",
                "interval": "60",
                "retryInterval": "15"
            },
            "flags": {
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "OS_KEYSTONE_URL": "--endpoint"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://wiki.egi.eu/wiki/Cloud_SAM_tests"
        }
    },
    {
        "eu.egi.cloud.OpenStack-Swift": {
            "tags": [],
            "probe": "swiftprobe.py",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "300",
                "path": "/usr/libexec/argo-monitoring/probes/fedcloud",
                "interval": "60",
                "retryInterval": "15"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "OBSESS": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "0",
                "org.nagios.Keystone-TCP": "1"
            },
            "attribute": {
                "OS_KEYSTONE_URL": "--endpoint",
                "OIDC_ACCESS_TOKEN": "--access-token"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu/nagios-plugins-fedcloud/blob"
                      "/master/README.md"
        }
    },
    {
        "eu.egi.cloud.OpenStack-VM": {
            "tags": [],
            "probe": "novaprobe.py",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "300",
                "path": "/usr/libexec/argo-monitoring/probes/fedcloud",
                "interval": "60",
                "retryInterval": "15"
            },
            "flags": {
                "VO": "1",
                "NOHOSTNAME": "1",
                "OBSESS": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "0",
                "org.nagios.Keystone-TCP": "1"
            },
            "attribute": {
                "OIDC_ACCESS_TOKEN": "--access-token",
                "OS_APPDB_IMAGE": "--appdb-image",
                "OS_KEYSTONE_URL": "--endpoint",
                "X509_USER_PROXY": "--cert",
                "OS_REGION": "--region"
            },
            "parameter": {
                "-v": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://wiki.egi.eu/wiki/Cloud_SAM_tests"
        }
    },
    {
        "eu.egi.GRAM-CertValidity": {
            "tags": [],
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
                "NAGIOS_HOST_KEY": "-K",
                "GRAM_PORT": "-p"
            },
            "parameter": {
                "-w": "30 -c 0 -N --altnames",
                "--rootcert-dir": "/etc/grid-security/certificates"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/matteocorti/check_ssl_cert/blob/"
                      "master/README.md"
        }
    },
    {
        "eu.egi.sec.ARCCE-Pakiti-Check": {
            "tags": [],
            "probe": "eu.egi.sec/probes/check_pakiti_vuln",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "30",
                "path": "/usr/libexec/grid-monitoring/probes",
                "interval": "60",
                "retryInterval": "5"
            },
            "flags": {
                "VO": "1",
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "VONAME": "--vo",
                "NAGIOS_HOST_CERT": "--cert",
                "NAGIOS_HOST_KEY": "--key",
                "SITENAME": "--site"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu/secmon-probes"
        }
    },
    {
        "eu.egi.SRM-All": {
            "tags": [],
            "probe": "srm_probe.py",
            "config": {
                "maxCheckAttempts": "4",
                "timeout": "300",
                "path": "/usr/lib64/nagios/plugins/srm",
                "interval": "60",
                "retryInterval": "15"
            },
            "flags": {
                "VO": "1"
            },
            "dependency": {},
            "attribute": {
                "VONAME": "--voname",
                "X509_USER_PROXY": "-X",
                "SITE_BDII": "--ldap-url",
                "SURL": "--endpoint"
            },
            "parameter": {
                "-d": "",
                "-p": "eu.egi.SRM",
                "--se-timeout": "260"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/EGI-Foundation/nagios-plugins-srm/"
                      "blob/master/README.md"
        }
    },
    {
        "eu.seadatanet.org.replicationmanager-check": {
            "tags": [],
            "probe": "check_http",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "30",
                "path": "/usr/lib64/nagios/plugins",
                "interval": "5",
                "retryInterval": "3"
            },
            "flags": {
                "PNP": "1",
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "rm_path": "-u"
            },
            "parameter": {
                "-f": "\"follow\""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http.html"
        }
    },
    {
        "eu.seadatanet.org.replicationmanager-check-status": {
            "tags": [],
            "probe": "replication_manager_check.py",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "30",
                "path": "/usr/libexec/argo-monitoring/probes/sdc-replication"
                        "-manager/",
                "interval": "5",
                "retryInterval": "3"
            },
            "flags": {
                "PNP": "1",
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "rm_path": "-r"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu/nagios-plugins-sdc-replication"
                      "-manager/blob/devel/README.md"
        }
    },
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
    },
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
                "--ssl": "",
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
        "generic.http.connect": {
            "tags": [
                "harmonized",
                "http",
                "network"
            ],
            "probe": "check_http",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "3",
                "timeout": "60"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "SSL": "-S --sni",
                "PORT": "-p",
                "PATH": "-u"
            },
            "parameter": {
                "--link": "",
                "--onredirect": "follow"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http.html"
        }
    },
    {
        "generic.ssh.connect": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_ssh",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "4",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "5",
                "timeout": "60"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "PORT": "-p"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/index.html"
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
        "grnet.agora.healthcheck": {
            "tags": [
                "catalogue",
                "harmonized",
                "profiles"
            ],
            "probe": "checkhealth",
            "config": {
                "timeout": "100",
                "retryInterval": "3",
                "path": "/usr/libexec/argo/probes/grnet-agora/",
                "maxCheckAttempts": "3",
                "interval": "15"
            },
            "flags": {
                "PNP": "1",
                "OBSESS": "1",
                "NOTIMEOUT": "1"
            },
            "dependency": {},
            "attribute": {
                "AGORA_USERNAME": "-u",
                "AGORA_PASSWORD": "-p"
            },
            "parameter": {
                "-v": "",
                "-i": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu-Metrics/argo-probe-grnet-agora"
                      "/blob/master/README.md"
        }
    },
    {
        "grnet.rciam.oidc-login-edugain-ni4os": {
            "tags": [
                "aai",
                "harmonized",
                "rciam"
            ],
            "probe": "checklogin",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "10",
                "path": "/usr/libexec/argo-monitoring/probes/rciam_probes",
                "interval": "15",
                "retryInterval": "2"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "EDUGAIN_USER": "-u",
                "EDUGAIN_PASSWORD": "-a"
            },
            "parameter": {
                "-i": "https://idp.admin.grnet.gr/idp/shibboleth",
                "-s": "https://snf-666522.vm.okeanos.grnet.gr/ni4os-rp/auth."
                      "php",
                "-C": "",
                "-e": "https://mon-dev.rciam.grnet.gr/probes/results"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/rciam/rciam_probes/blob/master/"
                      "README.md"
        }
    },
    {
        "org.bdii.Entries": {
            "tags": [],
            "probe": "check_bdii_entries",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "4",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "15",
                "timeout": "60"
            },
            "flags": {
                "NRPE": "1",
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {
                "org.nagios.BDII-Check": "1"
            },
            "attribute": {
                "BDII_DN": "-b",
                "BDII_PORT": "-p"
            },
            "parameter": {
                "-c": "40:1",
                "-w": "20:1"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://gridinfo-documentation.readthedocs.io/en/latest/"
                      "developers/tests.html"
        }
    },
    {
        "org.nagios.GLUE2-Check": {
            "tags": [],
            "probe": "midmon/check_bdii_entries_num",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "60",
                "path": "/usr/libexec/argo-monitoring/probes",
                "interval": "60",
                "retryInterval": "5"
            },
            "flags": {
                "PNP": "1",
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "GLUE2_BDII_DN": "-b",
                "BDII_PORT": "-p"
            },
            "parameter": {
                "-c": "1:1",
                "-f": "\"(&(objectClass=GLUE2Domain)"
                      "(GLUE2DomainID=$_SERVICESITE_NAME$))\""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://wiki.egi.eu/wiki/MW_Nagios_tests"
        }
    },
    {
        "org.nagios.GridFTP-Check": {
            "tags": [],
            "probe": "check_ftp",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "4",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "5",
                "timeout": "60"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {
                "org.nmap.Classic-SE": "1",
                "org.nmap.WMS": "1"
            },
            "attribute": {
                "GRIDFTP_PORT": "-p"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/index.html"
        }
    },
    {
        "org.nagios.Keystone-TCP": {
            "tags": [],
            "probe": "check_tcp",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "3",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "3",
                "timeout": "120"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1",
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "OS_KEYSTONE_PORT": "-p",
                "OS_KEYSTONE_HOST": "-H"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_tcp.html"
        }
    },
    {
        "org.nordugrid.ARC-CE-SRM-submit": {
            "tags": [],
            "probe": "check_arcce_submit",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "15",
                "timeout": "600"
            },
            "flags": {
                "NOTIMEOUT": "1",
                "OBSESS": "1",
                "VO": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "0"
            },
            "attribute": {
                "ARC_GOOD_SES": "-O",
                "VONAME": "--voms",
                "VO_FQAN": "--fqan",
                "X509_USER_PROXY": "--user-proxy",
                "ARC_CE_MEMORY_LIMIT": "--memory-limit"
            },
            "parameter": {
                "--job-tag": "dist-stage-srm",
                "--termination-service": "org.nordugrid.ARC-CE-SRM-result-"
                                         "$_SERVICEVO_FQAN$",
                "--test": "dist-stage-srm",
                "-O": "service_suffix=-$_SERVICEVO_FQAN$",
                "--command-file": "/var/nagios/rw/nagios.cmd",
                "--how-invoked": "nagios"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://git.nbi.ku.dk/downloads/"
                      "NorduGridARCNagiosPlugins/index.html#"
        }
    },
    {
        "org.nordugrid.ARC-CE-submit": {
            "tags": [],
            "probe": "check_arcce_submit",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "15",
                "timeout": "600"
            },
            "flags": {
                "NOTIMEOUT": "1",
                "OBSESS": "1",
                "VO": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "0"
            },
            "attribute": {
                "VONAME": "--voms",
                "VO_FQAN": "--fqan",
                "X509_USER_PROXY": "--user-proxy",
                "ARC_CE_MEMORY_LIMIT": "--memory-limit"
            },
            "parameter": {
                "--termination-service": "org.nordugrid.ARC-CE-result-"
                                         "$_SERVICEVO_FQAN$",
                "--test": "dist-caversion --test dist-sw-csh "
                          "--test dist-sw-gcc --test dist-sw-python "
                          "--test dist-sw-perl",
                "-O": "service_suffix=-$_SERVICEVO_FQAN$",
                "--command-file": "/var/nagios/rw/nagios.cmd",
                "--how-invoked": "nagios"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://git.nbi.ku.dk/downloads/NorduGridARCNagiosPlugins"
                      "/index.html#"
        }
    },
    {
        "pl.plgrid.QCG-Broker": {
            "tags": [],
            "probe": "org.qoscosgrid/broker/qcg-broker-probe",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "2",
                "path": "/usr/libexec/grid-monitoring/probes",
                "retryInterval": "15",
                "timeout": "600"
            },
            "flags": {
                "NRPE": "1",
                "OBSESS": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "1",
                "hr.srce.QCG-Broker-CertLifetime": "1"
            },
            "attribute": {
                "QCG-BROKER_PORT": "-p",
                "info_hostdn": "-n",
                "X509_USER_PROXY": "-x"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://www.qoscosgrid.org/trac/qcg-broker"
        }
    }
]

mock_topology = [
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.webui",
        "hostname": "argo.ni4os.eu",
        "tags": {
            "info_ID": "xxxx",
            "info_URL": "https://argo.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.test",
        "hostname": "argo.ni4os.eu",
        "tags": {
            "info_ID": "xxxx",
            "info_URL": "https://argo.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "UKIM",
        "type": "SITES",
        "service": "eu.ni4os.ops.gocdb",
        "hostname": "gocdb.ni4os.eu",
        "tags": {
            "info_ID": "xxxx",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.mon",
        "hostname": "argo-mon2.ni4os.eu",
        "tags": {
            "info_ID": "xxxx",
            "info_URL": "https://argo-mon2.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.webui",
        "hostname": "argo-devel.ni4os.eu",
        "tags": {
            "info_ID": "xxxx",
            "info_URL": "http://argo-devel.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-03-14",
        "group": "OPENSTACK",
        "type": "SITES",
        "service": "test.openstack.nova",
        "hostname": "cloud.cloudhost.com",
        "tags": {
            "info_HOSTDN": "/CN=cloud.cloudhost.com",
            "info_ID": "xxxxxxx",
            "info_URL": "https://cloud.cloudhost.com:5000/v3/",
            "monitored": "1",
            "production": "1",
            "scope": "scope1, scope2"
        }
    },
    {
        "date": "2022-03-14",
        "group": "WEBDAV-test",
        "type": "SITES",
        "service": "mock.webdav",
        "hostname": "dpm.bla.meh.com",
        "tags": {
            "info_HOSTDN": "/CN=host/dpm.bla.meh.com",
            "info_ID": "xxxxxxx",
            "info_URL": "https://dpm.bla.meh.com/dpm/ops/",
            "info_service_endpoint_URL": "https://mock.url.com/dpm/ops, "
                                         "https://mock2.url.com/dpm/ops",
            "monitored": "1",
            "production": "1",
            "scope": "scope1"
        }
    },
    {
        "date": "2022-03-15",
        "group": "GRIDOPS-CheckIn",
        "type": "SITES",
        "service": "egi.aai.saml",
        "hostname": "aai.eosc-portal.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://aai.eosc-portal.eu/proxy",
            "info_service_endpoint_URL":
                "https://aai.eosc-portal.eu/proxy/saml2/idp/metadata.php, "
                "https://aai.eosc-portal.eu/proxy/module.php/saml/sp/"
                "metadata.php/sso, "
                "https://aai.eosc-portal.eu/proxy/module.php/core/"
                "authenticate.php?as=sso",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-15",
        "group": "GRIDOPS-CheckIn",
        "type": "SITES",
        "service": "egi.aai.oidc",
        "hostname": "aai.eosc-portal.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://aai.eosc-portal.eu/oidc",
            "info_service_endpoint_URL":
                "https://aai.eosc-portal.eu/oidc/.well-known/"
                "openid-configuration, "
                "https://aai.eosc-portal.eu/oidc/authorize",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-15",
        "group": "BDII",
        "type": "SITES",
        "service": "Top-BDII",
        "hostname": "bdii1.test.com",
        "tags": {
            "info_ID": "xxxxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "scope3"
        }
    },
    {
        "date": "2022-03-15",
        "group": "SBDII",
        "type": "SITES",
        "service": "Site-BDII",
        "hostname": "sbdii.test.com",
        "tags": {
            "info_ID": "xxxxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-18",
        "group": "IPB",
        "type": "SITES",
        "service": "eu.ni4os.app.web",
        "hostname": "catalogue.ni4os.eu",
        "tags": {
            "info_ID": "xxx",
            "info_URL": "https://catalogue.ni4os.eu/",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "date": "2022-03-18",
        "group": "SRCE",
        "type": "SITES",
        "service": "eu.ni4os.hpc.ui",
        "hostname": "teran.srce.hr",
        "tags": {
            "info_ID": "xxx",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "date": "2022-03-18",
        "group": "IPB",
        "type": "SITES",
        "service": "eu.ni4os.hpc.ui",
        "hostname": "hpc.resource.ni4os.eu",
        "tags": {
            "info_ID": "xxxx",
            "info_ext_PORT": "1022",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "date": "2022-03-18",
        "group": "EGI-DDNS",
        "type": "SITES",
        "service": "eu.egi.cloud.dyndns",
        "hostname": "dns1.cloud.test.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://dns1.cloud.test.eu/",
            "info_ext_endpoint-name": "nsupdate",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-18",
        "group": "EGI-DDNS",
        "type": "SITES",
        "service": "eu.egi.cloud.dyndns",
        "hostname": "dns2.cloud.test.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_ext_endpoint-name": "secondary",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-18",
        "group": "EGI-DDNS",
        "type": "SITES",
        "service": "eu.egi.cloud.dyndns",
        "hostname": "dns3.cloud.test.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_ext_endpoint-name": "primary",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-23",
        "group": "INFN-CLOUD-CNAF",
        "type": "SITES",
        "service": "org.openstack.nova",
        "hostname": "cloud-api-pub.cr.cnaf.infn.it",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://cloud-api-pub.cr.cnaf.infn.it:5000/v3",
            "info_ext_OS_REGION": "sdds",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, FedCloud"
        }
    },
    {
        "date": "2022-03-23",
        "group": "INFN-PADOVA-STACK",
        "type": "SITES",
        "service": "org.openstack.nova",
        "hostname": "egi-cloud.pd.infn.it",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://egi-cloud.pd.infn.it:443/v3",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, FedCloud"
        }
    },
    {
        "date": "2022-03-23",
        "group": "CESNET-MCC",
        "type": "SITES",
        "service": "org.openstack.swift",
        "hostname": "identity.cloud.muni.cz",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://identity.cloud.muni.cz/v3",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, FedCloud"
        }
    },
    {
        "date": "2022-03-25",
        "group": "JUELICH",
        "type": "SITES",
        "service": "b2access.unity",
        "hostname": "b2access.eudat.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://b2access.eudat.eu/home/",
            "info_ext_servicetype_id": "xx",
            "info_ext_state": "production",
            "monitored": "1",
            "production": "0",
            "scope": "EUDAT"
        }
    },
    {
        "date": "2022-03-25",
        "group": "CA-UVic-Cloud",
        "type": "SITES",
        "service": "ch.cern.dynafed",
        "hostname": "dynafed.hostname.ca",
        "tags": {
            "info_HOSTDN": "/C=CA/O=Grid/CN=dynafed.hostname.ca",
            "info_ID": "xxxxxxx",
            "info_URL": "https://dynafed.hostname.ca:443/dynafed/ops",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-25",
        "group": "CERN-PROD",
        "type": "SITES",
        "service": "webdav",
        "hostname": "hostname.cern.ch",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://hostname.cern.ch/atlas/opstest",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-25",
        "group": "UPV-GRyCAP",
        "type": "SITES",
        "service": "es.upv.grycap.im",
        "hostname": "grycap.upv.es",
        "tags": {
            "info_ID": "xxxxxx",
            "info_URL": "https://grycap.upv.es:31443/im/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, FedCloud"
        }
    },
    {
        "date": "2022-03-25",
        "group": "CING",
        "type": "SITES",
        "service": "web.check",
        "hostname": "bioinformatics.cing.ac.cy",
        "tags": {
            "info_ID": "xxxx",
            "info_URL": "https://bioinformatics.cing.ac.cy/MelGene/",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "date": "2022-03-25",
        "group": "CYI",
        "type": "SITES",
        "service": "web.check",
        "hostname": "eewrc-las.cyi.ac.cy",
        "tags": {
            "info_ID": "xxx",
            "info_URL": "http://eewrc-las.cyi.ac.cy/las/getUI.do",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "date": "2022-03-25",
        "group": "SAMPA",
        "type": "SITES",
        "service": "web.check",
        "hostname": "sampaeos.if.usp.br",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://sampaeos.if.usp.br:9000//eos/ops/opstest/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2, alice"
        }
    },
    {
        "date": "2022-03-28",
        "group": "AUVERGRID",
        "type": "SITES",
        "service": "ARC-CE",
        "hostname": "gridarcce01.mesocentre.uca.fr",
        "tags": {
            "info_ID": "xxxxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, atlas, lhcb"
        }
    },
    {
        "date": "2022-03-28",
        "group": "ARNES",
        "type": "SITES",
        "service": "Site-BDII",
        "hostname": "kser.arnes.si",
        "tags": {
            "info_HOSTDN": "/C=SI/O=SiGNET/O=Arnes/CN=kser.arnes.si",
            "info_ID": "1691G0",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, atlas"
        }
    },
    {
        "date": "2022-03-28",
        "group": "ARNES",
        "type": "SITES",
        "service": "ngi.ARGUS",
        "hostname": "argus.sling.si",
        "tags": {
            "info_HOSTDN": "/C=SI/O=SiGNET/O=SLING/CN=argus.sling.si",
            "info_ID": "5024G0",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, atlas"
        }
    },
    {
        "date": "2022-03-28",
        "group": "ARNES",
        "type": "SITES",
        "service": "SRM",
        "hostname": "dcache.arnes.si",
        "tags": {
            "info_HOSTDN": "/C=SI/O=SiGNET/O=Arnes/CN=dcache.arnes.si",
            "info_ID": "5869G0",
            "info_bdii_SRM2_PORT": "8443",
            "monitored": "1",
            "production": "1",
            "scope": "EGI",
            "vo_cipkebip_attr_SE_PATH": "/data/arnes.si/cipkebip",
            "vo_gen.vo.sling_attr_SE_PATH": "/data/arnes.si/gen.vo.sling.si",
            "vo_ops_attr_SE_PATH": "/data/arnes.si/ops"
        }
    },
    {
        "date": "2022-03-28",
        "group": "RO-13-ISS",
        "type": "SITES",
        "service": "ARC-CE",
        "hostname": "alien.spacescience.ro",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_ext_ARC_CE_MEMORY_LIMIT": "268435456",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2, alice"
        }
    },
    {
        "date": "2022-03-28",
        "group": "NGI_PL_SERVICES",
        "type": "SITES",
        "service": "QCG.Broker",
        "hostname": "qcg-broker.man.poznan.pl",
        "tags": {
            "info_HOSTDN": "/C=PL/CN=qcg-broker.man.poznan.pl",
            "info_ID": "xxxxxx",
            "info_URL": "https://qcg-broker.man.poznan.pl:8443/qcg/services/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-29",
        "group": "DESY-HH",
        "type": "SITES",
        "service": "SRM",
        "hostname": "dcache-se-cms.desy.de",
        "tags": {
            "info_ID": "3080G0",
            "info_bdii_SRM2_PORT": "8443",
            "info_ext_SURL": "srm://dcache-se-cms.desy.de:8443/srm/"
                             "managerv2?SFN=/pnfs/desy.de/ops",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2, atlas, cms, lhcb",
            "vo_cms_attr_SE_PATH": "/pnfs/desy.de/cms/generated",
            "vo_desy_attr_SE_PATH": "/pnfs/desy.de/desy",
            "vo_dgops_attr_SE_PATH": "/pnfs/desy.de/dgops",
            "vo_dteam_attr_SE_PATH": "/pnfs/desy.de/dteam",
            "vo_ops_attr_SE_PATH": "/pnfs/desy.de/ops"
        }
    },
    {
        "date": "2022-03-29",
        "group": "DESY-HH",
        "type": "SITES",
        "service": "Site-BDII",
        "hostname": "grid-giis1.desy.de",
        "tags": {
            "info_ID": "1729G0",
            "info_URL": "ldap://grid-giis1.desy.de:2170/mds-vo-name=DESY-HH,"
                        "o=grid",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2, atlas, cms, lhcb"
        }
    },
    {
        "date": "2022-03-29",
        "group": "GAMMA",
        "type": "SITES",
        "service": "eu.seadatanet.org.replicationmanager",
        "hostname": "185.229.108.85",
        "tags": {
            "info_ID": "xxxxx",
            "info_URL": "http://185.229.108.85:8080/",
            "monitored": "1",
            "production": "1",
            "scope": "SDC"
        }
    },
    {
        "date": "2022-03-29",
        "group": "HNODC",
        "type": "SITES",
        "service": "eu.seadatanet.org.replicationmanager",
        "hostname": "hnodc-dm.ath.hcmr.gr",
        "tags": {
            "info_ID": "xxxxx",
            "info_URL": "http://hnodc-dm.ath.hcmr.gr/",
            "info_ext_rm_path": "/ReplicationManager/",
            "monitored": "1",
            "production": "1",
            "scope": "SDC"
        },
    },
    {
        "date": "2022-04-20",
        "group": "GRIDOPS",
        "type": "SITES",
        "service": "eu.eudat.itsm.spmt",
        "hostname": "eosc.agora.grnet.gr",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://eosc.agora.grnet.gr/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    }
]

mock_metric_profiles = [
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-11-24",
        "name": "ARGO_TEST1",
        "description": "Profile for monitoring",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.http.ar-argoui-ni4os",
                    "generic.tcp.connect"
                ]
            },
            {
                "service": "argo.test",
                "metrics": [
                    "generic.http.ar-argoui-ni4os"
                ]
            }
        ]
    },
    {
        "id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
        "date": "2021-12-01",
        "name": "ARGO_TEST2",
        "description": "Profile for testing hard-coded attributes",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.certificate.validity",
                    "eu.egi.GRAM-CertValidity"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST3",
        "description": "Another profile for testing hard-coded attributes",
        "services": [
            {
                "service": "argo.test",
                "metrics": [
                    "org.nagios.GridFTP-Check"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-11-24",
        "name": "ARGO_TEST4",
        "description": "Profile for testing metrics with attributes in file",
        "services": [
            {
                "service": "b2access.unity",
                "metrics": [
                    "eudat.b2access.unity.login-local",
                ]
            },
            {
                "service": "aai.oidc.login",
                "metrics": [
                    "grnet.rciam.oidc-login-edugain-ni4os"
                ]
            },
            {
                "service": "argo.test",
                "metrics": [
                    "eudat.b2access.unity.login-local"
                ]
            }
        ]
    },
    {
        "id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
        "date": "2021-12-01",
        "name": "ARGO_TEST5",
        "description": "Just another metric profile",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.http.ar-argoui-ni4os",
                    "generic.tcp.connect",
                    "generic.certificate.validity"
                ]
            }
        ]
    },
    {
        "id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
        "date": "2021-12-01",
        "name": "ARGO_TEST6",
        "description": "Profile for fetching PATH and PORT",
        "services": [
            {
                "service": "web.check",
                "metrics": [
                    "generic.http.connect"
                ]
            },
            {
                "service": "eu.ni4os.hpc.ui",
                "metrics": [
                    "generic.ssh.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST7",
        "description": "Profile for SSL",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.http.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST8",
        "description": "Profile for URLs",
        "services": [
            {
                "service": "webdav",
                "metrics": [
                    "ch.cern.WebDAV"
                ]
            },
            {
                "service": "ch.cern.dynafed",
                "metrics": [
                    "ch.cern.WebDAV-dynafed"
                ]
            },
            {
                "service": "es.upv.grycap.im",
                "metrics": [
                    "eu.egi.grycap.IM-Check"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST9",
        "description": "Profile for URLs",
        "services": [
            {
                "service": "mock.webdav",
                "metrics": [
                    "ch.cern.WebDAV"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST10",
        "description": "Profile for BDII",
        "services": [
            {
                "service": "Site-BDII",
                "metrics": [
                    "org.bdii.Entries",
                    "org.nagios.GLUE2-Check"
                ]
            },
            {
                "service": "Top-BDII",
                "metrics": [
                    "org.bdii.Entries"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST11",
        "description": "Profile for port testing",
        "services": [
            {
                "service": "eu.ni4os.hpc.ui",
                "metrics": [
                    "generic.ssh.connect"
                ]
            },
            {
                "service": "eu.ni4os.app.web",
                "metrics": [
                    "generic.http.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST12",
        "description": "Profile for testing extensions",
        "services": [
            {
                "service": "eu.egi.cloud.dyndns",
                "metrics": [
                    "eu.egi.cloud.DynDNS-Check"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST13",
        "description": "Profile for testing openstack",
        "services": [
            {
                "service": "org.openstack.nova",
                "metrics": [
                    "eu.egi.cloud.InfoProvider",
                    "eu.egi.cloud.OpenStack-VM",
                    "org.nagios.Keystone-TCP"
                ]
            },
            {
                "service": "org.openstack.swift",
                "metrics": [
                    "eu.egi.cloud.OpenStack-Swift"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST14",
        "description": "Profile for testing openstack",
        "services": [
            {
                "service": "egi.aai.saml",
                "metrics": [
                    "eu.egi.AAI-SAML-Login"
                ]
            },
            {
                "service": "egi.aai.oidc",
                "metrics": [
                    "eu.egi.AAI-OIDC-Login"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST15",
        "description": "Profile for testing Pakiti probes",
        "services": [
            {
                "service": "ARC-CE",
                "metrics": [
                    "eu.egi.sec.ARCCE-Pakiti-Check"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST16",
        "description": "Profile for testing SITE-BDII attribute",
        "services": [
            {
                "service": "SRM",
                "metrics": [
                    "eu.egi.SRM-All"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST17",
        "description": "Profile for testing ARC_GOOD_SES attribute",
        "services": [
            {
                "service": "ARC-CE",
                "metrics": [
                    "org.nordugrid.ARC-CE-SRM-submit"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST18",
        "description": "Profile for testing HOSTDN attribute",
        "services": [
            {
                "service": "QCG.Broker",
                "metrics": [
                    "pl.plgrid.QCG-Broker"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST19",
        "description": "Profile for testing optional extensions",
        "services": [
            {
                "service": "ARC-CE",
                "metrics": [
                    "org.nordugrid.ARC-CE-SRM-submit",
                    "org.nordugrid.ARC-CE-submit"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST20",
        "description": "Profile for testing same extension values, different "
                       "parameters",
        "services": [
            {
                "service": "eu.seadatanet.org.replicationmanager",
                "metrics": [
                    "eu.seadatanet.org.replicationmanager-check",
                    "eu.seadatanet.org.replicationmanager-check-status"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST21",
        "description": "Profile for testing topology from file",
        "services": [
            {
                "service": "argo.mon",
                "metrics": [
                    "generic.certificate.validity"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST22",
        "description": "Profile for testing secret attributes",
        "services": [
            {
                "service": "eu.eudat.itsm.spmt",
                "metrics": [
                    "grnet.agora.healthcheck"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST23",
        "description": "Profile for testing secret attributes with dots",
        "services": [
            {
                "service": "argo.api",
                "metrics": [
                    "argo.API-Check"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST24",
        "description": "Profile for testing NOPUBLISH",
        "services": [
            {
                "service": "argo.test",
                "metrics": [
                    "argo.AMSPublisher-Check",
                    "generic.tcp.connect"
                ]
            }
        ]
    }
]

mock_local_topology = [
    {
        "group": "SRCE",
        "service": "argo.mon",
        "hostname": "argo-mon-devel.egi.eu",
        "tags": {}
    },
    {
        "group": "SRCE",
        "service": "argo.mon",
        "hostname": "argo-mon-devel.ni4os.eu",
        "tags": {}
    },
    {
        "group": "argo-public-production",
        "service": "argo.api",
        "hostname": "api.argo.grnet.gr",
        "tags": {}
    }
]


class ConfigurationTests(unittest.TestCase):
    def test_generate_checks_configuration(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST1"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
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
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.ar-argoui-ni4os",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": ["argo.webui"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_checks_configuration_for_default_tenant(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST1"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=False, namespace="default")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 30 "
                               "-r argo.eu "
                               "-u /ni4os/report-ar/Critical/"
                               "NGI?accept=csv "
                               "--ssl --onredirect follow",
                    "subscriptions": ["argo.webui", "argo.test"],
                    "handlers": [],
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.ar-argoui-ni4os",
                        "namespace": "default"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": ["argo.webui"],
                    "handlers": [],
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "default"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_checks_configuration_without_publish(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST1"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=False, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 30 "
                               "-r argo.eu "
                               "-u /ni4os/report-ar/Critical/"
                               "NGI?accept=csv "
                               "--ssl --onredirect follow",
                    "subscriptions": ["argo.webui", "argo.test"],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_http_ar_argoui_ni4os == "
                            "'generic.http.ar-argoui-ni4os'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.ar-argoui-ni4os",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
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
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_hardcoded_attributes(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST2", "ARGO_TEST3"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 "
                               "-w 30 -c 0 -N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates "
                               "-C /etc/nagios/globus/hostcert.pem "
                               "-K /etc/nagios/globus/hostkey.pem -p 2119",
                    "subscriptions": ["argo.webui"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_gram_certvalidity == "
                            "'eu.egi.GRAM-CertValidity'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.GRAM-CertValidity",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 -w 30 -c 0 "
                               "-N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates "
                               "--rootcert-file "
                               "/etc/pki/tls/certs/ca-bundle.crt "
                               "-C /etc/nagios/globus/hostcert.pem "
                               "-K /etc/nagios/globus/hostkey.pem",
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
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.certificate.validity",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_ftp "
                               "-H {{ .labels.hostname }} -t 60 -p 2811",
                    "subscriptions": ["argo.test"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nagios_gridftp_check == "
                            "'org.nagios.GridFTP-Check'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nagios.GridFTP-Check",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_robot_cert_key(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST2"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg2.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=False, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 "
                               "-w 30 -c 0 -N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates "
                               "-C /etc/nagios/robot/robot.pem "
                               "-K /etc/nagios/robot/robot.key -p 2119",
                    "subscriptions": ["argo.webui"],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_gram_certvalidity == "
                            "'eu.egi.GRAM-CertValidity'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.GRAM-CertValidity",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 -w 30 -c 0 "
                               "-N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates "
                               "--rootcert-file "
                               "/etc/pki/tls/certs/ca-bundle.crt "
                               "-C /etc/nagios/robot/robot.pem "
                               "-K /etc/nagios/robot/robot.key",
                    "subscriptions": ["argo.webui"],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_certificate_validity == "
                            "'generic.certificate.validity'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.certificate.validity",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_file_defined_attributes(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST4"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo-monitoring/probes/"
                               "eudat-b2access/check_b2access_simple.py "
                               "-H {{ .labels.hostname }} "
                               "--url https://b2access.fz-juelich.de:8443 "
                               "--username username --password pa55w0rD",
                    "subscriptions": ["b2access.unity", "argo.test"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eudat_b2access_unity_login_local == "
                            "'eudat.b2access.unity.login-local'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eudat.b2access.unity.login-local",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/"
                               "rciam_probes/checklogin "
                               "-H {{ .labels.hostname }} -t 10 "
                               "-i https://idp.admin.grnet.gr/idp/shibboleth "
                               "-s https://snf-666522.vm.okeanos.grnet.gr/"
                               "ni4os-rp/auth.php -C "
                               "-e https://mon-dev.rciam.grnet.gr/probes/"
                               "results "
                               "-u edugain_user -a 3dug41npwd",
                    "subscriptions": ["aai.oidc.login"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.grnet_rciam_oidc_login_edugain_"
                            "ni4os == "
                            "'grnet.rciam.oidc-login-edugain-ni4os'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "grnet.rciam.oidc-login-edugain-ni4os",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_SSL(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST7"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 60 --link "
                               "--onredirect follow "
                               "{{ .labels.ssl }} "
                               "-p {{ .labels.port }} "
                               "-u {{ .labels.path | default '/' }}",
                    "subscriptions": ["argo.webui"],
                    "handlers": ["publisher-handler"],
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
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_various_URLs(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST8"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_webdav "
                               "-H {{ .labels.hostname }} -t 600 -v -v "
                               "--no-crls "
                               "-u {{ .labels.info_service_endpoint_url }} "
                               "-E /etc/nagios/globus/userproxy.pem",
                    "subscriptions": ["webdav"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.ch_cern_webdav == "
                            "'ch.cern.WebDAV'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "ch.cern.WebDAV",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_webdav "
                               "-H {{ .labels.hostname }} -t 600 -v -v "
                               "--no-crls --dynafed --fixed-content-length "
                               "-u {{ .labels.info_service_endpoint_url }} "
                               "-E /etc/nagios/globus/userproxy.pem",
                    "subscriptions": ["ch.cern.dynafed"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.ch_cern_webdav_dynafed == "
                            "'ch.cern.WebDAV-dynafed'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "ch.cern.WebDAV-dynafed",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/"
                               "es.upv.grycap.im/probeim.py -t 60 -l NONE "
                               "--url {{ .labels.info_url }} "
                               "--token /etc/nagios/globus/oidc",
                    "subscriptions": ["es.upv.grycap.im"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_grycap_im_check == "
                            "'eu.egi.grycap.IM-Check'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.grycap.IM-Check",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_BDII(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST10"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_bdii_entries "
                               "-H {{ .labels.hostname }} -t 60 -c 40:1 "
                               "-w 20:1 -b {{ .labels.bdii_dn }} "
                               "-p 2170",
                    "subscriptions": ["Site-BDII", "Top-BDII"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_bdii_entries == "
                            "'org.bdii.Entries'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.bdii.Entries",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/midmon/"
                               "check_bdii_entries_num "
                               "-H {{ .labels.hostname }} -t 60 -c 1:1 "
                               "-f \"(&(objectClass=GLUE2Domain)"
                               "(GLUE2DomainID=$_SERVICESITE_NAME$))\" "
                               "-b {{ .labels.glue2_bdii_dn }} -p 2170",
                    "subscriptions": ["Site-BDII"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nagios_glue2_check == "
                            "'org.nagios.GLUE2-Check'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nagios.GLUE2-Check",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_mandatory_extensions(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST12"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/libexec/argo-monitoring/probes/"
                               "nagios-plugin-dynamic-dns/"
                               "nagios-plugin-dynamic-dns.sh "
                               "-H {{ .labels.hostname }} -t 120 "
                               "--endpoint-name {{ .labels.endpoint-name }}",
                    "subscriptions": ["eu.egi.cloud.dyndns"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_dyndns_check == "
                            "'eu.egi.cloud.DynDNS-Check'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.DynDNS-Check",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_optional_extensions(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST19"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_arcce_submit "
                               "-H {{ .labels.hostname }} "
                               "--job-tag dist-stage-srm --termination-service "
                               "org.nordugrid.ARC-CE-SRM-result-"
                               "$_SERVICEVO_FQAN$ --test dist-stage-srm "
                               "-O service_suffix=-$_SERVICEVO_FQAN$ "
                               "--command-file /var/nagios/rw/nagios.cmd "
                               "--how-invoked nagios -O good_ses_file="
                               "/var/lib/gridprobes/ops/GoodSEs --voms test "
                               "--fqan {{ .labels.vo_fqan }} "
                               "--user-proxy /etc/nagios/globus/userproxy.pem "
                               "{{ .labels.memory_limit__arc_ce_memory_limit "
                               "| default '' }}",
                    "subscriptions": ["ARC-CE"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nordugrid_arc_ce_srm_submit == "
                            "'org.nordugrid.ARC-CE-SRM-submit'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nordugrid.ARC-CE-SRM-submit",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_arcce_submit "
                               "-H {{ .labels.hostname }} "
                               "--termination-service "
                               "org.nordugrid.ARC-CE-result-"
                               "$_SERVICEVO_FQAN$ --test dist-caversion --test "
                               "dist-sw-csh --test dist-sw-gcc "
                               "--test dist-sw-python --test dist-sw-perl "
                               "-O service_suffix=-$_SERVICEVO_FQAN$ "
                               "--command-file /var/nagios/rw/nagios.cmd "
                               "--how-invoked nagios --voms test "
                               "--fqan {{ .labels.vo_fqan }} "
                               "--user-proxy /etc/nagios/globus/userproxy.pem "
                               "{{ .labels.memory_limit__arc_ce_memory_limit "
                               "| default '' }}",
                    "subscriptions": ["ARC-CE"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nordugrid_arc_ce_submit == "
                            "'org.nordugrid.ARC-CE-submit'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nordugrid.ARC-CE-submit",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_different_parameter_exts(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST20"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 30 -f \"follow\" "
                               "{{ .labels.u__rm_path | default '' }}",
                    "subscriptions": ["eu.seadatanet.org.replicationmanager"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels."
                            "eu_seadatanet_org_replicationmanager_check == "
                            "'eu.seadatanet.org.replicationmanager-check'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.seadatanet.org.replicationmanager-check",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/"
                               "sdc-replication-manager/"
                               "replication_manager_check.py "
                               "-H {{ .labels.hostname }} -t 30 "
                               "{{ .labels.r__rm_path | default '' }}",
                    "subscriptions": ["eu.seadatanet.org.replicationmanager"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels."
                            "eu_seadatanet_org_replicationmanager_check_"
                            "status == "
                            "'eu.seadatanet.org.replicationmanager-check-"
                            "status'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.seadatanet.org.replicationmanager-check-"
                                "status",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_openstack_check_configuration(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST13"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo-monitoring/probes/fedcloud/"
                               "cloudinfo.py -t 300 "
                               "--endpoint {{ .labels.info_url }}",
                    "subscriptions": ["org.openstack.nova"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_infoprovider == "
                            "'eu.egi.cloud.InfoProvider'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.InfoProvider",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/fedcloud/"
                               "swiftprobe.py -t 300 "
                               "--endpoint {{ .labels.info_url }} "
                               "--access-token /etc/nagios/globus/oidc",
                    "subscriptions": ["org.openstack.swift"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_openstack_swift == "
                            "'eu.egi.cloud.OpenStack-Swift'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.OpenStack-Swift",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/fedcloud/"
                               "novaprobe.py -t 300 -v "
                               "--access-token /etc/nagios/globus/oidc "
                               "--appdb-image xxxx "
                               "--endpoint {{ .labels.info_url }} "
                               "--cert /etc/nagios/globus/userproxy.pem "
                               "{{ .labels.region__os_region | default '' }}",
                    "subscriptions": ["org.openstack.nova"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_openstack_vm == "
                            "'eu.egi.cloud.OpenStack-VM'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.OpenStack-VM",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-t 120 -p {{ .labels.os_keystone_port }} "
                               "-H {{ .labels.os_keystone_host }}",
                    "subscriptions": ["org.openstack.nova"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nagios_keystone_tcp == "
                            "'org.nagios.Keystone-TCP'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nagios.Keystone-TCP",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_pakiti_check_configuration(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST15"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/grid-monitoring/probes/eu.egi.sec/"
                               "probes/check_pakiti_vuln "
                               "-H {{ .labels.hostname }} -t 30 --vo test "
                               "--cert /etc/nagios/globus/hostcert.pem "
                               "--key /etc/nagios/globus/hostkey.pem "
                               "--site {{ .labels.site }}",
                    "subscriptions": ["ARC-CE"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_sec_arcce_pakiti_check == "
                            "'eu.egi.sec.ARCCE-Pakiti-Check'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.sec.ARCCE-Pakiti-Check",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_SITE_BDII(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST16"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/lib64/nagios/plugins/srm/srm_probe.py "
                               "-H {{ .labels.hostname }} -t 300 -d "
                               "-p eu.egi.SRM --se-timeout 260 --voname test "
                               "-X /etc/nagios/globus/userproxy.pem "
                               "--ldap-url {{ .labels.site_bdii }} "
                               "{{ .labels.endpoint__surl | default '' }}",
                    "subscriptions": ["SRM"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_srm_all == "
                            "'eu.egi.SRM-All'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.SRM-All",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_ARC_GOOD_SES(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST17"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_arcce_submit "
                               "-H {{ .labels.hostname }} "
                               "--job-tag dist-stage-srm --termination-service "
                               "org.nordugrid.ARC-CE-SRM-result-"
                               "$_SERVICEVO_FQAN$ --test dist-stage-srm "
                               "-O service_suffix=-$_SERVICEVO_FQAN$ "
                               "--command-file /var/nagios/rw/nagios.cmd "
                               "--how-invoked nagios "
                               "-O good_ses_file=/var/lib/gridprobes/ops/"
                               "GoodSEs --voms test "
                               "--fqan {{ .labels.vo_fqan }} "
                               "--user-proxy /etc/nagios/globus/userproxy.pem "
                               "{{ .labels.memory_limit__arc_ce_memory_limit "
                               "| default '' }}",
                    "subscriptions": ["ARC-CE"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nordugrid_arc_ce_srm_submit == "
                            "'org.nordugrid.ARC-CE-SRM-submit'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nordugrid.ARC-CE-SRM-submit",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_HOSTDN(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST18"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/libexec/grid-monitoring/probes/"
                               "org.qoscosgrid/broker/qcg-broker-probe "
                               "-H {{ .labels.hostname }} -t 600 -p 8443 "
                               "-n {{ .labels.info_hostdn }} "
                               "-x /etc/nagios/globus/userproxy.pem",
                    "subscriptions": ["QCG.Broker"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.pl_plgrid_qcg_broker == "
                            "'pl.plgrid.QCG-Broker'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "pl.plgrid.QCG-Broker",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_local_topology(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST21"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 "
                               "-w 30 -c 0 -N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates --rootcert-file"
                               " /etc/pki/tls/certs/ca-bundle.crt "
                               "-C /etc/nagios/globus/hostcert.pem "
                               "-K /etc/nagios/globus/hostkey.pem",
                    "subscriptions": ["argo.mon"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_certificate_validity == "
                            "'generic.certificate.validity'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.certificate.validity",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_secrets(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST22"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file="/path/to/secrets"
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            checks,
            [
                {
                    "command": "source /path/to/secrets ; "
                               "export $(cut -d= -f1 /path/to/secrets) ; "
                               "/usr/libexec/argo/probes/grnet-agora/"
                               "checkhealth -H {{ .labels.hostname }} -v -i "
                               "-u $AGORA_USERNAME -p $AGORA_PASSWORD",
                    "subscriptions": ["eu.eudat.itsm.spmt"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.grnet_agora_healthcheck == "
                            "'grnet.agora.healthcheck'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "grnet.agora.healthcheck",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_with_secrets_with_dots(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST23"],
            metric_profiles=mock_metric_profiles,
            topology=mock_local_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file="/path/to/secrets"
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            checks,
            [
                {
                    "command": "source /path/to/secrets ; "
                               "export $(cut -d= -f1 /path/to/secrets) ; "
                               "/usr/libexec/argo-monitoring/probes/argo/"
                               "web-api -H {{ .labels.hostname }} -t 120 "
                               "--tenant EGI --rtype ar --unused-reports "
                               "Cloud Critical-Fedcloud Fedcloud NGIHRTest "
                               "--day 1 --token $API_TOKEN",
                    "subscriptions": ["argo.api"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_api_check == "
                            "'argo.API-Check'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.API-Check",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_check_configuration_if_NOPUBLISH(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST24"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        checks = generator.generate_checks(publish=True, namespace="mockspace")
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo-monitoring/probes/argo/"
                               "ams-publisher-probe "
                               "-s /var/run/argo-nagios-ams-publisher/sock "
                               "-q 'w:metrics+g:published180' -c 4000 -q "
                               "'w:alarms+g:published180' -c 1 "
                               "-q 'w:metricsdevel+g:published180' -c 4000",
                    "subscriptions": ["argo.test"],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_amspublisher_check == "
                            "'argo.AMSPublisher-Check'"
                        ]
                    },
                    "interval": 10800,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.AMSPublisher-Check",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": ["argo.test"],
                    "handlers": ["publisher-handler"],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace"
                    },
                    "round_robin": False
                }
            ]
        )

    def test_generate_entity_configuration(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST5"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_ar_argoui_ni4os":
                                "generic.http.ar-argoui-ni4os",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "argo-devel.ni4os.eu",
                            "info_url": "http://argo-devel.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET"
                        }
                    },
                    "subscriptions": ["argo.webui"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_ar_argoui_ni4os":
                                "generic.http.ar-argoui-ni4os",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET"
                        }
                    },
                    "subscriptions": ["argo.webui"]
                }
            ]
        )

    def test_generate_entities_with_port_and_path(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST6"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui__hpc.resource.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "hostname": "hpc.resource.ni4os.eu",
                            "port": "1022",
                            "service": "eu.ni4os.hpc.ui",
                            "site": "IPB"
                        }
                    },
                    "subscriptions": ["eu.ni4os.hpc.ui"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui__teran.srce.hr",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "hostname": "teran.srce.hr",
                            "port": "22",
                            "service": "eu.ni4os.hpc.ui",
                            "site": "SRCE"
                        }
                    },
                    "subscriptions": ["eu.ni4os.hpc.ui"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "web.check__bioinformatics.cing.ac.cy",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "bioinformatics.cing.ac.cy",
                            "port": "443",
                            "path": "/MelGene/",
                            "ssl": "-S --sni",
                            "info_url":
                                "https://bioinformatics.cing.ac.cy/MelGene/",
                            "service": "web.check",
                            "site": "CING"
                        }
                    },
                    "subscriptions": ["web.check"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "web.check__eewrc-las.cyi.ac.cy",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "eewrc-las.cyi.ac.cy",
                            "port": "80",
                            "path": "/las/getUI.do",
                            "ssl": "",
                            "info_url":
                                "http://eewrc-las.cyi.ac.cy/las/getUI.do",
                            "service": "web.check",
                            "site": "CYI"
                        }
                    },
                    "subscriptions": ["web.check"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "web.check__sampaeos.if.usp.br",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "sampaeos.if.usp.br",
                            "port": "9000",
                            "path": "//eos/ops/opstest/",
                            "ssl": "-S --sni",
                            "info_url":
                                "https://sampaeos.if.usp.br:9000//eos/ops/"
                                "opstest/",
                            "service": "web.check",
                            "site": "SAMPA"
                        }
                    },
                    "subscriptions": ["web.check"]
                },
            ]
        )

    def test_generate_entities_with_SSL(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST7"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "argo-devel.ni4os.eu",
                            "path": "/",
                            "port": "80",
                            "ssl": "",
                            "info_url": "http://argo-devel.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET"
                        }
                    },
                    "subscriptions": ["argo.webui"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "argo.ni4os.eu",
                            "path": "/",
                            "port": "443",
                            "ssl": "-S --sni",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET"
                        }
                    },
                    "subscriptions": ["argo.webui"]
                }
            ]
        )

    def test_generate_entities_with_URLs(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST8"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "ch.cern.dynafed__dynafed.hostname.ca",
                        "namespace": "default",
                        "labels": {
                            "ch_cern_webdav_dynafed": "ch.cern.WebDAV-dynafed",
                            "hostname": "dynafed.hostname.ca",
                            "info_url":
                                "https://dynafed.hostname.ca:443/dynafed/ops",
                            "info_service_endpoint_url":
                                "https://dynafed.hostname.ca:443/dynafed/ops",
                            "service": "ch.cern.dynafed",
                            "site": "CA-UVic-Cloud",
                            "info_hostdn": "/C=CA/O=Grid/CN=dynafed.hostname.ca"
                        }
                    },
                    "subscriptions": ["ch.cern.dynafed"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "es.upv.grycap.im__grycap.upv.es",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_grycap_im_check": "eu.egi.grycap.IM-Check",
                            "hostname": "grycap.upv.es",
                            "info_url": "https://grycap.upv.es:31443/im/",
                            "service": "es.upv.grycap.im",
                            "site": "UPV-GRyCAP"
                        }
                    },
                    "subscriptions": ["es.upv.grycap.im"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__hostname.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "ch_cern_webdav": "ch.cern.WebDAV",
                            "hostname": "hostname.cern.ch",
                            "info_url":
                                "https://hostname.cern.ch/atlas/opstest",
                            "info_service_endpoint_url":
                                "https://hostname.cern.ch/atlas/opstest",
                            "service": "webdav",
                            "site": "CERN-PROD"
                        }
                    },
                    "subscriptions": ["webdav"]
                }
            ]
        )

    def test_generate_entities_with_multiple_endpoint_URLs(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST9"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "mock.webdav__dpm.bla.meh.com",
                        "namespace": "default",
                        "labels": {
                            "ch_cern_webdav": "ch.cern.WebDAV",
                            "hostname": "dpm.bla.meh.com",
                            "info_url": "https://dpm.bla.meh.com/dpm/ops/",
                            "info_service_endpoint_url":
                                "https://mock.url.com/dpm/ops",
                            "service": "mock.webdav",
                            "site": "WEBDAV-test",
                            "info_hostdn": "/CN=host/dpm.bla.meh.com"
                        }
                    },
                    "subscriptions": ["mock.webdav"]
                }
            ]
        )

    def test_generate_entities_with_BDII(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST10"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "Site-BDII__grid-giis1.desy.de",
                        "namespace": "default",
                        "labels": {
                            "org_bdii_entries": "org.bdii.Entries",
                            "org_nagios_glue2_check":
                                "org.nagios.GLUE2-Check",
                            "hostname": "grid-giis1.desy.de",
                            "bdii_dn": "Mds-Vo-Name=DESY-HH,O=Grid",
                            "bdii_type": "bdii_site",
                            "glue2_bdii_dn": "GLUE2DomainID=DESY-HH,o=glue",
                            "service": "Site-BDII",
                            "site": "DESY-HH",
                            "site_bdii": "grid-giis1.desy.de",
                            "info_url": "ldap://grid-giis1.desy.de:2170/"
                                        "mds-vo-name=DESY-HH,o=grid"
                        }
                    },
                    "subscriptions": ["Site-BDII"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "Site-BDII__kser.arnes.si",
                        "namespace": "default",
                        "labels": {
                            "org_bdii_entries": "org.bdii.Entries",
                            "org_nagios_glue2_check":
                                "org.nagios.GLUE2-Check",
                            "hostname": "kser.arnes.si",
                            "bdii_dn": "Mds-Vo-Name=ARNES,O=Grid",
                            "bdii_type": "bdii_site",
                            "glue2_bdii_dn": "GLUE2DomainID=ARNES,o=glue",
                            "service": "Site-BDII",
                            "site": "ARNES",
                            "site_bdii": "kser.arnes.si",
                            "info_hostdn": "/C=SI/O=SiGNET/O=Arnes/"
                                           "CN=kser.arnes.si"
                        }
                    },
                    "subscriptions": ["Site-BDII"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "Site-BDII__sbdii.test.com",
                        "namespace": "default",
                        "labels": {
                            "org_bdii_entries": "org.bdii.Entries",
                            "org_nagios_glue2_check":
                                "org.nagios.GLUE2-Check",
                            "hostname": "sbdii.test.com",
                            "bdii_dn": "Mds-Vo-Name=SBDII,O=Grid",
                            "bdii_type": "bdii_site",
                            "glue2_bdii_dn": "GLUE2DomainID=SBDII,o=glue",
                            "service": "Site-BDII",
                            "site": "SBDII",
                            "site_bdii": "sbdii.test.com"
                        }
                    },
                    "subscriptions": ["Site-BDII"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "Top-BDII__bdii1.test.com",
                        "namespace": "default",
                        "labels": {
                            "org_bdii_entries": "org.bdii.Entries",
                            "hostname": "bdii1.test.com",
                            "bdii_dn": "Mds-Vo-Name=local,O=Grid",
                            "bdii_type": "bdii_top",
                            "glue2_bdii_dn": "GLUE2DomainID=BDII,o=glue",
                            "service": "Top-BDII",
                            "site": "BDII"
                        }
                    },
                    "subscriptions": ["Top-BDII"]
                }
            ]
        )

    def test_generate_entities_with_different_PORTs(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST11"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.app.web__catalogue.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "catalogue.ni4os.eu",
                            "info_url": "https://catalogue.ni4os.eu/",
                            "ssl": "-S --sni",
                            "path": "/",
                            "port": "443",
                            "service": "eu.ni4os.app.web",
                            "site": "IPB"
                        }
                    },
                    "subscriptions": ["eu.ni4os.app.web"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui__hpc.resource.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "hostname": "hpc.resource.ni4os.eu",
                            "port": "1022",
                            "service": "eu.ni4os.hpc.ui",
                            "site": "IPB"
                        }
                    },
                    "subscriptions": ["eu.ni4os.hpc.ui"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui__teran.srce.hr",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "hostname": "teran.srce.hr",
                            "port": "22",
                            "service": "eu.ni4os.hpc.ui",
                            "site": "SRCE"
                        }
                    },
                    "subscriptions": ["eu.ni4os.hpc.ui"]
                }
            ]
        )

    def test_generate_entities_with_mandatory_extensions(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST12"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.egi.cloud.dyndns__dns1.cloud.test.eu",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_dyndns_check":
                                "eu.egi.cloud.DynDNS-Check",
                            "hostname": "dns1.cloud.test.eu",
                            "info_url": "https://dns1.cloud.test.eu/",
                            "endpoint-name": "nsupdate",
                            "service": "eu.egi.cloud.dyndns",
                            "site": "EGI-DDNS"
                        }
                    },
                    "subscriptions": ["eu.egi.cloud.dyndns"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.egi.cloud.dyndns__dns2.cloud.test.eu",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_dyndns_check":
                                "eu.egi.cloud.DynDNS-Check",
                            "hostname": "dns2.cloud.test.eu",
                            "endpoint-name": "secondary",
                            "service": "eu.egi.cloud.dyndns",
                            "site": "EGI-DDNS"
                        }
                    },
                    "subscriptions": ["eu.egi.cloud.dyndns"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.egi.cloud.dyndns__dns3.cloud.test.eu",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_dyndns_check":
                                "eu.egi.cloud.DynDNS-Check",
                            "hostname": "dns3.cloud.test.eu",
                            "endpoint-name": "primary",
                            "service": "eu.egi.cloud.dyndns",
                            "site": "EGI-DDNS"
                        }
                    },
                    "subscriptions": ["eu.egi.cloud.dyndns"]
                }
            ]
        )

    def test_generate_entities_with_optional_extensions(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST20"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.seadatanet.org.replicationmanager__"
                                "185.229.108.85",
                        "namespace": "default",
                        "labels": {
                            "eu_seadatanet_org_replicationmanager_check":
                                "eu.seadatanet.org.replicationmanager-check",
                            "eu_seadatanet_org_replicationmanager_check_status":
                                "eu.seadatanet.org.replicationmanager-check-"
                                "status",
                            "info_url": "http://185.229.108.85:8080/",
                            "hostname": "185.229.108.85",
                            "service": "eu.seadatanet.org.replicationmanager",
                            "site": "GAMMA"
                        }
                    },
                    "subscriptions": ["eu.seadatanet.org.replicationmanager"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.seadatanet.org.replicationmanager__"
                                "hnodc-dm.ath.hcmr.gr",
                        "namespace": "default",
                        "labels": {
                            "eu_seadatanet_org_replicationmanager_check":
                                "eu.seadatanet.org.replicationmanager-check",
                            "eu_seadatanet_org_replicationmanager_check_status":
                                "eu.seadatanet.org.replicationmanager-check-"
                                "status",
                            "info_url": "http://hnodc-dm.ath.hcmr.gr/",
                            "u__rm_path": "-u /ReplicationManager/",
                            "r__rm_path": "-r /ReplicationManager/",
                            "hostname": "hnodc-dm.ath.hcmr.gr",
                            "service": "eu.seadatanet.org.replicationmanager",
                            "site": "HNODC"
                        }
                    },
                    "subscriptions": ["eu.seadatanet.org.replicationmanager"]
                }
            ]
        )

    def test_generate_openstack_entities(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST13"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "org.openstack.nova__"
                                "cloud-api-pub.cr.cnaf.infn.it",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_infoprovider":
                                "eu.egi.cloud.InfoProvider",
                            "eu_egi_cloud_openstack_vm":
                                "eu.egi.cloud.OpenStack-VM",
                            "org_nagios_keystone_tcp":
                                "org.nagios.Keystone-TCP",
                            "info_url": "https://cloud-api-pub.cr.cnaf.infn.it:"
                                        "5000/v3",
                            "os_keystone_port": "5000",
                            "os_keystone_host": "cloud-api-pub.cr.cnaf.infn.it",
                            "hostname": "cloud-api-pub.cr.cnaf.infn.it",
                            "region__os_region": "--region sdds",
                            "service": "org.openstack.nova",
                            "site": "INFN-CLOUD-CNAF"
                        }
                    },
                    "subscriptions": ["org.openstack.nova"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "org.openstack.nova__egi-cloud.pd.infn.it",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_infoprovider":
                                "eu.egi.cloud.InfoProvider",
                            "eu_egi_cloud_openstack_vm":
                                "eu.egi.cloud.OpenStack-VM",
                            "org_nagios_keystone_tcp":
                                "org.nagios.Keystone-TCP",
                            "info_url": "https://egi-cloud.pd.infn.it:443/v3",
                            "os_keystone_port": "443",
                            "os_keystone_host": "egi-cloud.pd.infn.it",
                            "hostname": "egi-cloud.pd.infn.it",
                            "service": "org.openstack.nova",
                            "site": "INFN-PADOVA-STACK"
                        }
                    },
                    "subscriptions": ["org.openstack.nova"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "org.openstack.swift__identity.cloud.muni.cz",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_openstack_swift":
                                "eu.egi.cloud.OpenStack-Swift",
                            "info_url": "https://identity.cloud.muni.cz/v3",
                            "os_keystone_host": "identity.cloud.muni.cz",
                            "hostname": "identity.cloud.muni.cz",
                            "service": "org.openstack.swift",
                            "site": "CESNET-MCC"
                        }
                    },
                    "subscriptions": ["org.openstack.swift"]
                }
            ]
        )

    def test_generate_multiple_same_host_entities(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST14"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "egi.aai.oidc__aai.eosc-portal.eu",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_aai_oidc_login": "eu.egi.AAI-OIDC-Login",
                            "info_url": "https://aai.eosc-portal.eu/oidc",
                            "info_service_endpoint_url":
                                "https://aai.eosc-portal.eu/oidc/.well-known/"
                                "openid-configuration",
                            "hostname": "aai.eosc-portal.eu",
                            "service": "egi.aai.oidc",
                            "site": "GRIDOPS-CheckIn"
                        }
                    },
                    "subscriptions": ["egi.aai.oidc"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "egi.aai.saml__aai.eosc-portal.eu",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_aai_saml_login": "eu.egi.AAI-SAML-Login",
                            "info_url": "https://aai.eosc-portal.eu/proxy",
                            "info_service_endpoint_url":
                                "https://aai.eosc-portal.eu/proxy/saml2/idp/"
                                "metadata.php",
                            "hostname": "aai.eosc-portal.eu",
                            "service": "egi.aai.saml",
                            "site": "GRIDOPS-CheckIn"
                        }
                    },
                    "subscriptions": ["egi.aai.saml"]
                }
            ]
        )

    def test_generate_entities_with_SITE_BDII(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST16"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "SRM__dcache-se-cms.desy.de",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_srm_all": "eu.egi.SRM-All",
                            "hostname": "dcache-se-cms.desy.de",
                            "site_bdii": "grid-giis1.desy.de",
                            "service": "SRM",
                            "endpoint__surl":
                                "--endpoint srm://dcache-se-cms.desy.de:8443"
                                "/srm/managerv2?SFN=/pnfs/desy.de/ops",
                            "site": "DESY-HH"
                        }
                    },
                    "subscriptions": ["SRM"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "SRM__dcache.arnes.si",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_srm_all": "eu.egi.SRM-All",
                            "hostname": "dcache.arnes.si",
                            "site_bdii": "kser.arnes.si",
                            "service": "SRM",
                            "site": "ARNES",
                            "info_hostdn": "/C=SI/O=SiGNET/O=Arnes/"
                                           "CN=dcache.arnes.si"
                        }
                    },
                    "subscriptions": ["SRM"]
                }
            ]
        )

    def test_generate_entities_with_ARC_CE_MEMORY_LIMIT(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST17"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        entities = generator.generate_entities()
        self.assertEqual(
            entities,
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "ARC-CE__gridarcce01.mesocentre.uca.fr",
                        "namespace": "default",
                        "labels": {
                            "org_nordugrid_arc_ce_srm_submit":
                                "org.nordugrid.ARC-CE-SRM-submit",
                            "hostname": "gridarcce01.mesocentre.uca.fr",
                            "service": "ARC-CE",
                            "site": "AUVERGRID"
                        }
                    },
                    "subscriptions": ["ARC-CE"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "ARC-CE__alien.spacescience.ro",
                        "namespace": "default",
                        "labels": {
                            "org_nordugrid_arc_ce_srm_submit":
                                "org.nordugrid.ARC-CE-SRM-submit",
                            "hostname": "alien.spacescience.ro",
                            "service": "ARC-CE",
                            "site": "RO-13-ISS",
                            "memory_limit__arc_ce_memory_limit":
                                "--memory-limit 268435456"
                        }
                    },
                    "subscriptions": ["ARC-CE"]
                }
            ]
        )

    def test_generate_entities_with_local_topology(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST21"],
            metric_profiles=mock_metric_profiles,
            topology=mock_local_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )

        entities = generator.generate_entities()

        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.mon__argo-mon-devel.egi.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "argo-mon-devel.egi.eu",
                            "service": "argo.mon",
                            "site": "SRCE"
                        }
                    },
                    "subscriptions": ["argo.mon"]
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.mon__argo-mon-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "argo-mon-devel.ni4os.eu",
                            "service": "argo.mon",
                            "site": "SRCE"
                        }
                    },
                    "subscriptions": ["argo.mon"]
                }
            ]
        )

    def test_generate_subscriptions(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST1"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            local_attributes=os.path.join(os.getcwd(), 'ncg.conf'),
            secrets_file=""
        )
        subscriptions = generator.generate_subscriptions()
        self.assertEqual(sorted(subscriptions), ["argo.test", "argo.webui"])
