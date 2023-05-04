%define underscore() %(echo %1 | sed 's/-/_/g')
%define stripc() %(echo %1 | sed 's/el7.centos/el7/')
%define mydist %{stripc %{dist}}

Summary:       ARGO Sensu configuration manager.
Name:          argo-scg
Version:       0.2.1
Release:       1%{?dist}
Source0:       %{name}-%{version}.tar.gz
License:       ASL 2.0
Group:         Development/System
BuildRoot:     %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Prefix:        %{_prefix}
BuildArch:     noarch

BuildRequires: python3-devel
Requires:      python36-requests


%description
Package includes script that configures Sensu checks, entities, and namespaces using information from POEM and Web-API. It also includes tool used for preparation of Sensu event data for ARGO AMS Publisher.


%prep
%setup -q


%build
%{py3_build}


%install
%{py3_install "--record=INSTALLED_FILES" }
install --directory %{buildroot}/%{_localstatedir}/log/argo-scg/


%clean
rm -rf $RPM_BUILD_ROOT


%files -f INSTALLED_FILES
%defattr(-,root,root)
%config(noreplace) %{_sysconfdir}/%{name}/scg.conf
%dir %{python3_sitelib}/%{underscore %{name}}/
%{python3_sitelib}/%{underscore %{name}}/*.py

%attr(0755,root,root) %dir %{_localstatedir}/log/argo-scg/

%changelog
* Thu May 4 2023 Katarina Zailac <kzailac@srce.hr> - 0.2.1-1%{?dist}
- ARGO-4272 Handle checks with timeout
- ARGO-4270 Filtering OK events not working
- ARGO-4269 Refactor sensu-events tool to display entity names instead of hostnames
- ARGO-4254 scg-run-check.py not working as expected
- ARGO-4238 Possibility to change slack pipeline
- ARGO-4234 Create custom display of events
- ARGO-4231 Handle overrides for the same metric, but different hostnames
* Thu Mar 2 2023 Katarina Zailac <kzailac@srce.hr> - 0.1.1-1%{?dist}
- ARGO-4235 Remove regex validation of entity names
- ARGO-4228 Create tool to acknowledge alerts
- ARGO-4224 Skip configuration in case of data fetch error
- ARGO-4223 Create a tool that is going to force run check for an entity
- ARGO-4222 Create a tool that is going to display how exactly the probe is invoked
- ARGO-4091Delete all the resources in the namespace when it is no longer used
- ARGO-4215 Send entire metric output message to publisher
- ARGO-4193 Log calls to ams-metric-to-queue tool
- ARGO-4203 Send hostname_id in metric result
- ARGO-4197 Skip creation of improperly formatted entities
- ARGO-4189 Send metric output to ams
- ARGO-4139 Possibility to override default arguments
- ARGO-4137 Tool not creating "path" label for entity
- ARGO-4092 Add topology filtering
- ARGO-4090 The tool not creating labels for agent
- ARGO-4098 Bug with metric parameter overrides
- ARGO-4079 The tool not reporting missing metric configuration
- ARGO-4047 Create tool for ad hoc check execution request
- ARGO-4002 Remove hard-coded default ports
- ARGO-4003 Handle hostnames in tags
- ARGO-3999 Remove hard-coded list of secrets
- ARGO-3986 Tool not handling *_URL attributes properly
- ARGO-3956 Include filter mimicking hard/soft state to non-internal checks
- ARGO-3945 Include internal checks for sensu agent
- ARGO-3944 Improve filter for internal events
- ARGO-3910 Improve logging when setting up the configuration
- ARGO-3917 Handle attribute names which are not all capital letters
- ARGO-3913 Add extra filter to mimic hard/soft state for some metrics
- ARGO-3801 Add feature to override parameters from POEM
- ARGO-3761 Handle filters and handlers for tenants not using the publisher
- ARGO-3760 Treat "default" namespace differently
* Thu May 5 2022 Katarina Zailac <kzailac@srce.hr> - 0.1.0-1%{?dist}
- ARGO-3606 Investigate Sensu as replacement for Nagios
