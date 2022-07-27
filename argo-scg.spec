%define underscore() %(echo %1 | sed 's/-/_/g')
%define stripc() %(echo %1 | sed 's/el7.centos/el7/')
%define mydist %{stripc %{dist}}

Summary:       ARGO Sensu configuration manager.
Name:          argo-scg
Version:       0.1.0
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


%clean
rm -rf $RPM_BUILD_ROOT


%files -f INSTALLED_FILES
%defattr(-,root,root)
%config(noreplace) %{_sysconfdir}/%{name}/scg.conf
%dir %{python3_sitelib}/%{underscore %{name}}/
%{python3_sitelib}/%{underscore %{name}}/*.py

%attr(0755,root,root) %dir %{_localstatedir}/log/argo-scg/

%changelog
* Thu May 5 2022 Katarina Zailac <kzailac@srce.hr> - 0.1.0-1%{?dist}
- ARGO-3606 Investigate Sensu as replacement for Nagios
