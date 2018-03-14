# pdcfw - manages PDC Linux Netfilter/IPtables firewall configuration

# pdcfw.spec - pdcfw rpmbuild spec file
# Author: Ilari Korhonen, KTH Royal Institute of Technology
#
# Copyright (C) 2018 KTH Royal Institute of Technology. All rights reserved.
# See LICENSE file for more information.

Summary: pdcfw IPTables/netfilter firewall manager
Name: pdcfw
Version: 0.1.0
Release: 1
License: BSD
Group: Applications/System
%undefine _disable_source_fetch
Source: https://github.com/KTH-PDC/pdcfw/archive/%{version}.tar.gz
URL: https://github.com/KTH-PDC/pdcfw
Distribution: CentOS
BuildArch: noarch
Vendor: KTH
Packager: Ilari Korhonen <ilarik@kth.se>

%description
A utility for managing Linux IPTables/netfilter firewall rule sets.

%prep

%setup -q -c

%build

%install
mkdir -p %{buildroot}/etc/pdcfw
mkdir -p %{buildroot}/etc/sysconfig
mkdir -p %{buildroot}/opt/pdcfw
mkdir -p %{buildroot}/opt/pdcfw/rsyslog.d

cp %{name}-%{version}/LICENSE %{buildroot}/opt/pdcfw
cp %{name}-%{version}/pdcfw %{buildroot}/opt/pdcfw
cp %{name}-%{version}/functions.sh %{buildroot}/opt/pdcfw
cp %{name}-%{version}/etc/pdcfw/local-forward.sh %{buildroot}/etc/pdcfw
cp %{name}-%{version}/etc/pdcfw/local-input.sh %{buildroot}/etc/pdcfw
cp %{name}-%{version}/etc/pdcfw/local-output.sh %{buildroot}/etc/pdcfw
cp %{name}-%{version}/etc/pdcfw/main.sh %{buildroot}/etc/pdcfw
cp %{name}-%{version}/etc/sysconfig/pdcfw %{buildroot}/etc/sysconfig/pdcfw
cp %{name}-%{version}/etc/rsyslog.d/pdcfw.conf %{buildroot}/opt/pdcfw/rsyslog.d

%files
%defattr(-,root,root,-)
%attr(644,root,root) /opt/pdcfw/LICENSE
%attr(644,root,root) /opt/pdcfw/functions.sh
%attr(755,root,root) /opt/pdcfw/pdcfw
%attr(644,root,root) /etc/pdcfw/local-forward.sh
%attr(644,root,root) /etc/pdcfw/local-input.sh
%attr(644,root,root) /etc/pdcfw/local-output.sh
%attr(644,root,root) /etc/pdcfw/main.sh
%attr(644,root,root) /etc/sysconfig/pdcfw
%attr(644,root,root) /opt/pdcfw/rsyslog.d/pdcfw.conf

%post
ln -s /opt/pdcfw/pdcfw /usr/bin/pdcfw

%changelog
* Wed Mar 14 2018 Ilari Korhonen <ilarik@kth.se>
* first RPM release
