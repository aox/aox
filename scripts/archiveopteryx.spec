Name:           archiveopteryx
Summary:        Mail archive server based on PostgreSQL
Version:        1.10
Release:        1
Group:          Productivity/Networking/Email/Servers
License:        OSL 2.1
URL:            http://www.archiveopteryx.org/
Source:         http://www.aox.org/download/%{name}-%{version}.tar.bz2
Vendor:         Oryx Mail Systems GmbH
Packager:       info@oryx.com
Patch:          aox-installroot.diff
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
Archiveopteryx provides IMAP access to an email archive stored in
a normalized PostgreSQL database. It is optimised for high-volume,
long-term archival.

Author:
    Oryx Mail Systems GmbH <info@oryx.com>
    http://www.archiveopteryx.org/

%prep
%setup
%patch

%build
jam

%install
jam -sINSTALLROOT=$RPM_BUILD_ROOT install

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
/usr/local/archiveopteryx/COPYING
/usr/local/archiveopteryx/README
/usr/local/archiveopteryx/bin/aox
/usr/local/archiveopteryx/bin/aoximport
/usr/local/archiveopteryx/bin/deliver
/usr/local/archiveopteryx/lib/archiveopteryx
/usr/local/archiveopteryx/lib/field-names
/usr/local/archiveopteryx/lib/flag-names
/usr/local/archiveopteryx/lib/grant-privileges
/usr/local/archiveopteryx/lib/installer
/usr/local/archiveopteryx/lib/schema.pg
/usr/local/archiveopteryx/man/man5/aoxsuper.conf.5
/usr/local/archiveopteryx/man/man5/archiveopteryx.conf.5
/usr/local/archiveopteryx/man/man7/oryx.7
/usr/local/archiveopteryx/man/man8/aox.8
/usr/local/archiveopteryx/man/man8/archiveopteryx.8
/usr/local/archiveopteryx/man/man8/deliver.8
/usr/local/archiveopteryx/man/man8/installer.8
/usr/local/archiveopteryx/man/man8/logd.8
/usr/local/archiveopteryx/man/man8/ms.8
/usr/local/archiveopteryx/man/man8/ocd.8
/usr/local/archiveopteryx/man/man8/recorder.8
/usr/local/archiveopteryx/man/man8/tlsproxy.8
/usr/local/archiveopteryx/osl-2.1.txt
/usr/local/archiveopteryx/sbin/archiveopteryx
/usr/local/archiveopteryx/sbin/logd
/usr/local/archiveopteryx/sbin/ocd
/usr/local/archiveopteryx/sbin/recorder
/usr/local/archiveopteryx/sbin/tlsproxy

%post
/usr/local/archiveopteryx/lib/installer

%changelog -n archiveopteryx
* Sat Sep 16 2006 - ams@oryx.com
- Build an RPM for SuSE 9.1
