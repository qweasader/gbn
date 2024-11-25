# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63787");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 10 FEDORA-2009-2805 (ntop)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

ls -lh /var/log/ntop/access.log  -rw-rw-rw- 1 root root 0 2009-02-04 11:53
/var/log/ntop/access.log    Fixed.  log world-writable when the --access-log-
file option is used.    This option is not used in Fedora or Red Hat by default
and is not noted in the configuration file.  It is, however, noted in the ntop
manpage. It would require the root user to add this option to the configuration
in order for this file to be created.

ChangeLog:

  * Tue Mar 17 2009 Rakesh Pandit  - 3.3.8-3

  - Fixed world writable accesslog (#490561) - security bug

  * Tue Mar  3 2009 Peter Vrabec  - 3.3.8-2

  - invalid certificate fix (#486725)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update ntop' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2805");
  script_tag(name:"summary", value:"The remote host is missing an update to ntop
announced via advisory FEDORA-2009-2805.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490561");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
