# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63676");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
  script_cve_id("CVE-2008-5718");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-3069 (netatalk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

The bug fixes backporting from upstream.
ChangeLog:

  * Mon Feb 16 2009 Jiri Skala  -4:2.0.3-23

  - fix #480641 - CVE-2008-5718 netatalk: papd command injection vulnerability

  * Wed Jan  7 2009 Jiri Skala  - 4:2.0.3-22

  - #473939 - BuildRequires updated quota -> quota-devel");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update netatalk' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3069");
  script_tag(name:"summary", value:"The remote host is missing an update to netatalk
announced via advisory FEDORA-2009-3069.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=480641");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
