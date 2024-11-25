# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66448");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2009-3560", "CVE-2009-3720");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 12 FEDORA-2009-12737 (expat)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Two buffer over-read flaws were found in the way Expat handled malformed UTF-8
sequences when processing XML files.  A specially-crafted XML file could cause
applications using Expat to crash while parsing the file. (CVE-2009-3560,
CVE-2009-3720)

ChangeLog:

  * Tue Dec  1 2009 Joe Orton  - 2.0.1-8

  - add security fix for CVE-2009-3560 (#533174)

  - add security fix for CVE-2009-3720 (#531697)

  - run the test suite");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update expat' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-12737");
  script_tag(name:"summary", value:"The remote host is missing an update to expat
announced via advisory FEDORA-2009-12737.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=533174");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=531697");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
