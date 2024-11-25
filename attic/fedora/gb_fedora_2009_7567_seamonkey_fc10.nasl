# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64399");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-2210", "CVE-2009-1841", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1835", "CVE-2009-1832", "CVE-2009-1311", "CVE-2009-1307");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-7567 (seamonkey)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to upstream version 1.1.17, fixing multiple security flaws.

ChangeLog:

  * Fri Jul 10 2009 Martin Stransky  1.1.17-1

  - Update to 1.1.17

  * Thu May  7 2009 Kai Engert  1.1.16-1

  - Update to 1.1.16");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update seamonkey' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7567");
  script_tag(name:"summary", value:"The remote host is missing an update to seamonkey
announced via advisory FEDORA-2009-7567.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=507812");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503583");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503578");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503580");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503576");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503569");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496271");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496263");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
