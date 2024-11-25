# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65001");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-10-06 02:49:40 +0200 (Tue, 06 Oct 2009)");
  script_cve_id("CVE-2009-2813", "CVE-2009-2948", "CVE-2009-2906", "CVE-2009-0022", "CVE-2008-4314");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-10172 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Security Release, fixes CVE-2009-2813, CVE-2009-2948 and CVE-2009-2906

ChangeLog:

  * Thu Oct  1 2009 Guenther Deschner  - 3.2.15-0.36

  - Update to 3.2.15

  - Security Release, fixes CVE-2009-2813, CVE-2009-2948 and CVE-2009-2906");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update samba' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10172");
  script_tag(name:"summary", value:"The remote host is missing an update to samba
announced via advisory FEDORA-2009-10172.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=523752");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526074");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526645");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
