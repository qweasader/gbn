# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64226");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
  script_cve_id("CVE-2009-0153");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 9 FEDORA-2009-6121 (icu)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"CVE-2009-0153 Handle illegal sequences consistently

ChangeLog:

  * Thu Jun 11 2009 Caolan McNamara  - 3.8.1-9

  - Resolves: rhbz#505368 CVE-2009-0153 Handle illegal sequences consistently

  * Tue Aug 26 2008 Caolan McNamara  - 3.8.1-8

  - Resolves: rhbz#459698 drop Malayalam patches. Note test with
multiple fonts and not just Lohit Malayalam before filing bugs against icu
wrt. Malayalam rendering.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update icu' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6121");
  script_tag(name:"summary", value:"The remote host is missing an update to icu
announced via advisory FEDORA-2009-6121.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503071");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
