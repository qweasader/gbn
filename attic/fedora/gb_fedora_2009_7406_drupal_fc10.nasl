# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64354");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-07-06 20:36:15 +0200 (Mon, 06 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 10 FEDORA-2009-7406 (drupal)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"For details, on the issues addressed, please visit the
referenced security advisories.

ChangeLog:

  * Thu Jul  2 2009 Jon Ciesla  - 6.13-1

  - Update to 6.11, SA-CORE-2009-007.

  - Added clarifying text on module installation to readme, BZ 500707.

  * Thu May 14 2009 Jon Ciesla  - 6.12-1

  - Update to 6.11, SA-CORE-2009-006.

  * Thu Apr 30 2009 Jon Ciesla  - 6.11-1

  - Update to 6.11, SA-CORE-2009-005.

  * Mon Apr 27 2009 Jon Ciesla  - 6.10-2

  - Added SELinux/sendmail note to README, BZ 497642.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update drupal' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7406");
  script_tag(name:"summary", value:"The remote host is missing an update to drupal
announced via advisory FEDORA-2009-7406.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=500707");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
