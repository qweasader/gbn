# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64697");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2334", "CVE-2009-2335", "CVE-2009-2336");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 11 FEDORA-2009-8529 (wordpress-mu)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update spans MU-versions for the following security releases:

  * Backport of XSS fixes from WordPress 2.8.2

  * Backport of security fixes for admin.php?page= bugs (CVE-2009-2334)

ChangeLog:

  * Wed Aug 12 2009 Bret McMillan  - 2.8.4a-1

  - Update to version 2.8.4a for security fixes

  * Fri Jul 10 2009 Bret McMillan  - 2.7-6

  - Patch for CVE-2009-2334");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update wordpress-mu' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8529");
  script_tag(name:"summary", value:"The remote host is missing an update to wordpress-mu
announced via advisory FEDORA-2009-8529.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=510745");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
