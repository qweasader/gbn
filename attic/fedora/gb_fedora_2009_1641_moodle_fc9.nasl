# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63390");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2009-0499", "CVE-2008-5153", "CVE-2008-4796", "CVE-2009-0500", "CVE-2009-0502", "CVE-2009-0501");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-1641 (moodle)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Multiple security fixes.

ChangeLog:

  * Tue Feb 10 2009 Jon Ciesla  - 1.9.4-1

  - Update to 1.9.4 to fix CVE-2009-0499, 0500, 0501, 0502.

  * Tue Jan 27 2009 Jon Ciesla  - 1.9.3-6

  - Dropped and symlinked to khmeros-base-fonts.

  * Tue Jan 20 2009 Jon Ciesla  - 1.9.3-5

  - Dropped and symlinked illegal sm and to fonts.

  - Symlinking to FreeSans.

  - Drop spell-check-logic.cgi, CVE-2008-5153, per upstream, BZ 472117, 472119, 472120.

  * Wed Dec 17 2008 Jon Ciesla  - 1.9.3-4

  - Texed fix, BZ 476709.

  * Fri Nov  7 2008 Jon Ciesla  - 1.9.3-3

  - Moved to weekly downloaded 11/7/08 to fix Snoopy CVE-2008-4796.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update moodle' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1641");
  script_tag(name:"summary", value:"The remote host is missing an update to moodle
announced via advisory FEDORA-2009-1641.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484916");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484922");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484924");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484923");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
