# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64538");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Fedora Core 11 FEDORA-2009-7924 (pdfedit)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Free pdf editing using PdfEdit. Complete editing of pdf documents is made
possible with PDFedit. You can change either raw pdf objects (for advanced
users) or use predefined gui functions. Functions can be easily added as
everything is based on a script.

Update Information:

Update to new upstream version 0.4.3 fixing multiple issues:

  * xpdf code base updated to 3.02pl3 patch which fixes
  several serious remote vulnerabilities

  * French translation update (bug 275)

  * Fix for [33853] Secunia advisory backported from poppler

  * Flattener class implemented (bt#289)

  * Bugs 248, 256, 285, ...

ChangeLog:

  * Tue Jul 21 2009 Bernard Johnson - 0.4.3-1");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update pdfedit' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7924");
  script_tag(name:"summary", value:"The remote host is missing an update to pdfedit
announced via advisory FEDORA-2009-7924.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
