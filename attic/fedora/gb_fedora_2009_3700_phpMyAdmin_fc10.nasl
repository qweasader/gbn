# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63834");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2009-1285");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-04-20 23:45:17 +0200 (Mon, 20 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-3700 (phpMyAdmin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Improvements for 3.1.3.2:  - [security] Insufficient output sanitizing when
generating configuration file

ChangeLog:

  * Tue Apr 14 2009 Robert Scheck  3.1.3.2-1

  - Upstream released 3.1.3.2 (#495768)

  * Wed Mar 25 2009 Robert Scheck  3.1.3.1-1

  - Upstream released 3.1.3.1 (#492066)

  * Sun Mar  1 2009 Robert Scheck  3.1.3-1

  - Upstream released 3.1.3");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update phpMyAdmin' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3700");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34526");
  script_tag(name:"summary", value:"The remote host is missing an update to phpMyAdmin
announced via advisory FEDORA-2009-3700.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495768");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
