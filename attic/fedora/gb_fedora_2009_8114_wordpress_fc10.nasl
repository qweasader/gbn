# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64540");
  script_cve_id("CVE-2009-2851");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 10 FEDORA-2009-8114 (wordpress)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Wordpress is an online publishing / weblog package that makes it very easy,
almost trivial, to get information out to people on the web.

ChangeLog:

  * Tue Jul 28 2009 Adrian Reber  - 2.8.2-1

  - updated to 2.8.2 for security fixes - BZ 512900

  - fixed wrong-script-end-of-line-encoding of license.txt

  - correctly disable auto update check

  - fixed an error message from 'find' during the build

  * Mon Jul 27 2009 Fedora Release Engineering  - 2.8.1-2");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update wordpress' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8114");
  script_tag(name:"summary", value:"The remote host is missing an update to wordpress
announced via advisory FEDORA-2009-8114.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512900");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
