# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64612");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 10 FEDORA-2009-8328 (wordpress)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Wordpress is an online publishing / weblog package that makes it very easy,
almost trivial, to get information out to people on the web.

Update Information:

Update to upstream version 2.8.3

ChangeLog:

  * Mon Aug  3 2009 Adrian Reber  - 2.8.3-1

  - updated to 2.8.3 for security fixes

  * Tue Jul 28 2009 Adrian Reber  - 2.8.2-1

  - updated to 2.8.2 for security fixes - BZ 512900

  - fixed wrong-script-end-of-line-encoding of license.txt

  - correctly disable auto update check

  - fixed an error message from 'find' during the build

  * Mon Jul 27 2009 Fedora Release Engineering  - 2.8.1-2

  * Fri Jul 10 2009 Adrian Reber  - 2.8.1-1

  - updated to 2.8.1 for security fixes - BZ 510745");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update wordpress' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8328");
  script_tag(name:"summary", value:"The remote host is missing an update to wordpress
announced via advisory FEDORA-2009-8328.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"wordpress", rpm:"wordpress~2.8.3~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
