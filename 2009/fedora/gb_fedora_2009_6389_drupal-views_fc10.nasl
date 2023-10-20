# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64232");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 10 FEDORA-2009-6389 (drupal-views)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

  * Advisory ID: DRUPAL-SA-CONTRIB-2009-037 [0]

  * Project: Views

  * Versions: 6.x-2.x

  * Date: 2009-June-10

  * Security risk: Moderately critical

  * Exploitable from: Remote

  * Vulnerability: Cross Site Scripting (XSS), Access Bypass

ChangeLog:

  * Thu Jun 11 2009 Jon Ciesla  - 6.x.2.6-1

  - New upstream, fixes SA-CONTRIB-2009-037.

  * Tue Feb 24 2009 Fedora Release Engineering  - 6.x.2.2-2

  * Thu Dec 18 2008 Jon Ciesla  - 6.x.2.2-1

  - New upstream, fixes SA-2008-075.

  * Tue Nov  4 2008 Jon Ciesla  - 6.x.2.1-1

  - New upstream.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update drupal-views' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6389");
  script_tag(name:"summary", value:"The remote host is missing an update to drupal-views
announced via advisory FEDORA-2009-6389.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"drupal-views", rpm:"drupal-views~6.x.2.6~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
