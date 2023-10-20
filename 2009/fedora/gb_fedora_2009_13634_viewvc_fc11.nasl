# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66587");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 11 FEDORA-2009-13634 (viewvc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Update Information:

  * security fix: add root listing support of per-root authz config

  * security fix: query.py requires 'forbidden' authorizer (or none) in config

  * fix URL-ification of truncated log messages (issue #3)

  * fix regexp input validation (issue #426, #427, #440)

  * add support for configurable tab-to-spaces conversion

  * fix not-a-sequence error in diff view

  * allow viewvc-install to work when templates-contrib is absent

  * minor template improvements/corrections

  * expose revision metadata in diff view (issue #431)

  * markup file/directory item property URLs and email addresses (issue #434)

  * make ViewVC cross copies in Subversion history by default

  * fix bug that caused standalone.py failure under Python 1.5.2 (issue #442)

  * fix support for per-vhost overrides of authorizer parameters (issue #411)

  * fix root name identification in query.py interface

ChangeLog:

  * Wed Dec 23 2009 Bojan Smojver  - 1.1.3-1

  - bump up to 1.1.3

  - drop patch for upstream issue #427");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update viewvc' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13634");
  script_tag(name:"summary", value:"The remote host is missing an update to viewvc
announced via advisory FEDORA-2009-13634.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"viewvc", rpm:"viewvc~1.1.3~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"viewvc-httpd", rpm:"viewvc-httpd~1.1.3~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
