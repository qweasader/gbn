# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58317");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-1362", "CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200706-06 (mozilla/thunderbird/firefox/xulrunner)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported in Mozilla Firefox,
Thunderbird, SeaMonkey and XULRunner, some of which may allow
user-assisted arbitrary remote code execution.

For details on the issues addressed with this update,
please visit the referenced security advisories.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200706-06");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=180436");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200706-06.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-client/mozilla-firefox", unaffected: make_list("ge 2.0.0.4"), vulnerable: make_list("lt 2.0.0.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/mozilla-firefox-bin", unaffected: make_list("ge 2.0.0.4"), vulnerable: make_list("lt 2.0.0.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird", unaffected: make_list("ge 2.0.0.4", "rge 1.5.0.12"), vulnerable: make_list("lt 2.0.0.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 2.0.0.4", "rge 1.5.0.12"), vulnerable: make_list("lt 2.0.0.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/seamonkey", unaffected: make_list("ge 1.1.2"), vulnerable: make_list("lt 1.1.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/seamonkey-bin", unaffected: make_list("ge 1.1.2"), vulnerable: make_list("lt 1.1.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-libs/xulrunner", unaffected: make_list("ge 1.8.1.4"), vulnerable: make_list("lt 1.8.1.4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
