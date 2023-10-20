# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61052");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-4879", "CVE-2008-0304", "CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241", "CVE-2008-1380");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200805-18 (mozilla ...)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported in Mozilla Firefox,
Thunderbird, SeaMonkey and XULRunner, some of which may allow
user-assisted execution of arbitrary code.");
  script_tag(name:"solution", value:"Upgrade to the latest package. For details, please visit the
referenced security advisory.

NOTE: The crash vulnerability (CVE-2008-1380) is currently unfixed in the
SeaMonkey binary ebuild, as no precompiled packages have been released.
Until an update is available, we recommend all SeaMonkey users to disable
JavaScript, use Firefox for JavaScript-enabled browsing, or switch to the
SeaMonkey source ebuild.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200805-18");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=208128");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=214816");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=218065");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200805-18.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-client/mozilla-firefox", unaffected: make_list("ge 2.0.0.14"), vulnerable: make_list("lt 2.0.0.14"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/mozilla-firefox-bin", unaffected: make_list("ge 2.0.0.14"), vulnerable: make_list("lt 2.0.0.14"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird", unaffected: make_list("ge 2.0.0.14"), vulnerable: make_list("lt 2.0.0.14"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 2.0.0.14"), vulnerable: make_list("lt 2.0.0.14"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/seamonkey", unaffected: make_list("ge 1.1.9-r1"), vulnerable: make_list("lt 1.1.9-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/seamonkey-bin", unaffected: make_list("ge 1.1.9"), vulnerable: make_list("lt 1.1.9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-libs/xulrunner", unaffected: make_list("ge 1.8.1.14"), vulnerable: make_list("lt 1.8.1.14"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
