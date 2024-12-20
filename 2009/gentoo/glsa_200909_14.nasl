# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64883");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
  script_cve_id("CVE-2008-5917", "CVE-2009-0930", "CVE-2009-0931", "CVE-2009-0932", "CVE-2009-2360");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("Gentoo Security Advisory GLSA 200909-14 (horde horde-imp horde-passwd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Horde and two modules,
    allowing for the execution of arbitrary code, information disclosure,
or
    Cross-Site Scripting.");
  script_tag(name:"solution", value:"All Horde users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-3.3.4

All Horde IMP users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-imp-4.3.4

All Horde Passwd users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-passwd-3.1.1");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200909-14");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=256125");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=262976");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=262978");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=277294");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200909-14.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-apps/horde", unaffected: make_list("ge 3.3.4"), vulnerable: make_list("lt 3.3.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-imp", unaffected: make_list("ge 4.3.4"), vulnerable: make_list("lt 4.3.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-passwd", unaffected: make_list("ge 3.1.1"), vulnerable: make_list("lt 3.1.1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
