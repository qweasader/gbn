# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57967");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2006-5870");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200701-07 (openoffice)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A truncation error and integer overflows in the EMF/WMF file handling of
OpenOffice.org could be exploited to execute arbitrary code.");
  script_tag(name:"solution", value:"All OpenOffice.org binary users should update to version 2.1.0 or later:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-bin-2.1.0'

All OpenOffice.org users should update to version 2.0.4 or later:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-2.0.4'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200701-07");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=159951");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200701-07.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-office/openoffice-bin", unaffected: make_list("ge 2.1.0"), vulnerable: make_list("lt 2.1.0"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("ge 2.0.4"), vulnerable: make_list("lt 2.0.4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
