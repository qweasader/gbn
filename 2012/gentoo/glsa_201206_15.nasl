# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71582");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-5063", "CVE-2011-2501", "CVE-2011-2690", "CVE-2011-2691", "CVE-2011-2692", "CVE-2011-3026", "CVE-2011-3045", "CVE-2011-3048", "CVE-2011-3464");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:55 -0400 (Fri, 10 Aug 2012)");
  script_name("Gentoo Security Advisory GLSA 201206-15 (libpng)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in libpng might allow remote attackers to
execute arbitrary code or cause a Denial of Service condition.");
  script_tag(name:"solution", value:"All libpng 1.5 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libpng-1.5.10'


All libpng 1.2 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libpng-1.2.49'


Packages which depend on this library may need to be recompiled. Tools
such as revdep-rebuild may assist in identifying some of these
packages.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-15");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=373967");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=386185");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=401987");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=404197");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=410153");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201206-15.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge 1.5.10", "rge 1.2.49"), vulnerable: make_list("lt 1.5.10"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
