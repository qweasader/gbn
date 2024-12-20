# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70769");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-7243", "CVE-2009-5016", "CVE-2010-1128", "CVE-2010-1129", "CVE-2010-1130", "CVE-2010-1860", "CVE-2010-1861", "CVE-2010-1862", "CVE-2010-1864", "CVE-2010-1866", "CVE-2010-1868", "CVE-2010-1914", "CVE-2010-1915", "CVE-2010-1917", "CVE-2010-2093", "CVE-2010-2094", "CVE-2010-2097", "CVE-2010-2100", "CVE-2010-2101", "CVE-2010-2190", "CVE-2010-2191", "CVE-2010-2225", "CVE-2010-2484", "CVE-2010-2531", "CVE-2010-2950", "CVE-2010-3062", "CVE-2010-3063", "CVE-2010-3064", "CVE-2010-3065", "CVE-2010-3436", "CVE-2010-3709", "CVE-2010-3710", "CVE-2010-3870", "CVE-2010-4150", "CVE-2010-4409", "CVE-2010-4645", "CVE-2010-4697", "CVE-2010-4698", "CVE-2010-4699", "CVE-2010-4700", "CVE-2011-0420", "CVE-2011-0421", "CVE-2011-0708", "CVE-2011-0752", "CVE-2011-0753", "CVE-2011-0755", "CVE-2011-1092", "CVE-2011-1148", "CVE-2011-1153", "CVE-2011-1464", "CVE-2011-1466", "CVE-2011-1467", "CVE-2011-1468", "CVE-2011-1469", "CVE-2011-1470", "CVE-2011-1471", "CVE-2011-1657", "CVE-2011-1938", "CVE-2011-2202", "CVE-2011-2483", "CVE-2011-3182", "CVE-2011-3189", "CVE-2011-3267", "CVE-2011-3268");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 18:38:19 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:39 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201110-06 (php)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in PHP, the worst of which
    leading to remote execution of arbitrary code.");
  script_tag(name:"solution", value:"All PHP users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.3.8'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-06");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=306939");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=332039");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=340807");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=350908");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=355399");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=358791");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=358975");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=369071");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=372745");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=373965");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=380261");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201110-06.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"dev-lang/php", unaffected: make_list("ge 5.3.8"), vulnerable: make_list("lt 5.3.8"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
