# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121299");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:28:10 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_name("Gentoo Security Advisory GLSA 201412-13");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Chromium. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201412-13");
  script_cve_id("CVE-2014-3188", "CVE-2014-3189", "CVE-2014-3190", "CVE-2014-3191", "CVE-2014-3192", "CVE-2014-3193", "CVE-2014-3194", "CVE-2014-3195", "CVE-2014-3197", "CVE-2014-3198", "CVE-2014-3199", "CVE-2014-3200", "CVE-2014-7899", "CVE-2014-7900", "CVE-2014-7901", "CVE-2014-7902", "CVE-2014-7903", "CVE-2014-7904", "CVE-2014-7906", "CVE-2014-7907", "CVE-2014-7908", "CVE-2014-7909", "CVE-2014-7910");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201412-13");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-client/chromium", unaffected: make_list("ge 39.0.2171.65"), vulnerable: make_list("lt 39.0.2171.65"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
