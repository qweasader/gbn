# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121315");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:28:17 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_name("Gentoo Security Advisory GLSA 201412-29");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Tomcat. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201412-29");
  script_cve_id("CVE-2012-2733", "CVE-2012-3544", "CVE-2012-3546", "CVE-2012-4431", "CVE-2012-4534", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887", "CVE-2013-2067", "CVE-2013-2071", "CVE-2013-4286", "CVE-2013-4322", "CVE-2013-4590", "CVE-2014-0033", "CVE-2014-0050", "CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099", "CVE-2014-0119");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201412-29");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-servers/tomcat", unaffected: make_list("ge 7.0.56"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-servers/tomcat", unaffected: make_list("ge 6.0.41"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-servers/tomcat", unaffected: make_list(), vulnerable: make_list("lt 7.0.56"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
