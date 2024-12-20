# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121418");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"creation_date", value:"2015-11-08 13:04:38 +0200 (Sun, 08 Nov 2015)");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_name("Gentoo Security Advisory GLSA 201510-05");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in MediaWiki. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201510-05");
  script_cve_id("CVE-2015-2931", "CVE-2015-2932", "CVE-2015-2933", "CVE-2015-2934", "CVE-2015-2935", "CVE-2015-2936", "CVE-2015-2937", "CVE-2015-2938", "CVE-2015-2939", "CVE-2015-2940", "CVE-2015-2941", "CVE-2015-2942", "CVE-2015-6728", "CVE-2015-6729", "CVE-2015-6730", "CVE-2015-6731", "CVE-2015-6732", "CVE-2015-6733", "CVE-2015-6734", "CVE-2015-6735", "CVE-2015-6736", "CVE-2015-6737");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201510-05");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-apps/mediawiki", unaffected: make_list("ge 1.25.2"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-apps/mediawiki", unaffected: make_list("ge 1.24.3"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-apps/mediawiki", unaffected: make_list("ge 1.23.10"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-apps/mediawiki", unaffected: make_list(), vulnerable: make_list("lt 1.25.2"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
