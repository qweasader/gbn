# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121037");
  script_version("2024-07-10T05:05:27+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:25:59 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2024-07-10 05:05:27 +0000 (Wed, 10 Jul 2024)");
  script_name("Gentoo Security Advisory GLSA 201309-23");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Mozilla Firefox, Thunderbird, and SeaMonkey. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201309-23");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0744", "CVE-2013-0745", "CVE-2013-0746", "CVE-2013-0747", "CVE-2013-0748", "CVE-2013-0749", "CVE-2013-0750", "CVE-2013-0751", "CVE-2013-0752", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0755", "CVE-2013-0756", "CVE-2013-0757", "CVE-2013-0758", "CVE-2013-0759", "CVE-2013-0760", "CVE-2013-0761", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0764", "CVE-2013-0765", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0768", "CVE-2013-0769", "CVE-2013-0770", "CVE-2013-0771", "CVE-2013-0772", "CVE-2013-0773", "CVE-2013-0774", "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0777", "CVE-2013-0778", "CVE-2013-0779", "CVE-2013-0780", "CVE-2013-0781", "CVE-2013-0782", "CVE-2013-0783", "CVE-2013-0784", "CVE-2013-0787", "CVE-2013-0788", "CVE-2013-0789", "CVE-2013-0791", "CVE-2013-0792", "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0797", "CVE-2013-0799", "CVE-2013-0800", "CVE-2013-0801", "CVE-2013-1670", "CVE-2013-1671", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681", "CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1697", "CVE-2013-1701", "CVE-2013-1702", "CVE-2013-1704", "CVE-2013-1705", "CVE-2013-1707", "CVE-2013-1708", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1711", "CVE-2013-1712", "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717", "CVE-2013-1718", "CVE-2013-1719", "CVE-2013-1720", "CVE-2013-1722", "CVE-2013-1723", "CVE-2013-1724", "CVE-2013-1725", "CVE-2013-1726", "CVE-2013-1728", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737", "CVE-2013-1738");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 18:25:57 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201309-23");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"mail-client/thunderbird", unaffected: make_list("ge 17.0.9"), vulnerable: make_list("lt 17.0.9"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/firefox", unaffected: make_list("ge 17.0.9"), vulnerable: make_list("lt 17.0.9"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/seamonkey", unaffected: make_list("ge 2.21"), vulnerable: make_list("lt 2.21"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"mail-client/thunderbird-bin", unaffected: make_list("ge 17.0.9"), vulnerable: make_list("lt 17.0.9"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/firefox-bin", unaffected: make_list("ge 17.0.9"), vulnerable: make_list("lt 17.0.9"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/seamonkey-bin", unaffected: make_list("ge 2.21"), vulnerable: make_list("lt 2.21"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
