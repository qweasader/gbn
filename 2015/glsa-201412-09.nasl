# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121295");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:28:05 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_name("Gentoo Security Advisory GLSA 201412-09");
  script_tag(name:"insight", value:"Vulnerabilities have been discovered in the packages listed below. Please review the CVE identifiers in the references for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201412-09");
  script_cve_id("CVE-2007-4370", "CVE-2009-4023", "CVE-2009-4111", "CVE-2010-0778", "CVE-2010-1780", "CVE-2010-1782", "CVE-2010-1783", "CVE-2010-1784", "CVE-2010-1785", "CVE-2010-1786", "CVE-2010-1787", "CVE-2010-1788", "CVE-2010-1790", "CVE-2010-1791", "CVE-2010-1792", "CVE-2010-1793", "CVE-2010-1807", "CVE-2010-1812", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-2526", "CVE-2010-2901", "CVE-2010-3255", "CVE-2010-3257", "CVE-2010-3259", "CVE-2010-3362", "CVE-2010-3374", "CVE-2010-3389", "CVE-2010-3812", "CVE-2010-3813", "CVE-2010-3999", "CVE-2010-4042", "CVE-2010-4197", "CVE-2010-4198", "CVE-2010-4204", "CVE-2010-4206", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4577", "CVE-2010-4578", "CVE-2011-0007", "CVE-2011-0465", "CVE-2011-0482", "CVE-2011-0721", "CVE-2011-0727", "CVE-2011-0904", "CVE-2011-0905", "CVE-2011-1072", "CVE-2011-1097", "CVE-2011-1144", "CVE-2011-1425", "CVE-2011-1572", "CVE-2011-1760", "CVE-2011-1951", "CVE-2011-2471", "CVE-2011-2472", "CVE-2011-2473", "CVE-2011-2524", "CVE-2011-3365", "CVE-2011-3366", "CVE-2011-3367");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 19:21:00 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201412-09");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"games-sports/racer-bin", unaffected: make_list(), vulnerable: make_list("lt 0.5.0-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/fmod", unaffected: make_list("ge 4.38.00"), vulnerable: make_list("lt 4.38.00"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-php/PEAR-Mail", unaffected: make_list("ge 1.2.0"), vulnerable: make_list("lt 1.2.0"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"sys-fs/lvm2", unaffected: make_list("ge 2.02.72"), vulnerable: make_list("lt 2.02.72"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-office/gnucash", unaffected: make_list("ge 2.4.4"), vulnerable: make_list("lt 2.4.4"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/xine-lib", unaffected: make_list("ge 1.1.19"), vulnerable: make_list("lt 1.1.19"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-sound/lastfmplayer", unaffected: make_list("ge 1.5.4.26862-r3"), vulnerable: make_list("lt 1.5.4.26862-r3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"net-libs/webkit-gtk", unaffected: make_list("ge 1.2.7"), vulnerable: make_list("lt 1.2.7"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"sys-apps/shadow", unaffected: make_list("ge 4.1.4.3"), vulnerable: make_list("lt 4.1.4.3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-php/PEAR-PEAR", unaffected: make_list("ge 1.9.2-r1"), vulnerable: make_list("lt 1.9.2-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-db/unixODBC", unaffected: make_list("ge 2.3.0-r1"), vulnerable: make_list("lt 2.3.0-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"sys-cluster/resource-agents", unaffected: make_list("ge 1.0.4-r1"), vulnerable: make_list("lt 1.0.4-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"net-misc/mrouted", unaffected: make_list("ge 3.9.5"), vulnerable: make_list("lt 3.9.5"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"net-misc/rsync", unaffected: make_list("ge 3.0.8"), vulnerable: make_list("lt 3.0.8"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-libs/xmlsec", unaffected: make_list("ge 1.2.17"), vulnerable: make_list("lt 1.2.17"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"x11-apps/xrdb", unaffected: make_list("ge 1.0.9"), vulnerable: make_list("lt 1.0.9"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"net-misc/vino", unaffected: make_list("ge 2.32.2"), vulnerable: make_list("lt 2.32.2"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-util/oprofile", unaffected: make_list("ge 0.9.6-r1"), vulnerable: make_list("lt 0.9.6-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-admin/syslog-ng", unaffected: make_list("ge 3.2.4"), vulnerable: make_list("lt 3.2.4"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"net-analyzer/sflowtool", unaffected: make_list("ge 3.20"), vulnerable: make_list("lt 3.20"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"gnome-base/gdm", unaffected: make_list("ge 3.8.4-r3"), vulnerable: make_list("lt 3.8.4-r3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"net-libs/libsoup", unaffected: make_list("ge 2.34.3"), vulnerable: make_list("lt 2.34.3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-misc/ca-certificates", unaffected: make_list("ge 20110502-r1"), vulnerable: make_list("lt 20110502-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-vcs/gitolite", unaffected: make_list("ge 1.5.9.1"), vulnerable: make_list("lt 1.5.9.1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-util/qt-creator", unaffected: make_list("ge 2.1.0"), vulnerable: make_list("lt 2.1.0"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
