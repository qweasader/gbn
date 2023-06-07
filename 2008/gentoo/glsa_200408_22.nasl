###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54652");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0763", "CVE-2004-0758", "CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200408-22 (mozilla)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"New releases of Mozilla, Epiphany, Galeon, Mozilla Thunderbird, and Mozilla
Firefox fix several vulnerabilities, including remote DoS and buffer
overflows.");
  script_tag(name:"solution", value:"All users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv your-version
    # emerge your-version");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200408-22");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=57380");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=59419");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200408-22.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-www/mozilla", unaffected: make_list("ge 1.7.2"), vulnerable: make_list("lt 1.7.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-firefox", unaffected: make_list("ge 0.9.3"), vulnerable: make_list("lt 0.9.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird", unaffected: make_list("ge 0.7.3"), vulnerable: make_list("lt 0.7.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-bin", unaffected: make_list("ge 1.7.2"), vulnerable: make_list("lt 1.7.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-firefox-bin", unaffected: make_list("ge 0.9.3"), vulnerable: make_list("lt 0.9.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 0.7.3"), vulnerable: make_list("lt 0.7.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/epiphany", unaffected: make_list("ge 1.2.7-r1"), vulnerable: make_list("lt 1.2.7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/galeon", unaffected: make_list("ge 1.3.17"), vulnerable: make_list("lt 1.3.17"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
