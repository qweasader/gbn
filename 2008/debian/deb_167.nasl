# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 167-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc.
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53424");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1151");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 167-1 (Konquerer)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20167-1");
  script_tag(name:"insight", value:"A cross site scripting problem has been discovered in Konquerer, a
famous browser for KDE and other programs using KHTML.  The KDE team
reports that Konqueror's cross site scripting protection fails to
initialize the domains on sub-(i)frames correctly.  As a result,
Javascript is able to access any foreign subframe which is defined in
the HTML source.  Users of Konqueror and other KDE software that uses
the KHTML rendering engine may become victim of a cookie stealing and
other cross site scripting attacks.

This problem has been fixed in version 2.2.2-13.woody.3 for the
current stable distribution (woody) and in version 2.2.2-14 for the
unstable distribution (sid).  The old stable distribution (potato) is
not affected since it didn't ship KDE.");

  script_tag(name:"solution", value:"We recommend that you upgrade your kdelibs package and restart");
  script_tag(name:"summary", value:"The remote host is missing an update to Konquerer
announced via advisory DSA 167-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kdelibs3-doc", ver:"2.2.2-13.woody.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdelibs3", ver:"2.2.2-13.woody.3", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
