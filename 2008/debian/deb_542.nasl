# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 542-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53232");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 542-1 (qt-copy)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20542-1");
  script_tag(name:"insight", value:"Several vulnerabilities were discovered in recent versions of Qt, a
commonly used graphic widget set, used in KDE for example.  The first
problem allows an attacker to execute arbitrary code, while the other
two only seem to pose a denial of service danger.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:

CVE-2004-0691:

Chris Evans has discovered a heap-based overflow when handling
8-bit RLE encoded BMP files.

CVE-2004-0692:

Marcus Meissner has discovered a crash condition in the XPM
handling code, which is not yet fixed in Qt 3.3.

CVE-2004-0693:

Marcus Meissner has discovered a crash condition in the GIF
handling code, which is not yet fixed in Qt 3.3.

For the stable distribution (woody) this problem has been fixed in
version 3.0.3-20020329-1woody2.

For the unstable distribution (sid) this problem has been fixed in
version 3.3.3-4 of qt-x11-free.");

  script_tag(name:"solution", value:"We recommend that you upgrade your qt packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to qt-copy
announced via advisory DSA 542-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"qt3-doc", ver:"3.0.3-20020329-1woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt3", ver:"3.0.3-20020329-1woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt3-dev", ver:"3.0.3-20020329-1woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt3-mt", ver:"3.0.3-20020329-1woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt3-mt-dev", ver:"3.0.3-20020329-1woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt3-mt-mysql", ver:"3.0.3-20020329-1woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt3-mt-odbc", ver:"3.0.3-20020329-1woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt3-mysql", ver:"3.0.3-20020329-1woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt3-odbc", ver:"3.0.3-20020329-1woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqxt0", ver:"3.0.3-20020329-1woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qt3-tools", ver:"3.0.3-20020329-1woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}