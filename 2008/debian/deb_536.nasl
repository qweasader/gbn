# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 536-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53226");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1363", "CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599", "CVE-2004-0768");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 536-1 (libpng)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20536-1");
  script_tag(name:"insight", value:"Chris Evans discovered several vulnerabilities in libpng:

CVE-2004-0597 - Multiple buffer overflows exist, including when
handling transparency chunk data, which could be exploited to cause
arbitrary code to be executed when a specially crafted PNG image is
processed

CVE-2004-0598 - Multiple NULL pointer dereferences in
png_handle_iCPP() and elsewhere could be exploited to cause an
application to crash when a specially crafted PNG image is processed

CVE-2004-0599 - Multiple integer overflows in png_handle_sPLT(),
png_read_png() nctions and elsewhere could be exploited to cause an
application to crash, or potentially arbitrary code to be executed,
when a specially crafted PNG image is processed

In addition, a bug related to CVE-2002-1363 was fixed:

CVE-2004-0768 - A buffer overflow could be caused by incorrect
calculation of buffer offsets, possibly leading to the execution of
arbitrary code

For the current stable distribution (woody), these problems have been
fixed in libpng3 version 1.2.1-1.1.woody.7 and libpng version
1.0.12-3.woody.7.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you update your libpng and libpng3 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to libpng
announced via advisory DSA 536-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libpng2", ver:"1.0.12-3.woody.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng2-dev", ver:"1.0.12-3.woody.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng-dev", ver:"1.2.1-1.1.woody.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.1-1.1.woody.7", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
