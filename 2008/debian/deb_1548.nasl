# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 1548-1 (xpdf)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60795");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-04-21 20:40:14 +0200 (Mon, 21 Apr 2008)");
  script_cve_id("CVE-2008-1693");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 1548-1 (xpdf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201548-1");
  script_tag(name:"insight", value:"Kees Cook discovered a vulnerability in xpdf, set set of tools for
display and conversion of Portable Document Format (PDF) files.  The
Common Vulnerabilities and Exposures project identifies the following
problem:

CVE-2008-1693

Xpdf's handling of embedded fonts lacks sufficient validation
and type checking.  If a maliciously-crafted PDF file is opened,
the vulnerability may allow the execution of arbitrary code with
the privileges of the user running xpdf.

For the stable distribution (etch), these problems have been fixed in
version 3.01-9.1+etch3.

For the unstable distribution (sid), these problems were fixed in
version 3.02-1.2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your xpdf package.");
  script_tag(name:"summary", value:"The remote host is missing an update to xpdf
announced via advisory DSA 1548-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"xpdf", ver:"3.01-9.1+etch4", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xpdf-common", ver:"3.01-9.1+etch4", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xpdf-reader", ver:"3.01-9.1+etch4", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xpdf-utils", ver:"3.01-9.1+etch4", rls:"DEB4")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
