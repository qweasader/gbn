# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 202-2
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
  script_oid("1.3.6.1.4.1.25623.1.0.53448");
  script_cve_id("CVE-2002-1395");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Debian Security Advisory DSA 202-2 (im)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20202-2");
  script_tag(name:"insight", value:"Despite popular belief, the IM packages are not architecture
independent, since the number of the fsync syscal is detected on
build time and this number differs on Linux architectures and
other operating systems.  As a result of this the optional feature
``NoSync=no'' does only work on the architecture the package was
built on.  As usual, we are including the text of the original
advisory DSA 202-1:

Tatsuya Kinoshita discovered that IM, which contains interface
commands and Perl libraries for E-mail and NetNews, creates
temporary files insecurely.

1. The impwagent program creates a temporary directory in an
insecure manner in /tmp using predictable directory names
without checking the return code of mkdir, so it's possible to
seize a permission of the temporary directory by local access
as another user.

2. The immknmz program creates a temporary file in an insecure
manner in /tmp using a predictable filename, so an attacker
with local access can easily create and overwrite files as
another user.

This problem has been fixed in version 141-18.2 for the current
stable distribution (woody), in version 133-2.3 of the old stable
distribution (potato).  A correection is expected for the unstable
distribution (sid) soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your IM package.");
  script_tag(name:"summary", value:"The remote host is missing an update to im
announced via advisory DSA 202-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"im", ver:"133-2.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"im", ver:"141-18.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
