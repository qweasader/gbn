# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 171-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53427");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1174", "CVE-2002-1175");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 171-1 (fetchmail, fetchmail-ssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20171-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5825");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5826");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5827");
  script_tag(name:"insight", value:"Stefan Esser discovered several buffer overflows and a broken boundary
check within fetchmail.  If fetchmail is running in multidrop mode
these flaws can be used by remote attackers to crash it or to execute
arbitrary code under the user id of the user running fetchmail.
Depending on the configuration this even allows a remote root
compromise.

These problems have been fixed in version 5.9.11-6.1 for both
fetchmail and fetchmail-ssl for the current stable distribution
(woody), in version 5.3.3-4.2 for fetchmail for the old stable
distribution (potato) and in version 6.1.0-1 for both fetchmail and
fetchmail-ssl for the unstable distribution (sid).  There are no
fetchmail-ssl packages for the old stable distribution (potato) and
thus no updates.");

  script_tag(name:"solution", value:"We recommend that you upgrade your fetchmail packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to fetchmail, fetchmail-ssl
announced via advisory DSA 171-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"fetchmailconf", ver:"5.3.3-4.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fetchmail", ver:"5.3.3-4.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fetchmail-common", ver:"5.9.11-6.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fetchmailconf", ver:"5.9.11-6.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fetchmail", ver:"5.9.11-6.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fetchmail-ssl", ver:"5.9.11-6.1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
