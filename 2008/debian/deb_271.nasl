# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 271-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53340");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0162");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 271-1 (ecartis, listar)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20271-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6971");
  script_tag(name:"insight", value:"A problem has been discovered in ecartis, a mailing list manager,
formerly known as listar.  This vulnerability enables an attacker to
reset the password of any user defined on the list server, including
the list admins.

For the stable distribution (woody) this problem has been fixed in
version 0.129a+1.0.0-snap20020514-1.1 of ecartis.

For the old stable distribution (potato) this problem has been fixed
in version 0.129a-2.potato3 of listar.

For the unstable distribution (sid) this problem has been
fixed in version 1.0.0+cvs.20030321-1 of ecartis.");

  script_tag(name:"solution", value:"We recommend that you upgrade your ecartis and listar packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to ecartis, listar
announced via advisory DSA 271-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"listar", ver:"0.129a-2.potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"listar-cgi", ver:"0.129a-2.potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ecartis", ver:"0.129a+1.0.0-snap20020514-1.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ecartis-cgi", ver:"0.129a+1.0.0-snap20020514-1.1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}