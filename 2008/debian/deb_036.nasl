# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 036-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53798");
  script_cve_id("CVE-2000-1109");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 036-1 (mc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20036-1");
  script_tag(name:"insight", value:"It has been reported that a local user could tweak Midnight Commander
of another user into executing a random program under the user id of
the person running Midnight Commander.  This behaviour has been fixed
by Andrew V. Samoilov.

We recommend you upgrade your mc package.");
  script_tag(name:"summary", value:"The remote host is missing an update to mc
announced via advisory DSA 036-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gmc", ver:"4.5.42-11.potato.6", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mc-common", ver:"4.5.42-11.potato.6", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mc", ver:"4.5.42-11.potato.6", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
