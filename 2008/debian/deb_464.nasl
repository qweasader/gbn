# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 464-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53161");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0111");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 464-1 (gdk-pixbuf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20464-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9842");
  script_tag(name:"insight", value:"Thomas Kristensen discovered a vulnerability in gdk-pixbuf (binary
package libgdk-pixbuf2), the GdkPixBuf image library for Gtk, that can
cause the surrounding application to crash.  To exploit this problem,
a remote attacker could send a carefully-crafted BMP file via mail,
which would cause e.g. Evolution to crash but is probably not limited
to Evolution.

For the stable distribution (woody) this problem has been fixed in
version 0.17.0-2woody1.

For the unstable distribution (sid) this problem has been fixed in
version 0.22.0-3.");

  script_tag(name:"solution", value:"We recommend that you upgrade your libgdk-pixbuf2 package.");
  script_tag(name:"summary", value:"The remote host is missing an update to gdk-pixbuf
announced via advisory DSA 464-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libgdk-pixbuf-dev", ver:"0.17.0-2woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgdk-pixbuf-gnome-dev", ver:"0.17.0-2woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgdk-pixbuf-gnome2", ver:"0.17.0-2woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgdk-pixbuf2", ver:"0.17.0-2woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
