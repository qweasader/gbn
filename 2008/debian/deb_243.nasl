# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 243-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53318");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1393");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 243-1 (kdemultimedia)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20243-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6462");
  script_tag(name:"insight", value:"The KDE team discovered several vulnerabilities in the K Desktop
Environment.  In some instances KDE fails to properly quote parameters
of instructions passed to a command shell for execution.  These
parameters may incorporate data such as URLs, filenames and e-mail
addresses, and this data may be provided remotely to a victim in an
e-mail, a webpage or files on a network filesystem or other untrusted
source.

By carefully crafting such data an attacker might be able to execute
arbitrary commands on a vulnerable system using the victim's account and
privileges.  The KDE Project is not aware of any existing exploits of
these vulnerabilities.  The patches also provide better safe guards
and check data from untrusted sources more strictly in multiple
places.

For the current stable distribution (woody), these problems have been
fixed in version 2.2.2-8.2.  Please note that we are unable to provide
updated packages for both MIPS architectures since the compilation of
kdemultimedia triggers an internal compiler error on these machines.

The old stable distribution (potato) does not contain KDE packages.

For the unstable distribution (sid), these problems will most probably
not be fixed but new packages for KDE 3.1 for sid are expected for
this year.");

  script_tag(name:"solution", value:"We recommend that you upgrade your KDE packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to kdemultimedia
announced via advisory DSA 243-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"artsbuilder", ver:"2.2.2-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdemultimedia-dev", ver:"2.2.2-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kmid", ver:"2.2.2-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kmidi", ver:"2.2.2-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kmix", ver:"2.2.2-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kscd", ver:"2.2.2-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarts-mpeglib", ver:"2.2.2-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mpeglib", ver:"2.2.2-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"noatun", ver:"2.2.2-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
