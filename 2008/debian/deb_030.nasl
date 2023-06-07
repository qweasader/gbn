# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 030-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53792");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 030-1 (xfree86-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20030-1");
  script_tag(name:"insight", value:"Chris Evans, Joseph S. Myers, Michal Zalewski, Alan Cox, and others have
noted a number of problems in several components of the X Window System
sample implementation (from which XFree86 is derived).  While there are no
known reports of real-world malicious exploits of any of these problems, it
is nevertheless suggested that you upgrade your XFree86 packages
immediately.

The scope of this advisory is XFree86 3.3.6 only, since that is the version
released with Debian GNU/Linux 2.2 ('potato'). Debian packages of XFree86
4.0 and later have not been released as part of a Debian distribution.

Several people are responsible for authoring the fixes to these problems,
including Aaron Campbell, Paulo Cesar Pereira de Andrade, Keith Packard,
David Dawes, Matthieu Herrb, Trevor Johnson, Colin Phipps, and Branden
Robinson.

For a more detailed description of the problems addressed, please visit
the referenced security advisory.

These problems have been fixed in version 3.3.6-11potato32 and we recommend
that you upgrade your X packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to xfree86-1
announced via advisory DSA 030-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"rstart", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xbase", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfree86-common", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"rstartd", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"twm", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xbase-clients", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xdm", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xext", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xf86setup", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xlib6g-dev", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xlib6g-static", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xlib6g", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xmh", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xnest", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xproxy", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xprt", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-3dlabs", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-common", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-fbdev", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-i128", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-mach64", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-mono", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-p9000", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-s3", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-s3v", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-svga", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-tga", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-vga16", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xsm", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xterm", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xvfb", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xlib6-altdev", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xlib6", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-8514", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-agx", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-mach32", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-mach8", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-w32", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-xsun-mono", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-xsun24", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xserver-xsun", ver:"3.3.6-11potato32", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
