# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 417-2
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
  script_oid("1.3.6.1.4.1.25623.1.0.53118");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0985");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 417-2 (kernel-image-2.4.18-1-alpha)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20417-2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9356");
  script_tag(name:"insight", value:"Since DSA 417-1 lacked fixed kernel image files for the alpha
architecture these are added now.  For completeness below is the
original advisory:

Paul Starzetz discovered a flaw in bounds checking in mremap() in
the Linux kernel (present in version 2.4.x and 2.6.x) which may
allow a local attacker to gain root privileges.  Version 2.2 is not
affected by this bug.

For the stable distribution (woody) this problem has been fixed in
version 2.4.18-13 for the alpha architecture.

For the unstable distribution (sid) this problem will be fixed soon
with newly uploaded packages.");

  script_tag(name:"solution", value:"We recommend that you upgrade your kernel packages.  This problem has");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel-image-2.4.18-1-alpha
announced via advisory DSA 417-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1", ver:"2.4.18-13", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-generic", ver:"2.4.18-13", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-smp", ver:"2.4.18-13", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-generic", ver:"2.4.18-13", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-smp", ver:"2.4.18-13", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
