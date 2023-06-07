# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 070-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53820");
  script_cve_id("CVE-2001-0554");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 070-1 (netkit-telnet)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20070-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/203000");
  script_tag(name:"insight", value:"The telnet daemon contained in the netkit-telnet_0.16-4potato1 package in
the 'stable' (potato) distribution of Debian GNU/Linux is vulnerable to an
exploitable overflow in its output handling.
The original bug was found by <scut@nb.in-berlin.de>, and announced to
bugtraq on Jul 18 2001. At that time, netkit-telnet versions after 0.14 were
not believed to be vulnerable.
On Aug 10 2001, zen-parse posted an advisory based on the same problem, for
all netkit-telnet versions below 0.17.
More details can be found on the references.
As Debian uses the 'telnetd' user to run in.telnetd, this is not a remote
root compromise on Debian systems. The 'telnetd' user can be compromised.

We strongly advise you update your netkit-telnet packages to the versions
listed below.");
  script_tag(name:"summary", value:"The remote host is missing an update to netkit-telnet
announced via advisory DSA 070-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"telnet", ver:"0.16-4potato.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"telnetd", ver:"0.16-4potato.2", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
