# Copyright (C) 2012 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841237");
  script_cve_id("CVE-2012-0957", "CVE-2012-4565", "CVE-2012-6536", "CVE-2012-6537", "CVE-2012-6538", "CVE-2012-6539", "CVE-2012-6540", "CVE-2012-6541", "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2013-0309", "CVE-2013-1826", "CVE-2013-1928");
  script_tag(name:"creation_date", value:"2012-12-04 04:18:45 +0000 (Tue, 04 Dec 2012)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1648-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.10");

  script_xref(name:"Advisory-ID", value:"USN-1648-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1648-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1648-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brad Spengler discovered a flaw in the Linux kernel's uname system call. An
unprivileged user could exploit this flaw to read kernel stack memory.
(CVE-2012-0957)

Rodrigo Freire discovered a flaw in the Linux kernel's TCP illinois
congestion control algorithm. A local attacker could use this to cause a
denial of service. (CVE-2012-4565)

Mathias Krause discovered a flaw in the Linux kernel's XFRM netlink
interface. A local user with the NET_ADMIN capability could exploit this
flaw to leak the contents of kernel memory. (CVE-2012-6536)

Mathias Krause discovered several errors in the Linux kernel's xfrm_user
implementation. A local attacker could exploit these flaws to examine parts
of kernel memory. (CVE-2012-6537)

Mathias Krause discovered an information leak in the Linux kernel's
xfrm_user copy_to_user_auth function. A local user could exploit this flaw
to examine parts of kernel heap memory. (CVE-2012-6538)

Mathias Krause discovered information leak in the Linux kernel's compat
ioctl interface. A local user could exploit the flaw to examine parts of
kernel stack memory (CVE-2012-6539)

Mathias Krause discovered an information leak in the Linux kernel's
getsockopt for IP_VS_SO_GET_TIMEOUT. A local user could exploit this flaw
to examine parts of kernel stack memory. (CVE-2012-6540)

Mathias Krause discovered an information leak in the Linux kernel's
getsockopt implementation for the Datagram Congestion Control Protocol
(DCCP). A local user could exploit this flaw to examine some of the
kernel's stack memory. (CVE-2012-6541)

Mathias Krause discovered an information leak in the Linux kernel's
getsockname implementation for Logical Link Layer (llc) sockets. A local
user could exploit this flaw to examine some of the kernel's stack memory.
(CVE-2012-6542)

Mathias Krause discovered information leaks in the Linux kernel's Bluetooth
Logical Link Control and Adaptation Protocol (L2CAP) implementation. A
local user could exploit these flaws to examine some of the kernel's stack
memory. (CVE-2012-6544)

Mathias Krause discovered information leaks in the Linux kernel's Bluetooth
RFCOMM protocol implementation. A local user could exploit these flaws to
examine parts of kernel memory. (CVE-2012-6545)

Mathias Krause discovered information leaks in the Linux kernel's
Asynchronous Transfer Mode (ATM) networking stack. A local user could
exploit these flaws to examine some parts of kernel memory. (CVE-2012-6546)

A flaw was discovered in the Linux kernels handling of memory ranges with
PROT_NONE when transparent hugepages are in use. An unprivileged local user
could exploit this flaw to cause a denial of service (crash the system).
(CVE-2013-0309)

Mathias Krause discovered a flaw in xfrm_user in the Linux kernel. A local
attacker with NET_ADMIN capability could potentially exploit this flaw to
escalate privileges. (CVE-2013-1826)

An information leak was discovered in the Linux ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-28-generic-pae", ver:"3.0.0-28.45", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-28-generic", ver:"3.0.0-28.45", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-28-omap", ver:"3.0.0-28.45", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-28-powerpc-smp", ver:"3.0.0-28.45", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-28-powerpc", ver:"3.0.0-28.45", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-28-powerpc64-smp", ver:"3.0.0-28.45", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-28-server", ver:"3.0.0-28.45", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-28-virtual", ver:"3.0.0-28.45", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
