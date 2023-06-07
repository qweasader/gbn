# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.843314");
  script_cve_id("CVE-2017-7493", "CVE-2017-8112", "CVE-2017-8380", "CVE-2017-9060", "CVE-2017-9310", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9374", "CVE-2017-9375", "CVE-2017-9503", "CVE-2017-9524");
  script_tag(name:"creation_date", value:"2017-09-21 05:18:56 +0000 (Thu, 21 Sep 2017)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-06 02:06:00 +0000 (Wed, 06 Sep 2017)");

  script_name("Ubuntu: Security Advisory (USN-3414-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3414-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3414-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1718222");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-3414-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3414-1 fixed vulnerabilities in QEMU. The patch backport for
CVE-2017-9375 was incomplete and caused a regression in the USB xHCI
controller emulation support. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Leo Gaspard discovered that QEMU incorrectly handled VirtFS access control.
 A guest attacker could use this issue to elevate privileges inside the
 guest. (CVE-2017-7493)

 Li Qiang discovered that QEMU incorrectly handled VMWare PVSCSI emulation.
 A privileged attacker inside the guest could use this issue to cause QEMU
 to consume resources or crash, resulting in a denial of service.
 (CVE-2017-8112)

 It was discovered that QEMU incorrectly handled MegaRAID SAS 8708EM2 Host
 Bus Adapter emulation support. A privileged attacker inside the guest could
 use this issue to cause QEMU to crash, resulting in a denial of service, or
 possibly to obtain sensitive host memory. This issue only affected Ubuntu
 16.04 LTS and Ubuntu 17.04. (CVE-2017-8380)

 Li Qiang discovered that QEMU incorrectly handled the Virtio GPU device. An
 attacker inside the guest could use this issue to cause QEMU to consume
 resources and crash, resulting in a denial of service. This issue only
 affected Ubuntu 17.04. (CVE-2017-9060)

 Li Qiang discovered that QEMU incorrectly handled the e1000e device. A
 privileged attacker inside the guest could use this issue to cause QEMU to
 hang, resulting in a denial of service. This issue only affected Ubuntu
 17.04. (CVE-2017-9310)

 Li Qiang discovered that QEMU incorrectly handled USB OHCI emulation
 support. An attacker inside the guest could use this issue to cause QEMU to
 crash, resulting in a denial of service. (CVE-2017-9330)

 Li Qiang discovered that QEMU incorrectly handled IDE AHCI emulation
 support. A privileged attacker inside the guest could use this issue to
 cause QEMU to consume resources and crash, resulting in a denial of
 service. (CVE-2017-9373)

 Li Qiang discovered that QEMU incorrectly handled USB EHCI emulation
 support. A privileged attacker inside the guest could use this issue to
 cause QEMU to consume resources and crash, resulting in a denial of
 service. (CVE-2017-9374)

 Li Qiang discovered that QEMU incorrectly handled USB xHCI emulation
 support. A privileged attacker inside the guest could use this issue to
 cause QEMU to hang, resulting in a denial of service. (CVE-2017-9375)

 Zhangyanyu discovered that QEMU incorrectly handled MegaRAID SAS 8708EM2
 Host Bus Adapter emulation support. A privileged attacker inside the guest
 could use this issue to cause QEMU to crash, resulting in a denial of
 service. (CVE-2017-9503)

 It was discovered that the QEMU qemu-nbd server incorrectly handled
 initialization. A remote attacker could use this issue to cause the server
 to crash, resulting in a denial of service. (CVE-2017-9524)

 It was discovered that the QEMU ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"2.0.0+dfsg-2ubuntu1.36", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"2.0.0+dfsg-2ubuntu1.36", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"2.0.0+dfsg-2ubuntu1.36", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"2.0.0+dfsg-2ubuntu1.36", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"2.0.0+dfsg-2ubuntu1.36", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"2.0.0+dfsg-2ubuntu1.36", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"2.0.0+dfsg-2ubuntu1.36", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"2.0.0+dfsg-2ubuntu1.36", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"1:2.5+dfsg-5ubuntu10.16", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.5+dfsg-5ubuntu10.16", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.5+dfsg-5ubuntu10.16", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.5+dfsg-5ubuntu10.16", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.5+dfsg-5ubuntu10.16", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:2.5+dfsg-5ubuntu10.16", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.5+dfsg-5ubuntu10.16", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.5+dfsg-5ubuntu10.16", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.5+dfsg-5ubuntu10.16", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"1:2.8+dfsg-3ubuntu2.5", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.8+dfsg-3ubuntu2.5", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.8+dfsg-3ubuntu2.5", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.8+dfsg-3ubuntu2.5", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.8+dfsg-3ubuntu2.5", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:2.8+dfsg-3ubuntu2.5", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.8+dfsg-3ubuntu2.5", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.8+dfsg-3ubuntu2.5", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.8+dfsg-3ubuntu2.5", rls:"UBUNTU17.04"))) {
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
