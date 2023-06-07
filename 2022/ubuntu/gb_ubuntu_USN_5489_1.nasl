# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.845420");
  script_cve_id("CVE-2021-3507", "CVE-2021-3929", "CVE-2021-4206", "CVE-2021-4207", "CVE-2022-0358", "CVE-2022-26353", "CVE-2022-26354");
  script_tag(name:"creation_date", value:"2022-06-22 01:00:42 +0000 (Wed, 22 Jun 2022)");
  script_version("2022-12-01T10:11:22+0000");
  script_tag(name:"last_modification", value:"2022-12-01 10:11:22 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-29 16:21:00 +0000 (Tue, 29 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-5489-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.10|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5489-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5489-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-5489-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander Bulekov discovered that QEMU incorrectly handled floppy disk
emulation. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service, or possibly leak
sensitive information. (CVE-2021-3507)

It was discovered that QEMU incorrectly handled NVME controller emulation.
An attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 22.04 LTS. (CVE-2021-3929)

It was discovered that QEMU incorrectly handled QXL display device
emulation. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2021-4206, CVE-2021-4207)

Jietao Xiao, Jinku Li, Wenbo Shen, and Nanzi Yang discovered that QEMU
incorrectly handled the virtiofsd shared file system daemon. An attacker
inside the guest could use this issue to create files with incorrect
ownership, possibly leading to privilege escalation. This issue only
affected Ubuntu 22.04 LTS. (CVE-2022-0358)

It was discovered that QEMU incorrectly handled virtio-net devices. A
privileged attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2022-26353)

It was discovered that QEMU incorrectly handled vhost-vsock devices. A
privileged attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2022-26354)");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.11+dfsg-1ubuntu7.40", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.11+dfsg-1ubuntu7.40", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.11+dfsg-1ubuntu7.40", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.11+dfsg-1ubuntu7.40", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:2.11+dfsg-1ubuntu7.40", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.11+dfsg-1ubuntu7.40", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.11+dfsg-1ubuntu7.40", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.11+dfsg-1ubuntu7.40", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:4.2-3ubuntu6.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:4.2-3ubuntu6.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:4.2-3ubuntu6.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:4.2-3ubuntu6.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:4.2-3ubuntu6.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:4.2-3ubuntu6.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-microvm", ver:"1:4.2-3ubuntu6.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:4.2-3ubuntu6.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:4.2-3ubuntu6.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:4.2-3ubuntu6.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:6.0+dfsg-2expubuntu1.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:6.0+dfsg-2expubuntu1.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:6.0+dfsg-2expubuntu1.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:6.0+dfsg-2expubuntu1.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:6.0+dfsg-2expubuntu1.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:6.0+dfsg-2expubuntu1.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-microvm", ver:"1:6.0+dfsg-2expubuntu1.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:6.0+dfsg-2expubuntu1.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:6.0+dfsg-2expubuntu1.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:6.0+dfsg-2expubuntu1.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:6.2+dfsg-2ubuntu6.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:6.2+dfsg-2ubuntu6.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:6.2+dfsg-2ubuntu6.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:6.2+dfsg-2ubuntu6.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:6.2+dfsg-2ubuntu6.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:6.2+dfsg-2ubuntu6.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-microvm", ver:"1:6.2+dfsg-2ubuntu6.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:6.2+dfsg-2ubuntu6.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:6.2+dfsg-2ubuntu6.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:6.2+dfsg-2ubuntu6.2", rls:"UBUNTU22.04 LTS"))) {
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
