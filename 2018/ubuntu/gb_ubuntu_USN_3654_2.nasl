# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.843530");
  script_cve_id("CVE-2017-17975", "CVE-2017-18193", "CVE-2017-18222", "CVE-2018-1065", "CVE-2018-1068", "CVE-2018-1130", "CVE-2018-3639", "CVE-2018-5803", "CVE-2018-7480", "CVE-2018-7757", "CVE-2018-7995", "CVE-2018-8781", "CVE-2018-8822");
  script_tag(name:"creation_date", value:"2018-05-22 10:40:57 +0000 (Tue, 22 May 2018)");
  script_version("2023-03-06T10:19:58+0000");
  script_tag(name:"last_modification", value:"2023-03-06 10:19:58 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 15:10:00 +0000 (Fri, 03 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-3654-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3654-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3654-2");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/Variant4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-lts-xenial' package(s) announced via the USN-3654-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3654-1 fixed vulnerabilities and added mitigations in the Linux
kernel for Ubuntu 16.04 LTS. This update provides the corresponding
updates for the Linux Hardware Enablement (HWE) kernel from Ubuntu
16.04 LTS for Ubuntu 14.04 LTS.

Jann Horn and Ken Johnson discovered that microprocessors utilizing
speculative execution of a memory read may allow unauthorized memory
reads via a sidechannel attack. This flaw is known as Spectre
Variant 4. A local attacker could use this to expose sensitive
information, including kernel memory. (CVE-2018-3639)

Tuba Yavuz discovered that a double-free error existed in the USBTV007
driver of the Linux kernel. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2017-17975)

It was discovered that a race condition existed in the F2FS implementation
in the Linux kernel. A local attacker could use this to cause a denial of
service (system crash). (CVE-2017-18193)

It was discovered that a buffer overflow existed in the Hisilicon HNS
Ethernet Device driver in the Linux kernel. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-18222)

It was discovered that the netfilter subsystem in the Linux kernel did not
validate that rules containing jumps contained user-defined chains. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-1065)

It was discovered that the netfilter subsystem of the Linux kernel did not
properly validate ebtables offsets. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-1068)

It was discovered that a null pointer dereference vulnerability existed in
the DCCP protocol implementation in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash). (CVE-2018-1130)

It was discovered that the SCTP Protocol implementation in the Linux kernel
did not properly validate userspace provided payload lengths in some
situations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2018-5803)

It was discovered that a double free error existed in the block layer
subsystem of the Linux kernel when setting up a request queue. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-7480)

It was discovered that a memory leak existed in the SAS driver subsystem of
the Linux kernel. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2018-7757)

It was discovered that a race condition existed in the x86 machine check
handler in the Linux kernel. A local privileged attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-7995)

Eyal Itkin discovered ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-aws, linux-lts-xenial' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1022-aws", ver:"4.4.0-1022.22", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-127-generic-lpae", ver:"4.4.0-127.153~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-127-generic", ver:"4.4.0-127.153~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-127-lowlatency", ver:"4.4.0-127.153~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-127-powerpc-e500mc", ver:"4.4.0-127.153~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-127-powerpc-smp", ver:"4.4.0-127.153~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-127-powerpc64-emb", ver:"4.4.0-127.153~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-127-powerpc64-smp", ver:"4.4.0-127.153~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1022.22", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-xenial", ver:"4.4.0.127.107", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.127.107", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.127.107", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc-lts-xenial", ver:"4.4.0.127.107", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp-lts-xenial", ver:"4.4.0.127.107", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb-lts-xenial", ver:"4.4.0.127.107", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp-lts-xenial", ver:"4.4.0.127.107", rls:"UBUNTU14.04 LTS"))) {
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
