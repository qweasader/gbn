# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844850");
  script_cve_id("CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-27673", "CVE-2020-27675", "CVE-2020-27777", "CVE-2020-27815", "CVE-2020-27830", "CVE-2020-27835", "CVE-2020-28588", "CVE-2020-28941", "CVE-2020-28974", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-35508");
  script_tag(name:"creation_date", value:"2021-02-26 04:01:00 +0000 (Fri, 26 Feb 2021)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4751-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|20\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4751-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4751-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.8, linux-kvm, linux-oracle, linux-raspi' package(s) announced via the USN-4751-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the console keyboard driver in the Linux kernel
contained a race condition. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2020-25656)

Minh Yuan discovered that the tty driver in the Linux kernel contained race
conditions when handling fonts. A local attacker could possibly use this to
expose sensitive information (kernel memory). (CVE-2020-25668)

Bodong Zhao discovered a use-after-free in the Sun keyboard driver
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service or possibly execute arbitrary code.
(CVE-2020-25669)

Kiyin (Yin Liang ) discovered that the perf subsystem in the Linux kernel did
not properly deallocate memory in some situations. A privileged attacker
could use this to cause a denial of service (kernel memory exhaustion).
(CVE-2020-25704)

Julien Grall discovered that the Xen dom0 event handler in the Linux kernel
did not properly limit the number of events queued. An attacker in a guest
VM could use this to cause a denial of service in the host OS.
(CVE-2020-27673)

Jinoh Kang discovered that the Xen event channel infrastructure in the
Linux kernel contained a race condition. An attacker in guest could
possibly use this to cause a denial of service (dom0 crash).
(CVE-2020-27675)

Daniel Axtens discovered that PowerPC RTAS implementation in the Linux
kernel did not properly restrict memory accesses in some situations. A
privileged local attacker could use this to arbitrarily modify kernel
memory, potentially bypassing kernel lockdown restrictions.
(CVE-2020-27777)

It was discovered that the jfs file system implementation in the Linux
kernel contained an out-of-bounds read vulnerability. A local attacker
could use this to possibly cause a denial of service (system crash).
(CVE-2020-27815)

Shisong Qin and Bodong Zhao discovered that Speakup screen reader driver in
the Linux kernel did not correctly handle setting line discipline in some
situations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2020-27830, CVE-2020-28941)

It was discovered that a use-after-free vulnerability existed in the
infiniband hfi1 device driver in the Linux kernel. A local attacker could
possibly use this to cause a denial of service (system crash).
(CVE-2020-27835)

It was discovered that an information leak existed in the syscall
implementation in the Linux kernel on 32 bit systems. A local attacker
could use this to expose sensitive information (kernel memory).
(CVE-2020-28588)

Minh Yuan discovered that the framebuffer console driver in the Linux
kernel did not properly handle fonts in some conditions. A local attacker
could use this to cause a denial of service (system crash) or possibly
expose sensitive information (kernel memory). (CVE-2020-28974)

Michael Kurth and Pawel Wieczorkiewicz discovered that the Xen event
processing ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.8, linux-kvm, linux-oracle, linux-raspi' package(s) on Ubuntu 20.04, Ubuntu 20.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-44-generic-lpae", ver:"5.8.0-44.50~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-44-generic", ver:"5.8.0-44.50~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-44-lowlatency", ver:"5.8.0-44.50~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-20.04", ver:"5.8.0.44.50~20.04.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-20.04", ver:"5.8.0.44.50~20.04.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-20.04", ver:"5.8.0.44.50~20.04.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-20.04", ver:"5.8.0.44.50~20.04.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-20.04", ver:"5.8.0.44.50~20.04.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1016-raspi-nolpae", ver:"5.8.0-1016.19", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1016-raspi", ver:"5.8.0-1016.19", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1019-kvm", ver:"5.8.0-1019.21", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1021-oracle", ver:"5.8.0-1021.22", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1023-azure", ver:"5.8.0-1023.25", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1023-gcp", ver:"5.8.0-1023.24", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1024-aws", ver:"5.8.0-1024.26", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-44-generic-64k", ver:"5.8.0-44.50", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-44-generic-lpae", ver:"5.8.0-44.50", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-44-generic", ver:"5.8.0-44.50", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-44-lowlatency", ver:"5.8.0-44.50", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.8.0.1024.26", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.8.0.1023.23", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.8.0.1023.23", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"5.8.0.44.49", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.8.0.44.49", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.8.0.44.49", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.8.0.1023.23", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.8.0.1019.21", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.8.0.44.49", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.8.0.44.49", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.8.0.1021.20", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.8.0.1016.19", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.8.0.1016.19", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.8.0.44.49", rls:"UBUNTU20.10"))) {
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
