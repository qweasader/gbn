# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.842018");
  script_cve_id("CVE-2014-3182", "CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-7145");
  script_tag(name:"creation_date", value:"2014-10-31 04:45:38 +0000 (Fri, 31 Oct 2014)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 18:09:00 +0000 (Thu, 13 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-2394-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2394-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2394-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-2394-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nadav Amit reported that the KVM (Kernel Virtual Machine) mishandles
noncanonical addresses when emulating instructions that change the rip
(Instruction Pointer). A guest user with access to I/O or the MMIO can use
this flaw to cause a denial of service (system crash) of the guest.
(CVE-2014-3647)

A flaw was discovered with the handling of the invept instruction in the
KVM (Kernel Virtual Machine) subsystem of the Linux kernel. An unprivileged
guest user could exploit this flaw to cause a denial of service (system
crash) on the guest. (CVE-2014-3646)

Lars Bull reported a race condition in the PIT (programmable interrupt
timer) emulation in the KVM (Kernel Virtual Machine) subsystem of the Linux
kernel. A local guest user with access to PIT i/o ports could exploit this
flaw to cause a denial of service (crash) on the host. (CVE-2014-3611)

Lars Bull and Nadav Amit reported a flaw in how KVM (the Kernel Virtual
Machine) handles noncanonical writes to certain MSR registers. A privileged
guest user can exploit this flaw to cause a denial of service (kernel
panic) on the host. (CVE-2014-3610)

A bounds check error was discovered in the driver for the Logitech Unifying
receivers and devices. A physically proximate attacker could exploit this
flaw to cause a denial of service (invalid kfree) or to execute
arbitrary code. (CVE-2014-3182)

Raphael Geissert reported a NULL pointer dereference in the Linux kernel's
CIFS client. A remote CIFS server could cause a denial of service (system
crash) or possibly have other unspecified impact by deleting IPC$ share
during resolution of DFS referrals. (CVE-2014-7145)");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-39-generic-lpae", ver:"3.13.0-39.66~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-39-generic", ver:"3.13.0-39.66~precise1", rls:"UBUNTU12.04 LTS"))) {
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