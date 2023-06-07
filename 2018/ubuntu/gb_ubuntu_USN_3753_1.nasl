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
  script_oid("1.3.6.1.4.1.25623.1.0.843627");
  script_cve_id("CVE-2017-13168", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-12233", "CVE-2018-13094", "CVE-2018-13405", "CVE-2018-13406");
  script_tag(name:"creation_date", value:"2018-08-25 04:47:37 +0000 (Sat, 25 Aug 2018)");
  script_version("2023-02-28T10:20:42+0000");
  script_tag(name:"last_modification", value:"2023-02-28 10:20:42 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:37:00 +0000 (Fri, 24 Feb 2023)");

  script_name("Ubuntu: Security Advisory (USN-3753-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3753-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3753-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-raspi2, linux-snapdragon' package(s) announced via the USN-3753-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the generic SCSI driver in the Linux kernel did not
properly enforce permissions on kernel memory access. A local attacker
could use this to expose sensitive information or possibly elevate
privileges. (CVE-2017-13168)

Wen Xu discovered that a use-after-free vulnerability existed in the ext4
filesystem implementation in the Linux kernel. An attacker could use this
to construct a malicious ext4 image that, when mounted, could cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2018-10876, CVE-2018-10879)

Wen Xu discovered that a buffer overflow existed in the ext4 filesystem
implementation in the Linux kernel. An attacker could use this to construct
a malicious ext4 image that, when mounted, could cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2018-10877)

Wen Xu discovered that an out-of-bounds write vulnerability existed in the
ext4 filesystem implementation in the Linux kernel. An attacker could use
this to construct a malicious ext4 image that, when mounted, could cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2018-10878, CVE-2018-10882)

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly keep meta-data information consistent in some
situations. An attacker could use this to construct a malicious ext4 image
that, when mounted, could cause a denial of service (system crash).
(CVE-2018-10881)

Shankara Pailoor discovered that the JFS filesystem implementation in the
Linux kernel contained a buffer overflow when handling extended attributes.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2018-12233)

Wen Xu discovered that the XFS filesystem implementation in the Linux
kernel did not properly handle an error condition with a corrupted xfs
image. An attacker could use this to construct a malicious xfs image that,
when mounted, could cause a denial of service (system crash).
(CVE-2018-13094)

It was discovered that the Linux kernel did not properly handle setgid file
creation when performed by a non-member of the group. A local attacker
could use this to gain elevated privileges. (CVE-2018-13405)

Silvio Cesare discovered that the generic VESA frame buffer driver in the
Linux kernel contained an integer overflow. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-13406)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-raspi2, linux-snapdragon' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1032-kvm", ver:"4.4.0-1032.38", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1066-aws", ver:"4.4.0-1066.76", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1095-raspi2", ver:"4.4.0-1095.103", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1099-snapdragon", ver:"4.4.0-1099.104", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-134-generic-lpae", ver:"4.4.0-134.160", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-134-generic", ver:"4.4.0-134.160", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-134-lowlatency", ver:"4.4.0-134.160", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-134-powerpc-e500mc", ver:"4.4.0-134.160", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-134-powerpc-smp", ver:"4.4.0-134.160", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-134-powerpc64-emb", ver:"4.4.0-134.160", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-134-powerpc64-smp", ver:"4.4.0-134.160", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1066.68", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.4.0.134.140", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.134.140", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1032.31", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.134.140", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"4.4.0.134.140", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"4.4.0.134.140", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"4.4.0.134.140", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"4.4.0.134.140", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.4.0.1095.95", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"4.4.0.1099.91", rls:"UBUNTU16.04 LTS"))) {
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