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
  script_oid("1.3.6.1.4.1.25623.1.0.845456");
  script_cve_id("CVE-2022-1195", "CVE-2022-1199", "CVE-2022-1204", "CVE-2022-1205", "CVE-2022-1789", "CVE-2022-28388", "CVE-2022-33981");
  script_tag(name:"creation_date", value:"2022-07-29 01:00:37 +0000 (Fri, 29 Jul 2022)");
  script_version("2023-01-05T10:12:14+0000");
  script_tag(name:"last_modification", value:"2023-01-05 10:12:14 +0000 (Thu, 05 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-06 18:25:00 +0000 (Tue, 06 Sep 2022)");

  script_name("Ubuntu: Security Advisory (USN-5539-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5539-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5539-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-bluefield, linux-gcp-5.4, linux-gke-5.4' package(s) announced via the USN-5539-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the implementation of the 6pack and mkiss protocols
in the Linux kernel did not handle detach events properly in some
situations, leading to a use-after-free vulnerability. A local attacker
could possibly use this to cause a denial of service (system crash).
(CVE-2022-1195)

Duoming Zhou discovered that the AX.25 amateur radio protocol
implementation in the Linux kernel did not handle detach events properly in
some situations. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2022-1199)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel during device detach operations. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-1204)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel, leading to use-after-free
vulnerabilities. A local attacker could possibly use this to cause a denial
of service (system crash). (CVE-2022-1205)

Yongkang Jia discovered that the KVM hypervisor implementation in the Linux
kernel did not properly handle guest TLB mapping invalidation requests in
some situations. An attacker in a guest VM could use this to cause a denial
of service (system crash) in the host OS. (CVE-2022-1789)

It was discovered that the 8 Devices USB2CAN interface implementation in
the Linux kernel did not properly handle certain error conditions, leading
to a double-free. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2022-28388)

Minh Yuan discovered that the floppy driver in the Linux kernel contained a
race condition in some situations, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-33981)");

  script_tag(name:"affected", value:"'linux-bluefield, linux-gcp-5.4, linux-gke-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1078-gke", ver:"5.4.0-1078.84~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1084-gcp", ver:"5.4.0-1084.92~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.4.0.1084.63", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.4", ver:"5.4.0.1078.84~18.04.40", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1042-bluefield", ver:"5.4.0-1042.47", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-bluefield", ver:"5.4.0.1042.41", rls:"UBUNTU20.04 LTS"))) {
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
