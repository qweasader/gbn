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
  script_oid("1.3.6.1.4.1.25623.1.0.845083");
  script_cve_id("CVE-2021-22543", "CVE-2021-3679", "CVE-2021-3732", "CVE-2021-38204", "CVE-2021-38205");
  script_tag(name:"creation_date", value:"2021-10-01 01:00:51 +0000 (Fri, 01 Oct 2021)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-17 16:37:00 +0000 (Tue, 17 Aug 2021)");

  script_name("Ubuntu: Security Advisory (USN-5094-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5094-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5094-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi2' package(s) announced via the USN-5094-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the KVM hypervisor implementation in the Linux
kernel did not properly perform reference counting in some situations,
leading to a use-after-free vulnerability. An attacker who could start and
control a VM could possibly use this to expose sensitive information or
execute arbitrary code. (CVE-2021-22543)

It was discovered that the tracing subsystem in the Linux kernel did not
properly keep track of per-cpu ring buffer state. A privileged attacker
could use this to cause a denial of service. (CVE-2021-3679)

Alois Wohlschlager discovered that the overlay file system in the Linux
kernel did not restrict private clones in some situations. An attacker
could use this to expose sensitive information. (CVE-2021-3732)

It was discovered that the MAX-3421 host USB device driver in the Linux
kernel did not properly handle device removal events. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2021-38204)

It was discovered that the Xilinx 10/100 Ethernet Lite device driver in the
Linux kernel could report pointer addresses in some situations. An attacker
could use this information to ease the exploitation of another
vulnerability. (CVE-2021-38205)");

  script_tag(name:"affected", value:"'linux-raspi2' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1096-raspi2", ver:"4.15.0-1096.102", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.15.0.1096.94", rls:"UBUNTU18.04 LTS"))) {
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
