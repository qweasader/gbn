# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5991.1");
  script_cve_id("CVE-2021-3669", "CVE-2022-3424", "CVE-2022-36280", "CVE-2022-41218", "CVE-2022-47929", "CVE-2023-0045", "CVE-2023-0266", "CVE-2023-0394", "CVE-2023-23455", "CVE-2023-23559", "CVE-2023-28328");
  script_tag(name:"creation_date", value:"2023-04-03 04:11:13 +0000 (Mon, 03 Apr 2023)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-23 19:29:00 +0000 (Mon, 23 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-5991-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5991-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5991-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp-4.15' package(s) announced via the USN-5991-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the System V IPC implementation in the Linux kernel
did not properly handle large shared memory counts. A local attacker could
use this to cause a denial of service (memory exhaustion). (CVE-2021-3669)

It was discovered that a use-after-free vulnerability existed in the SGI
GRU driver in the Linux kernel. A local attacker could possibly use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3424)

Ziming Zhang discovered that the VMware Virtual GPU DRM driver in the Linux
kernel contained an out-of-bounds write vulnerability. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2022-36280)

Hyunwoo Kim discovered that the DVB Core driver in the Linux kernel did not
properly perform reference counting in some situations, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2022-41218)

It was discovered that the network queuing discipline implementation in the
Linux kernel contained a null pointer dereference in some situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2022-47929)

Jose Oliveira and Rodrigo Branco discovered that the prctl syscall
implementation in the Linux kernel did not properly protect against
indirect branch prediction attacks in some situations. A local attacker
could possibly use this to expose sensitive information. (CVE-2023-0045)

It was discovered that a use-after-free vulnerability existed in the
Advanced Linux Sound Architecture (ALSA) subsystem. A local attacker could
use this to cause a denial of service (system crash). (CVE-2023-0266)

Kyle Zeng discovered that the IPv6 implementation in the Linux kernel
contained a NULL pointer dereference vulnerability in certain situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-0394)

Kyle Zeng discovered that the ATM VC queuing discipline implementation in
the Linux kernel contained a type confusion vulnerability in some
situations. An attacker could use this to cause a denial of service (system
crash). (CVE-2023-23455)

It was discovered that the RNDIS USB driver in the Linux kernel contained
an integer overflow vulnerability. A local attacker with physical access
could plug in a malicious USB device to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2023-23559)

Wei Chen discovered that the DVB USB AZ6027 driver in the Linux kernel
contained a null pointer dereference when handling certain messages from
user space. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-28328)");

  script_tag(name:"affected", value:"'linux-gcp-4.15' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1147-gcp", ver:"4.15.0-1147.163", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-18.04", ver:"4.15.0.1147.161", rls:"UBUNTU18.04 LTS"))) {
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
