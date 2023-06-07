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
  script_oid("1.3.6.1.4.1.25623.1.0.841847");
  script_cve_id("CVE-2013-4387", "CVE-2013-4470", "CVE-2013-4483", "CVE-2014-1438", "CVE-2014-3122", "CVE-2014-3153");
  script_tag(name:"creation_date", value:"2014-06-09 09:16:06 +0000 (Mon, 09 Jun 2014)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2234-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2234-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2234-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-2234-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pinkie Pie discovered a flaw in the Linux kernel's futex subsystem. An
unprivileged local user could exploit this flaw to cause a denial of
service (system crash) or gain administrative privileges. (CVE-2014-3153)

Dmitry Vyukov reported a flaw in the Linux kernel's handling of IPv6 UDP
Fragmentation Offload (UFO) processing. A remote attacker could leverage
this flaw to cause a denial of service (system crash). (CVE-2013-4387)

Hannes Frederic Sowa discovered a flaw in the Linux kernel's UDP
Fragmentation Offload (UFO). An unprivileged local user could exploit this
flaw to cause a denial of service (system crash) or possibly gain
administrative privileges. (CVE-2013-4470)

A flaw was discovered in the Linux kernel's IPC reference counting. An
unprivileged local user could exploit this flaw to cause a denial of
service (OOM system crash). (CVE-2013-4483)

halfdog reported an error in the AMD K7 and K8 platform support in the
Linux kernel. An unprivileged local user could exploit this flaw on AMD
based systems to cause a denial of service (task kill) or possibly gain
privileges via a crafted application. (CVE-2014-1438)

Sasha Levin reported a bug in the Linux kernel's virtual memory management
subsystem. An unprivileged local user could exploit this flaw to cause a
denial of service (system crash). (CVE-2014-3122)");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-365-ec2", ver:"2.6.32-365.79", rls:"UBUNTU10.04 LTS"))) {
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
