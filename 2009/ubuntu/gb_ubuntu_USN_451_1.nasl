# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.840066");
  script_cve_id("CVE-2007-0006", "CVE-2007-0772", "CVE-2007-0958");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2022-09-16T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:39 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-451-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10)");

  script_xref(name:"Advisory-ID", value:"USN-451-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-451-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.15, linux-source-2.6.17' package(s) announced via the USN-451-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel key management code did not correctly handle key reuse. A
local attacker could create many key requests, leading to a denial of
service. (CVE-2007-0006)

The kernel NFS code did not correctly validate NFSACL2 ACCESS requests.
If a system was serving NFS mounts, a remote attacker could send a
specially crafted packet, leading to a denial of service.
(CVE-2007-0772)

When dumping core, the kernel did not correctly handle PT_INTERP
processes. A local attacker could create situations where they could
read the contents of otherwise unreadable executable programs.
(CVE-2007-0958)");

  script_tag(name:"affected", value:"'linux-source-2.6.15, linux-source-2.6.17' package(s) on Ubuntu 6.06, Ubuntu 6.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-386", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-686", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-generic", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-k8", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-server", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-xeon", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-k7", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-powerpc-smp", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-powerpc", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-powerpc64-smp", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-server-bigiron", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-server", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-sparc64-smp", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-sparc64", ver:"2.6.15-28.53", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-386", ver:"2.6.17.1-11.37", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-generic", ver:"2.6.17.1-11.37", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-powerpc-smp", ver:"2.6.17.1-11.37", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-powerpc", ver:"2.6.17.1-11.37", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-powerpc64-smp", ver:"2.6.17.1-11.37", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-server-bigiron", ver:"2.6.17.1-11.37", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-server", ver:"2.6.17.1-11.37", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-sparc64-smp", ver:"2.6.17.1-11.37", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-sparc64", ver:"2.6.17.1-11.37", rls:"UBUNTU6.10"))) {
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
