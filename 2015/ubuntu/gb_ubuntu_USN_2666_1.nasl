# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.842271");
  script_cve_id("CVE-2015-1420", "CVE-2015-4001", "CVE-2015-4002", "CVE-2015-4003", "CVE-2015-4167", "CVE-2015-4700");
  script_tag(name:"creation_date", value:"2015-07-08 04:33:04 +0000 (Wed, 08 Jul 2015)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_name("Ubuntu: Security Advisory (USN-2666-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.10");

  script_xref(name:"Advisory-ID", value:"USN-2666-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2666-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2666-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition was discovered in the Linux kernel's file_handle size
verification. A local user could exploit this flaw to read potentially
sensitive memory locations. (CVE-2015-1420)

A underflow error was discovered in the Linux kernel's Ozmo Devices USB
over WiFi host controller driver. A remote attacker could exploit this flaw
to cause a denial of service (system crash) or potentially execute
arbitrary code via a specially crafted packet. (CVE-2015-4001)

A bounds check error was discovered in the Linux kernel's Ozmo Devices USB
over WiFi host controller driver. A remote attacker could exploit this flaw
to cause a denial of service (system crash) or potentially execute
arbitrary code via a specially crafted packet. (CVE-2015-4002)

A division by zero error was discovered in the Linux kernel's Ozmo Devices
USB over WiFi host controller driver. A remote attacker could exploit this
flaw to cause a denial of service (system crash). (CVE-2015-4003)

Carl H Lunde discovered missing consistency checks in the Linux kernel's UDF
file system (CONFIG_UDF_FS). A local attacker could exploit this flaw to
cause a denial of service (system crash) by using a corrupted file system
image. (CVE-2015-4167)

Daniel Borkmann reported a kernel crash in the Linux kernel's BPF filter
JIT optimization. A local attacker could exploit this flaw to cause a
denial of service (system crash). (CVE-2015-4700)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 14.10.");

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

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-43-generic-lpae", ver:"3.16.0-43.58", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-43-generic", ver:"3.16.0-43.58", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-43-lowlatency", ver:"3.16.0-43.58", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-43-powerpc-e500mc", ver:"3.16.0-43.58", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-43-powerpc-smp", ver:"3.16.0-43.58", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-43-powerpc64-emb", ver:"3.16.0-43.58", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-43-powerpc64-smp", ver:"3.16.0-43.58", rls:"UBUNTU14.10"))) {
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
