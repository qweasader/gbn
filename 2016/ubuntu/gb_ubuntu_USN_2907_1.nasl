# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.842651");
  script_cve_id("CVE-2015-7550", "CVE-2015-8543", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8785", "CVE-2016-1575", "CVE-2016-1576");
  script_tag(name:"creation_date", value:"2016-02-23 05:25:44 +0000 (Tue, 23 Feb 2016)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 17:59:00 +0000 (Mon, 18 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-2907-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2907-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2907-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2907-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"halfdog discovered that OverlayFS, when mounting on top of a FUSE mount,
incorrectly propagated file attributes, including setuid. A local
unprivileged attacker could use this to gain privileges. (CVE-2016-1576)

halfdog discovered that OverlayFS in the Linux kernel incorrectly
propagated security sensitive extended attributes, such as
POSIX ACLs. A local unprivileged attacker could use this to gain
privileges. (CVE-2016-1575)

It was discovered that the Linux kernel keyring subsystem contained a race
between read and revoke operations. A local attacker could use this to
cause a denial of service (system crash). (CVE-2015-7550)

Guo Yong Gang discovered that the Linux kernel networking implementation did
not validate protocol identifiers for certain protocol families, A local
attacker could use this to cause a denial of service (system crash) or
possibly gain administrative privileges. (CVE-2015-8543)

Dmitry Vyukov discovered that the pptp implementation in the Linux kernel
did not verify an address length when setting up a socket. A local attacker
could use this to craft an application that exposed sensitive information
from kernel memory. (CVE-2015-8569)

David Miller discovered that the Bluetooth implementation in the Linux
kernel did not properly validate the socket address length for Synchronous
Connection-Oriented (SCO) sockets. A local attacker could use this to
expose sensitive information. (CVE-2015-8575)

It was discovered that the Linux kernel's Filesystem in Userspace (FUSE)
implementation did not handle initial zero length segments properly. A
local attacker could use this to cause a denial of service (unkillable
task). (CVE-2015-8785)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-79-generic-lpae", ver:"3.13.0-79.123", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-79-generic", ver:"3.13.0-79.123", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-79-lowlatency", ver:"3.13.0-79.123", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-79-powerpc-e500", ver:"3.13.0-79.123", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-79-powerpc-e500mc", ver:"3.13.0-79.123", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-79-powerpc-smp", ver:"3.13.0-79.123", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-79-powerpc64-emb", ver:"3.13.0-79.123", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-79-powerpc64-smp", ver:"3.13.0-79.123", rls:"UBUNTU14.04 LTS"))) {
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