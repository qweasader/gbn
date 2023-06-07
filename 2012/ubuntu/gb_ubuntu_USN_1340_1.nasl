# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.840875");
  script_cve_id("CVE-2011-2203", "CVE-2011-4077", "CVE-2011-4110", "CVE-2011-4132", "CVE-2011-4330", "CVE-2012-0044");
  script_tag(name:"creation_date", value:"2012-01-25 05:46:19 +0000 (Wed, 25 Jan 2012)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-29 15:27:00 +0000 (Wed, 29 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1340-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1340-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1340-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-backport-oneiric' package(s) announced via the USN-1340-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Clement Lecigne discovered a bug in the HFS filesystem. A local attacker
could exploit this to cause a kernel oops. (CVE-2011-2203)

A bug was discovered in the XFS filesystem's handling of pathnames. A local
attacker could exploit this to crash the system, leading to a denial of
service, or gain root privileges. (CVE-2011-4077)

A flaw was found in how the Linux kernel handles user-defined key types. An
unprivileged local user could exploit this to crash the system.
(CVE-2011-4110)

A flaw was found in the Journaling Block Device (JBD). A local attacker
able to mount ext3 or ext4 file systems could exploit this to crash the
system, leading to a denial of service. (CVE-2011-4132)

Clement Lecigne discovered a bug in the HFS file system bounds checking.
When a malformed HFS file system is mounted a local user could crash the
system or gain root privileges. (CVE-2011-4330)

Chen Haogang discovered an integer overflow that could result in memory
corruption. A local unprivileged user could use this to crash the system.
(CVE-2012-0044)");

  script_tag(name:"affected", value:"'linux-lts-backport-oneiric' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-15-generic-pae", ver:"3.0.0-15.25~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-15-generic", ver:"3.0.0-15.25~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-15-server", ver:"3.0.0-15.25~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-15-virtual", ver:"3.0.0-15.25~lucid1", rls:"UBUNTU10.04 LTS"))) {
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
