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
  script_oid("1.3.6.1.4.1.25623.1.0.842104");
  script_cve_id("CVE-2013-7423", "CVE-2014-9402", "CVE-2015-1472", "CVE-2015-1473");
  script_tag(name:"creation_date", value:"2015-02-27 04:42:47 +0000 (Fri, 27 Feb 2015)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2519-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|14\.04\ LTS|14\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2519-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2519-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc, glibc' package(s) announced via the USN-2519-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Arnaud Le Blanc discovered that the GNU C Library incorrectly handled file
descriptors when resolving DNS queries under high load. This may cause a
denial of service in other applications, or an information leak. This issue
only affected Ubuntu 10.04 LTS, Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2013-7423)

It was discovered that the GNU C Library incorrectly handled receiving a
positive answer while processing the network name when performing DNS
resolution. A remote attacker could use this issue to cause the GNU C
Library to hang, resulting in a denial of service. (CVE-2014-9402)

Joseph Myers discovered that the GNU C Library wscanf function incorrectly
handled memory. A remote attacker could possibly use this issue to cause
the GNU C Library to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 12.04 LTS, Ubuntu
14.04 LTS and Ubuntu 14.10. (CVE-2015-1472, CVE-2015-1473)");

  script_tag(name:"affected", value:"'eglibc, glibc' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.11.1-0ubuntu7.21", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.15-0ubuntu10.11", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.19-0ubuntu6.6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.19-10ubuntu2.3", rls:"UBUNTU14.10"))) {
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