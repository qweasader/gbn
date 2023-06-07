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
  script_oid("1.3.6.1.4.1.25623.1.0.843719");
  script_cve_id("CVE-2017-14177", "CVE-2017-14180");
  script_tag(name:"creation_date", value:"2018-10-26 04:11:02 +0000 (Fri, 26 Oct 2018)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-15 13:21:00 +0000 (Thu, 15 Feb 2018)");

  script_name("Ubuntu: Security Advisory (USN-3480-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|17\.04|17\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3480-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3480-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1733366");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apport' package(s) announced via the USN-3480-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3480-2 fixed regressions in Apport. The update introduced a new regression in the container support. This update addresses the problem.

We apologize for the inconvenience.

Original advisory details:

 Sander Bos discovered that Apport incorrectly handled core dumps for setuid
 binaries. A local attacker could use this issue to perform a denial of service
 via resource exhaustion or possibly gain root privileges. (CVE-2017-14177)

 Sander Bos discovered that Apport incorrectly handled core dumps for processes
 in a different PID namespace. A local attacker could use this issue to perform
 a denial of service via resource exhaustion or possibly gain root privileges.
 (CVE-2017-14180)");

  script_tag(name:"affected", value:"'apport' package(s) on Ubuntu 16.04, Ubuntu 17.04, Ubuntu 17.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apport", ver:"2.20.1-0ubuntu2.15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"apport", ver:"2.20.4-0ubuntu4.10", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"apport", ver:"2.20.7-0ubuntu3.7", rls:"UBUNTU17.10"))) {
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
