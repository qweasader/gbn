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
  script_oid("1.3.6.1.4.1.25623.1.0.842804");
  script_cve_id("CVE-2016-0749", "CVE-2016-2150");
  script_tag(name:"creation_date", value:"2016-06-22 03:29:06 +0000 (Wed, 22 Jun 2016)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-22 17:48:00 +0000 (Mon, 22 Apr 2019)");

  script_name("Ubuntu: Security Advisory (USN-3014-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|15\.10|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3014-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3014-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice' package(s) announced via the USN-3014-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jing Zhao discovered that the Spice smartcard support incorrectly handled
memory. A remote attacker could use this issue to cause Spice to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only applied to Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2016-0749)

Frediano Ziglio discovered that Spice incorrectly handled certain primary
surface parameters. A malicious guest operating system could potentially
exploit this issue to escape virtualization. (CVE-2016-2150)");

  script_tag(name:"affected", value:"'spice' package(s) on Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libspice-server1", ver:"0.12.4-0nocelt2ubuntu1.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libspice-server1", ver:"0.12.5-1.1ubuntu2.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libspice-server1", ver:"0.12.6-4ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
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