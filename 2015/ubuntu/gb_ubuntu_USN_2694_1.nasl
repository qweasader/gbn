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
  script_oid("1.3.6.1.4.1.25623.1.0.842393");
  script_cve_id("CVE-2014-8964", "CVE-2015-2325", "CVE-2015-2326", "CVE-2015-3210", "CVE-2015-5073");
  script_tag(name:"creation_date", value:"2015-07-30 03:15:02 +0000 (Thu, 30 Jul 2015)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-2694-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2694-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2694-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcre3' package(s) announced via the USN-2694-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michele Spagnuolo discovered that PCRE incorrectly handled certain regular
expressions. A remote attacker could use this issue to cause applications
using PCRE to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS. (CVE-2014-8964)

Kai Lu discovered that PCRE incorrectly handled certain regular
expressions. A remote attacker could use this issue to cause applications
using PCRE to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS and Ubuntu 15.04.
(CVE-2015-2325, CVE-2015-2326)

Wen Guanxing discovered that PCRE incorrectly handled certain regular
expressions. A remote attacker could use this issue to cause applications
using PCRE to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 15.04. (CVE-2015-3210)

It was discovered that PCRE incorrectly handled certain regular
expressions. A remote attacker could use this issue to cause applications
using PCRE to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 12.04 LTS and 14.04 LTS.
(CVE-2015-5073)");

  script_tag(name:"affected", value:"'pcre3' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpcre3", ver:"8.12-4ubuntu0.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpcre3", ver:"1:8.31-2ubuntu2.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libpcre3", ver:"2:8.35-3.3ubuntu1.1", rls:"UBUNTU15.04"))) {
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
