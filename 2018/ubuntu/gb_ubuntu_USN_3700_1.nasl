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
  script_oid("1.3.6.1.4.1.25623.1.0.843785");
  script_cve_id("CVE-2018-10958", "CVE-2018-10998", "CVE-2018-10999", "CVE-2018-11531", "CVE-2018-12264", "CVE-2018-12265");
  script_tag(name:"creation_date", value:"2018-10-26 04:19:24 +0000 (Fri, 26 Oct 2018)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3700-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.10|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3700-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3700-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the USN-3700-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Exiv2 incorrectly handled certain files.
An attacker could possibly use this to cause a denial of service.
(CVE-2018-10958, CVE-2018-10998)

It was discovered that Exiv2 incorrectly handled certain PNG files.
An attacker could possibly use this to access sensitive information.
(CVE-2018-10999)

It was discovered that Exiv2 incorrectly handled certain files.
An attacker could possibly use this to execute arbitrary code.
(CVE-2018-11531)

It was discovered that Exiv2 incorrectly handled certain files.
An attacker could possibly use this to access sensitive information.
(CVE-2018-12264, CVE-2018-12265)");

  script_tag(name:"affected", value:"'exiv2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.23-1ubuntu2.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexiv2-12", ver:"0.23-1ubuntu2.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.25-2.1ubuntu16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexiv2-14", ver:"0.25-2.1ubuntu16.04.2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.25-3.1ubuntu0.17.10.1", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexiv2-14", ver:"0.25-3.1ubuntu0.17.10.1", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.25-3.1ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexiv2-14", ver:"0.25-3.1ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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
