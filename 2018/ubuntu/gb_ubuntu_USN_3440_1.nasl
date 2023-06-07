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
  script_oid("1.3.6.1.4.1.25623.1.0.843767");
  script_cve_id("CVE-2017-14518", "CVE-2017-14520", "CVE-2017-14617", "CVE-2017-14926", "CVE-2017-14928", "CVE-2017-14929", "CVE-2017-14975", "CVE-2017-14977", "CVE-2017-9776");
  script_tag(name:"creation_date", value:"2018-10-26 04:16:50 +0000 (Fri, 26 Oct 2018)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-12 17:27:00 +0000 (Tue, 12 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-3440-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3440-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3440-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the USN-3440-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Poppler incorrectly handled certain files.
If a user or automated system were tricked into opening a
crafted PDF file, an attacker could cause a denial of service.
(CVE-2017-14518, CVE-2017-14520, CVE-2017-14617, CVE-2017-14929,
CVE-2017-14975, CVE-2017-14977)

It was discovered that Poppler incorrectly handled certain files.
If a user or automated system were tricked into opening a crafted
PDF file, an attacker could cause a denial of service. This issue
only affected Ubuntu 17.04 and 16.04. (CVE-2017-14926, CVE-2017-14928)

Alberto Garcia, Francisco Oca and Suleman Ali discovered that Poppler
incorrectly handled certain files. If a user or automated system were
tricked into opening a crafted PDF file, an attacker could cause a
denial of service. (CVE-2017-9776)");

  script_tag(name:"affected", value:"'poppler' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler44", ver:"0.24.5-2ubuntu4.7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.24.5-2ubuntu4.7", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler58", ver:"0.41.0-0ubuntu1.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.41.0-0ubuntu1.4", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler64", ver:"0.48.0-2ubuntu2.3", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.48.0-2ubuntu2.3", rls:"UBUNTU17.04"))) {
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
