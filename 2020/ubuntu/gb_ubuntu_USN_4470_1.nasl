# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844547");
  script_cve_id("CVE-2017-6318", "CVE-2020-12861", "CVE-2020-12862", "CVE-2020-12863", "CVE-2020-12864", "CVE-2020-12865", "CVE-2020-12866", "CVE-2020-12867");
  script_tag(name:"creation_date", value:"2020-08-25 03:00:47 +0000 (Tue, 25 Aug 2020)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-4470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4470-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4470-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sane-backends' package(s) announced via the USN-4470-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kritphong Mongkhonvanit discovered that sane-backends incorrectly handled
certain packets. A remote attacker could possibly use this issue to obtain
sensitive memory information. This issue only affected Ubuntu 16.04 LTS.
(CVE-2017-6318)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to execute
arbitrary code. This issue only applied to Ubuntu 18.04 LTS and Ubuntu
20.04 LTS. (CVE-2020-12861)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to obtain
sensitive information. (CVE-2020-12862, CVE-2020-12863)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to obtain
sensitive information. This issue only applied to Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-12864)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to execute
arbitrary code. (CVE-2020-12865)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to cause a
denial of service. This issue only applied to Ubuntu 18.04 LTS and Ubuntu
20.04 LTS. (CVE-2020-12866)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to cause a
denial of service. (CVE-2020-12867)");

  script_tag(name:"affected", value:"'sane-backends' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsane", ver:"1.0.25+git20150528-1ubuntu2.16.04.3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsane1", ver:"1.0.27-1~experimental3ubuntu2.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libsane1", ver:"1.0.29-0ubuntu5.1", rls:"UBUNTU20.04 LTS"))) {
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