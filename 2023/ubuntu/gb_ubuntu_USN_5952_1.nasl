# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5952.1");
  script_cve_id("CVE-2020-15389", "CVE-2020-27814", "CVE-2020-27823", "CVE-2020-27824", "CVE-2020-27841", "CVE-2020-27842", "CVE-2020-27843", "CVE-2020-27845", "CVE-2020-6851", "CVE-2020-8112");
  script_tag(name:"creation_date", value:"2023-03-16 04:11:27 +0000 (Thu, 16 Mar 2023)");
  script_version("2023-03-16T10:19:47+0000");
  script_tag(name:"last_modification", value:"2023-03-16 10:19:47 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-5952-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5952-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5952-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg2' package(s) announced via the USN-5952-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sebastian Poeplau discovered that OpenJPEG incorrectly handled certain inputs.
If a user or an automated system were tricked into opening a specially crafted
input file, a remote attacker could possibly use this issue to cause a denial
of service or execute arbitrary code. This issue only affected Ubuntu 18.04
LTS. (CVE-2020-6851, CVE-2020-8112)

It was discovered that OpenJPEG incorrectly handled certain inputs. If a user
or an automated system were tricked into opening a specially crafted input
file, a remote attacker could possibly use this issue to cause a denial of
service or execute arbitrary code. This issue only affected Ubuntu 18.04 LTS.
(CVE-2020-15389, CVE-2020-27814, CVE-2020-27823, CVE-2020-27824,
CVE-2020-27841, CVE-2020-27845)

It was discovered that OpenJPEG incorrectly handled certain inputs. If a user
or an automated system were tricked into opening a specially crafted input
file, a remote attacker could possibly use this issue to cause a denial of
service. (CVE-2020-27842, CVE-2020-27843)");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7", ver:"2.1.2-1.1+deb9u6ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp3d7", ver:"2.1.2-1.1+deb9u6ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip7", ver:"2.1.2-1.1+deb9u6ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7", ver:"2.3.0-2+deb10u2build0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp3d7", ver:"2.3.0-2+deb10u2build0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip7", ver:"2.3.0-2+deb10u2build0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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
