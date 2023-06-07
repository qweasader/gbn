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
  script_oid("1.3.6.1.4.1.25623.1.0.844537");
  script_cve_id("CVE-2018-15750", "CVE-2018-15751", "CVE-2019-17361", "CVE-2020-11651", "CVE-2020-11652");
  script_tag(name:"creation_date", value:"2020-08-15 03:00:16 +0000 (Sat, 15 Aug 2020)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-20 01:17:00 +0000 (Thu, 20 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4459-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4459-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4459-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the USN-4459-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Salt allows remote attackers to determine which files
exist on the server. An attacker could use that to extract sensitive
information. (CVE-2018-15750)

It was discovered that Salt has a vulnerability that allows an user to bypass
authentication. An attacker could use that to extract sensitive information,
execute arbitrary code or crash the server. (CVE-2018-15751)

It was discovered that Salt is vulnerable to command injection. This allows
an unauthenticated attacker with network access to the API endpoint to
execute arbitrary code on the salt-api host. (CVE-2019-17361)

It was discovered that Salt incorrectly validated method calls and
sanitized paths. A remote attacker could possibly use this issue to access
some methods without authentication. (CVE-2020-11651, CVE-2020-11652)");

  script_tag(name:"affected", value:"'salt' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"salt-api", ver:"2015.8.8+ds-1ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"2015.8.8+ds-1ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-master", ver:"2015.8.8+ds-1ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-minion", ver:"2015.8.8+ds-1ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"salt-api", ver:"2017.7.4+dfsg1-1ubuntu18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"2017.7.4+dfsg1-1ubuntu18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-master", ver:"2017.7.4+dfsg1-1ubuntu18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-minion", ver:"2017.7.4+dfsg1-1ubuntu18.04.2", rls:"UBUNTU18.04 LTS"))) {
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
