# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2021.5006.2");
  script_cve_id("CVE-2020-7068", "CVE-2020-7071", "CVE-2021-21702", "CVE-2021-21704", "CVE-2021-21705");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-08 03:44:00 +0000 (Fri, 08 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5006-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5006-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5006-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5, php7.0' package(s) announced via the USN-5006-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5006-1 fixed several vulnerabilities in PHP. This update provides
the corresponding update for Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.

Original advisory details:

 It was discovered that PHP incorrectly handled certain PHAR files. A remote
 attacker could possibly use this issue to cause PHP to crash, resulting in
 a denial of service, or possibly obtain sensitive information. (CVE-2020-7068)

 It was discovered that PHP incorrectly handled parsing URLs with passwords.
 A remote attacker could possibly use this issue to cause PHP to mis-parse
 the URL and produce wrong data. (CVE-2020-7071)

 It was discovered that PHP incorrectly handled certain malformed XML data
 when being parsed by the SOAP extension. A remote attacker could possibly
 use this issue to cause PHP to crash, resulting in a denial of service.
 (CVE-2021-21702)

 It was discovered that PHP incorrectly handled the pdo_firebase module. A
 remote attacker could possibly use this issue to cause PHP to crash,
 resulting in a denial of service. (CVE-2021-21704)

 It was discovered that PHP incorrectly handled the FILTER_VALIDATE_URL
 check. A remote attacker could possibly use this issue to perform a server-
 side request forgery attack. (CVE-2021-21705)");

  script_tag(name:"affected", value:"'php5, php7.0' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.5.9+dfsg-1ubuntu4.29+esm14", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.5.9+dfsg-1ubuntu4.29+esm14", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.5.9+dfsg-1ubuntu4.29+esm14", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.5.9+dfsg-1ubuntu4.29+esm14", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.0", ver:"7.0.33-0ubuntu0.16.04.16+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-cgi", ver:"7.0.33-0ubuntu0.16.04.16+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-cli", ver:"7.0.33-0ubuntu0.16.04.16+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-fpm", ver:"7.0.33-0ubuntu0.16.04.16+esm1", rls:"UBUNTU16.04 LTS"))) {
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
