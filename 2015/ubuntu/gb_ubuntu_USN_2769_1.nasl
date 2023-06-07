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
  script_oid("1.3.6.1.4.1.25623.1.0.842488");
  script_cve_id("CVE-2012-5783", "CVE-2012-6153", "CVE-2014-3577", "CVE-2015-5262");
  script_tag(name:"creation_date", value:"2015-10-15 06:48:23 +0000 (Thu, 15 Oct 2015)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2769-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2769-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2769-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'commons-httpclient' package(s) announced via the USN-2769-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Apache Commons HttpClient did not properly verify the
Common Name or subjectAltName fields of X.509 certificates. An attacker could
exploit this to perform a machine-in-the-middle attack to view sensitive
information or alter encrypted communications. This issue only affected Ubuntu
12.04 LTS. (CVE-2012-5783)

Florian Weimer discovered the fix for CVE-2012-5783 was incomplete for Apache
Commons HttpClient. An attacker could exploit this to perform a
machine-in-the-middle attack to view sensitive information or alter
encrypted communications. This issue only affected Ubuntu 12.04 LTS.
(CVE-2012-6153)

Subodh Iyengar and Will Shackleton discovered the fix for CVE-2012-5783 was
incomplete for Apache Commons HttpClient. An attacker could exploit this to
perform a machine-in-the-middle attack to view sensitive information or alter
encrypted communications. (CVE-2014-3577)

It was discovered that Apache Commons HttpClient did not properly handle read
timeouts during HTTPS handshakes. A remote attacker could trigger this flaw to
cause a denial of service. (CVE-2015-5262)");

  script_tag(name:"affected", value:"'commons-httpclient' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcommons-httpclient-java", ver:"3.1-10ubuntu0.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libcommons-httpclient-java", ver:"3.1-10.2ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libcommons-httpclient-java", ver:"3.1-10.2ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
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
