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
  script_oid("1.3.6.1.4.1.25623.1.0.843449");
  script_cve_id("CVE-2014-1693", "CVE-2015-2774", "CVE-2016-10253", "CVE-2017-1000385");
  script_tag(name:"creation_date", value:"2018-02-15 07:44:50 +0000 (Thu, 15 Feb 2018)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-11 15:07:00 +0000 (Wed, 11 Jul 2018)");

  script_name("Ubuntu: Security Advisory (USN-3571-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3571-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3571-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'erlang' package(s) announced via the USN-3571-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Erlang FTP module incorrectly handled certain
CRLF sequences. A remote attacker could possibly use this issue to inject
arbitrary FTP commands. This issue only affected Ubuntu 14.04 LTS.
(CVE-2014-1693)

It was discovered that Erlang incorrectly checked CBC padding bytes. A
remote attacker could possibly use this issue to perform a padding oracle
attack and decrypt traffic. This issue only affected Ubuntu 14.04 LTS.
(CVE-2015-2774)

It was discovered that Erlang incorrectly handled certain regular
expressions. A remote attacker could possibly use this issue to cause
Erlang to crash, resulting in a denial of service, or execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-10253)

Hanno Bock, Juraj Somorovsky and Craig Young discovered that the Erlang
otp TLS server incorrectly handled error reporting. A remote attacker could
possibly use this issue to perform a variation of the Bleichenbacher attack
and decrypt traffic or sign messages. (CVE-2017-1000385)");

  script_tag(name:"affected", value:"'erlang' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"erlang", ver:"1:16.b.3-dfsg-1ubuntu2.2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"erlang", ver:"1:18.3-dfsg-1ubuntu3.1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"erlang", ver:"1:20.0.4+dfsg-1ubuntu1.1", rls:"UBUNTU17.10"))) {
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
