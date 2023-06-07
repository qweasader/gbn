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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2020.4376.2");
  script_cve_id("CVE-2019-1547", "CVE-2019-1559", "CVE-2019-1563");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-24 19:47:00 +0000 (Thu, 24 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-4376-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4376-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4376-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-4376-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4376-1 fixed several vulnerabilities in OpenSSL. This update provides
the corresponding update for Ubuntu 12.04 ESM and Ubuntu 14.04 ESM.

Original advisory details:

 Cesar Pereida Garcia, Sohaib ul Hassan, Nicola Tuveri, Iaroslav Gridin,
 Alejandro Cabrera Aldaya, and Billy Brumley discovered that OpenSSL
 incorrectly handled ECDSA signatures. An attacker could possibly use this
 issue to perform a timing side-channel attack and recover private ECDSA
 keys. (CVE-2019-1547)

 Juraj Somorovsky, Robert Merget, and Nimrod Aviram discovered that certain
 applications incorrectly used OpenSSL and could be exposed to a padding
 oracle attack. A remote attacker could possibly use this issue to decrypt
 data. (CVE-2019-1559)

 Bernd Edlinger discovered that OpenSSL incorrectly handled certain
 decryption functions. In certain scenarios, a remote attacker could
 possibly use this issue to perform a padding oracle attack and decrypt
 traffic. (CVE-2019-1563)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 12.04, Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1-4ubuntu5.44", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu2.27+esm1", rls:"UBUNTU14.04 LTS"))) {
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
