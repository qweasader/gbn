# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.843225");
  script_cve_id("CVE-2016-6329", "CVE-2017-7479", "CVE-2017-7508", "CVE-2017-7512", "CVE-2017-7520", "CVE-2017-7521");
  script_tag(name:"creation_date", value:"2017-06-23 05:17:19 +0000 (Fri, 23 Jun 2017)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|16\.10|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3339-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3339-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvpn' package(s) announced via the USN-3339-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Karthikeyan Bhargavan and Gaetan Leurent discovered that 64-bit block
ciphers are vulnerable to a birthday attack. A remote attacker could
possibly use this issue to recover cleartext data. Fixing this issue
requires a configuration change to switch to a different cipher. This
update adds a warning to the log file when a 64-bit block cipher is in use.
This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and
Ubuntu 16.10. (CVE-2016-6329)

It was discovered that OpenVPN incorrectly handled rollover of packet ids.
An authenticated remote attacker could use this issue to cause OpenVPN to
crash, resulting in a denial of service. This issue only affected Ubuntu
14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2017-7479)

Guido Vranken discovered that OpenVPN incorrectly handled certain malformed
IPv6 packets. A remote attacker could use this issue to cause OpenVPN to
crash, resulting in a denial of service. (CVE-2017-7508)

Guido Vranken discovered that OpenVPN incorrectly handled memory. A remote
attacker could use this issue to cause OpenVPN to crash, resulting in a
denial of service. (CVE-2017-7512)

Guido Vranken discovered that OpenVPN incorrectly handled an HTTP proxy
with NTLM authentication. A remote attacker could use this issue to cause
OpenVPN clients to crash, resulting in a denial of service, or possibly
expose sensitive memory contents. (CVE-2017-7520)

Guido Vranken discovered that OpenVPN incorrectly handled certain x509
extensions. A remote attacker could use this issue to cause OpenVPN to
crash, resulting in a denial of service. (CVE-2017-7521)");

  script_tag(name:"affected", value:"'openvpn' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openvpn", ver:"2.3.2-7ubuntu3.2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openvpn", ver:"2.3.10-1ubuntu2.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openvpn", ver:"2.3.11-1ubuntu2.1", rls:"UBUNTU16.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openvpn", ver:"2.4.0-4ubuntu1.3", rls:"UBUNTU17.04"))) {
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
