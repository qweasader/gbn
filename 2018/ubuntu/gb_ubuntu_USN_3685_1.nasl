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
  script_oid("1.3.6.1.4.1.25623.1.0.843784");
  script_cve_id("CVE-2017-0898", "CVE-2017-0901", "CVE-2017-0902", "CVE-2017-0903", "CVE-2017-10784", "CVE-2017-14064", "CVE-2017-17742", "CVE-2018-1000074", "CVE-2018-8777");
  script_tag(name:"creation_date", value:"2018-10-26 04:18:53 +0000 (Fri, 26 Oct 2018)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-13 18:48:00 +0000 (Mon, 13 May 2019)");

  script_name("Ubuntu: Security Advisory (USN-3685-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3685-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3685-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.9.1, ruby2.0, ruby2.3' package(s) announced via the USN-3685-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Some of these CVE were already addressed in previous
USN: 3439-1, 3553-1, 3528-1. Here we address for
the remain releases.

It was discovered that Ruby incorrectly handled certain inputs.
An attacker could use this to cause a buffer overrun. (CVE-2017-0898)

It was discovered that Ruby incorrectly handled certain files.
An attacker could use this to overwrite any file on the filesystem.
(CVE-2017-0901)

It was discovered that Ruby was vulnerable to a DNS hijacking vulnerability.
An attacker could use this to possibly force the RubyGems client to download
and install gems from a server that the attacker controls. (CVE-2017-0902)

It was discovered that Ruby incorrectly handled certain YAML files.
An attacker could use this to possibly execute arbitrary code. (CVE-2017-0903)

It was discovered that Ruby incorrectly handled certain files.
An attacker could use this to expose sensitive information.
(CVE-2017-14064)

It was discovered that Ruby incorrectly handled certain inputs.
An attacker could use this to execute arbitrary code. (CVE-2017-10784)

It was discovered that Ruby incorrectly handled certain network requests.
An attacker could possibly use this to inject a crafted key into a HTTP
response. (CVE-2017-17742)

It was discovered that Ruby incorrectly handled certain files.
An attacker could possibly use this to execute arbitrary code.
This update is only addressed to ruby2.0. (CVE-2018-1000074)

It was discovered that Ruby incorrectly handled certain network requests.
An attacker could possibly use this to cause a denial of service.
(CVE-2018-8777)");

  script_tag(name:"affected", value:"'ruby1.9.1, ruby2.0, ruby2.3' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1", ver:"1.9.3.484-2ubuntu1.12", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.0", ver:"2.0.0.484-1ubuntu2.10", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1", ver:"1.9.3.484-2ubuntu1.12", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.3", ver:"1.9.3.484-2ubuntu1.12", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.0", ver:"2.0.0.484-1ubuntu2.10", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.1-2~16.04.10", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.1-2~16.04.10", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.3-1ubuntu1.6", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.3-1ubuntu1.6", rls:"UBUNTU17.10"))) {
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
