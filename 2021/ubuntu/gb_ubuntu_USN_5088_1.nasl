# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.845073");
  script_cve_id("CVE-2019-11098", "CVE-2021-23840", "CVE-2021-3712", "CVE-2021-38575");
  script_tag(name:"creation_date", value:"2021-09-24 01:06:50 +0000 (Fri, 24 Sep 2021)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-10 18:41:00 +0000 (Fri, 10 Dec 2021)");

  script_name("Ubuntu: Security Advisory (USN-5088-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|21\.04)");

  script_xref(name:"Advisory-ID", value:"USN-5088-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5088-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'edk2' package(s) announced via the USN-5088-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that EDK II incorrectly handled input validation in
MdeModulePkg. A local user could possibly use this issue to cause EDK II to
crash, resulting in a denial of service, obtain sensitive information or
execute arbitrary code. (CVE-2019-11098)

Paul Kehrer discovered that OpenSSL used in EDK II incorrectly handled
certain input lengths in EVP functions. An attacker could possibly use this
issue to cause EDK II to crash, resulting in a denial of service.
(CVE-2021-23840)

Ingo Schwarze discovered that OpenSSL used in EDK II incorrectly handled
certain ASN.1 strings. An attacker could use this issue to cause EDK II to
crash, resulting in a denial of service, or possibly obtain sensitive
information. (CVE-2021-3712)

It was discovered that EDK II incorrectly decoded certain strings. A remote
attacker could use this issue to cause EDK II to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2021-38575)");

  script_tag(name:"affected", value:"'edk2' package(s) on Ubuntu 20.04, Ubuntu 21.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"0~20191122.bd85bf54-2ubuntu3.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"0~20191122.bd85bf54-2ubuntu3.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"0~20191122.bd85bf54-2ubuntu3.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi", ver:"0~20191122.bd85bf54-2ubuntu3.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.04") {

  if(!isnull(res = isdpkgvuln(pkg:"ovmf-ia32", ver:"2020.11-4ubuntu0.1", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"2020.11-4ubuntu0.1", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"2020.11-4ubuntu0.1", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"2020.11-4ubuntu0.1", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi", ver:"2020.11-4ubuntu0.1", rls:"UBUNTU21.04"))) {
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
