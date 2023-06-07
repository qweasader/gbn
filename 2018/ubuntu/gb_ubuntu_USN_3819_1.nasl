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
  script_oid("1.3.6.1.4.1.25623.1.0.843818");
  script_cve_id("CVE-2018-15471");
  script_tag(name:"creation_date", value:"2018-11-15 04:59:08 +0000 (Thu, 15 Nov 2018)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3819-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.10");

  script_xref(name:"Advisory-ID", value:"USN-3819-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3819-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-kvm, linux-raspi2' package(s) announced via the USN-3819-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Felix Wilhelm discovered that the Xen netback driver in the Linux kernel
did not properly perform input validation in some situations. An attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code.");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-kvm, linux-raspi2' package(s) on Ubuntu 18.10.");

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

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-1003-gcp", ver:"4.18.0-1003.4", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-1004-aws", ver:"4.18.0-1004.5", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-1004-kvm", ver:"4.18.0-1004.4", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-1006-raspi2", ver:"4.18.0-1006.8", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-11-generic-lpae", ver:"4.18.0-11.12", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-11-generic", ver:"4.18.0-11.12", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-11-lowlatency", ver:"4.18.0-11.12", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-11-snapdragon", ver:"4.18.0-11.12", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.18.0.1004.4", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.18.0.1003.3", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.18.0.11.12", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.18.0.11.12", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.18.0.1003.3", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.18.0.1004.4", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.18.0.11.12", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.18.0.1006.3", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"4.18.0.11.12", rls:"UBUNTU18.10"))) {
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
