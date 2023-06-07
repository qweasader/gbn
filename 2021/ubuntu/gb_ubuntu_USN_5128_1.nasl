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
  script_oid("1.3.6.1.4.1.25623.1.0.845119");
  script_cve_id("CVE-2020-27781", "CVE-2021-20288", "CVE-2021-3509", "CVE-2021-3524", "CVE-2021-3531");
  script_tag(name:"creation_date", value:"2021-11-02 02:01:00 +0000 (Tue, 02 Nov 2021)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-03 18:28:00 +0000 (Thu, 03 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-5128-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|21\.04)");

  script_xref(name:"Advisory-ID", value:"USN-5128-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5128-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the USN-5128-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Goutham Pacha Ravi, Jahson Babel, and John Garbutt discovered that user
credentials in Ceph could be manipulated in certain environments. An
attacker could use this to gain unintended access to resources. This issue
only affected Ubuntu 18.04 LTS. (CVE-2020-27781)

It was discovered that Ceph contained an authentication flaw, leading to
key reuse. An attacker could use this to cause a denial of service or
possibly impersonate another user. This issue only affected Ubuntu 21.04.
(CVE-2021-20288)

Sergey Bobrov discovered that the Ceph dashboard was susceptible to a
cross-site scripting attack. An attacker could use this to expose sensitive
information or gain unintended access. This issue only affected Ubuntu
21.04. (CVE-2021-3509)

Sergey Bobrov discovered that Ceph's RadosGW (Ceph Object Gateway) allowed
the injection of HTTP headers in responses to CORS requests. An attacker
could use this to violate system integrity. (CVE-2021-3524)

It was discovered that Ceph's RadosGW (Ceph Object Gateway) did not
properly handle GET requests for swift URLs in some situations, leading to
an application crash. An attacker could use this to cause a denial of
service. (CVE-2021-3531)");

  script_tag(name:"affected", value:"'ceph' package(s) on Ubuntu 18.04, Ubuntu 21.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ceph-base", ver:"12.2.13-0ubuntu0.18.04.10", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"12.2.13-0ubuntu0.18.04.10", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"12.2.13-0ubuntu0.18.04.10", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ceph-base", ver:"16.2.6-0ubuntu0.21.04.2", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"16.2.6-0ubuntu0.21.04.2", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"16.2.6-0ubuntu0.21.04.2", rls:"UBUNTU21.04"))) {
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