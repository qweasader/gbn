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
  script_oid("1.3.6.1.4.1.25623.1.0.844614");
  script_cve_id("CVE-2019-12107", "CVE-2019-12108", "CVE-2019-12109", "CVE-2019-12110", "CVE-2019-12111");
  script_tag(name:"creation_date", value:"2020-09-26 03:00:31 +0000 (Sat, 26 Sep 2020)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 20:15:00 +0000 (Mon, 28 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-4542-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4542-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4542-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'miniupnpd' package(s) announced via the USN-4542-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that MiniUPnPd did not properly validate callback
addresses. A remote attacker could possibly use this issue to expose
sensitive information. (CVE-2019-12107)

It was discovered that MiniUPnPd incorrectly handled unpopulated user XML
input. An attacker could possibly use this issue to cause MiniUPnPd to
crash, resulting in a denial of service. (CVE-2019-12108, CVE-2019-12109)

It was discovered that MiniUPnPd incorrectly handled an empty description
when port mapping. An attacker could possibly use this issue to cause
MiniUPnPd to crash, resulting in a denial of service. (CVE-2019-12110)

It was discovered that MiniUPnPd did not properly parse certain PCP
requests. An attacker could possibly use this issue to cause MiniUPnPd to
crash, resulting in a denial of service. (CVE-2019-12111)");

  script_tag(name:"affected", value:"'miniupnpd' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"miniupnpd", ver:"1.8.20140523-4.1+deb9u2build0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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