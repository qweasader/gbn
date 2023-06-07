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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0346");
  script_cve_id("CVE-2016-4273", "CVE-2016-4286", "CVE-2016-6981", "CVE-2016-6982", "CVE-2016-6983", "CVE-2016-6984", "CVE-2016-6985", "CVE-2016-6986", "CVE-2016-6987", "CVE-2016-6989", "CVE-2016-6990", "CVE-2016-6992");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-11-21T10:11:06+0000");
  script_tag(name:"last_modification", value:"2022-11-21 10:11:06 +0000 (Mon, 21 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-18 17:29:00 +0000 (Fri, 18 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2016-0346)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0346");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0346.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19584");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-32.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2016-0346 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.637 contains fixes to critical security
vulnerabilities found in earlier versions that could potentially allow
an attacker to take control of the affected system.

This update resolves a type confusion vulnerability that could lead to
code execution (CVE-2016-6992).
This update resolves use-after-free vulnerabilities that could lead to
code execution (CVE-2016-6981, CVE-2016-6987).
This update resolves a security bypass vulnerability (CVE-2016-4286).
This update resolves memory corruption vulnerabilities that could lead
to code execution (CVE-2016-4273, CVE-2016-6982, CVE-2016-6983,
CVE-2016-6984, CVE-2016-6985, CVE-2016-6986, CVE-2016-6989,
CVE-2016-6990).");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.637~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.637~1.mga5.nonfree", rls:"MAGEIA5"))) {
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
