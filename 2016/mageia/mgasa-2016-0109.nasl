# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.131264");
  script_cve_id("CVE-2016-0960", "CVE-2016-0961", "CVE-2016-0962", "CVE-2016-0963", "CVE-2016-0986", "CVE-2016-0987", "CVE-2016-0988", "CVE-2016-0989", "CVE-2016-0990", "CVE-2016-0991", "CVE-2016-0993", "CVE-2016-0994", "CVE-2016-0995", "CVE-2016-0996", "CVE-2016-1000", "CVE-2016-1001", "CVE-2016-1005", "CVE-2016-1010");
  script_tag(name:"creation_date", value:"2016-03-14 13:57:14 +0000 (Mon, 14 Mar 2016)");
  script_version("2023-01-20T10:11:50+0000");
  script_tag(name:"last_modification", value:"2023-01-20 10:11:50 +0000 (Fri, 20 Jan 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-14 18:33:00 +0000 (Wed, 14 Dec 2022)");

  script_name("Mageia: Security Advisory (MGASA-2016-0109)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0109");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0109.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17945");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-08.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2016-0109 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.577 contains fixes to critical security
vulnerabilities found in earlier versions that could potentially allow an
attacker to take control of the affected system.

This update resolves integer overflow vulnerabilities that could lead to
code execution (CVE-2016-0963, CVE-2016-0993, CVE-2016-1010).

This update resolves use-after-free vulnerabilities that could lead to
code execution (CVE-2016-0987, CVE-2016-0988, CVE-2016-0990,
CVE-2016-0991, CVE-2016-0994, CVE-2016-0995, CVE-2016-0996,
CVE-2016-1000).

This update resolves a heap overflow vulnerability that could lead to code
execution (CVE-2016-1001).

This update resolves memory corruption vulnerabilities that could lead to
code execution (CVE-2016-0960, CVE-2016-0961, CVE-2016-0962,
CVE-2016-0986, CVE-2016-0989, CVE-2016-1005).

Adobe reports that an exploit for CVE-2016-1010 is being used in limited,
targeted attacks.");

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

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.577~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.577~1.mga5.nonfree", rls:"MAGEIA5"))) {
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
