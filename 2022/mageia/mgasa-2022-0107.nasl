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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0107");
  script_cve_id("CVE-2022-0971", "CVE-2022-0972", "CVE-2022-0973", "CVE-2022-0974", "CVE-2022-0975", "CVE-2022-0976", "CVE-2022-0977", "CVE-2022-0978", "CVE-2022-0979", "CVE-2022-0980");
  script_tag(name:"creation_date", value:"2022-03-22 04:07:04 +0000 (Tue, 22 Mar 2022)");
  script_version("2022-07-28T10:10:25+0000");
  script_tag(name:"last_modification", value:"2022-07-28 10:10:25 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-26 14:29:00 +0000 (Tue, 26 Jul 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0107)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0107");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0107.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30183");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/03/stable-channel-update-for-desktop_15.html?m=1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0107 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the 99.0.4844.74
version that fixes multiples security vulnerabilities.

[1299422] Critical CVE-2022-0971: Use after free in Blink Layout.
[1301320] High CVE-2022-0972: Use after free in Extensions.
[1297498] High CVE-2022-0973: Use after free in Safe Browsing.
[1291986] High CVE-2022-0974 : Use after free in Splitscreen.
[1295411] High CVE-2022-0975: Use after free in ANGLE.
[1296866] High CVE-2022-0976: Heap buffer overflow in GPU.
[1299225] High CVE-2022-0977: Use after free in Browser UI.
[1299264] High CVE-2022-0978: Use after free in ANGLE.
[1302644] High CVE-2022-0979: Use after free in Safe Browsing.
[1302157] Medium CVE-2022-0980: Use after free in New Tab Page.");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~99.0.4844.74~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~99.0.4844.74~1.mga8", rls:"MAGEIA8"))) {
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
