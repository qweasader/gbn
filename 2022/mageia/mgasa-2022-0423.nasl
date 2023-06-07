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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0423");
  script_cve_id("CVE-2022-44638");
  script_tag(name:"creation_date", value:"2022-11-14 04:25:42 +0000 (Mon, 14 Nov 2022)");
  script_version("2022-11-14T10:12:51+0000");
  script_tag(name:"last_modification", value:"2022-11-14 10:12:51 +0000 (Mon, 14 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-05 03:15:00 +0000 (Sat, 05 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0423)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0423");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0423.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31088");
  script_xref(name:"URL", value:"https://lists.x.org/archives/xorg-announce/2022-November/003249.html");
  script_xref(name:"URL", value:"https://lists.x.org/archives/xorg-announce/2022-November/003251.html");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3179");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pixman' package(s) announced via the MGASA-2022-0423 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In libpixman in Pixman before 0.42.2, there is an out-of-bounds write (aka
heap-based buffer overflow) in rasterize_edges_8 due to an integer
overflow in pixman_sample_floor_y. (CVE-2022-44638)");

  script_tag(name:"affected", value:"'pixman' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64pixman-devel", rpm:"lib64pixman-devel~0.40.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pixman1_0", rpm:"lib64pixman1_0~0.40.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpixman-devel", rpm:"libpixman-devel~0.40.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpixman1_0", rpm:"libpixman1_0~0.40.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pixman", rpm:"pixman~0.40.0~1.1.mga8", rls:"MAGEIA8"))) {
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
