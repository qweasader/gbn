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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0290");
  script_cve_id("CVE-2020-36277", "CVE-2020-36278", "CVE-2020-36279", "CVE-2020-36280", "CVE-2020-36281");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-22 12:58:00 +0000 (Thu, 22 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0290)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0290");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0290.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28994");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JQUEA2X6UTH4DMYCMZAWE2QQLN5YANUA/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2612");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'leptonica' package(s) announced via the MGASA-2021-0290 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Leptonica before 1.80.0 allows a denial of service (application crash) via an
incorrect left shift in pixConvert2To8 in pixconv.c (CVE-2020-36277).

Leptonica before 1.80.0 allows a heap-based buffer over-read in
findNextBorderPixel in ccbord.c (CVE-2020-36278).

Leptonica before 1.80.0 allows a heap-based buffer over-read in
rasteropGeneralLow, related to adaptmap_reg.c and adaptmap.c (CVE-2020-36279).

Leptonica before 1.80.0 allows a heap-based buffer over-read in
pixReadFromTiffStream, related to tiffio.c (CVE-2020-36280).

Leptonica before 1.80.0 allows a heap-based buffer over-read in
pixFewColorsOctcubeQuantMixed in colorquant1.c (CVE-2020-36281).");

  script_tag(name:"affected", value:"'leptonica' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"leptonica", rpm:"leptonica~1.80.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64leptonica-devel", rpm:"lib64leptonica-devel~1.80.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64leptonica5", rpm:"lib64leptonica5~1.80.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libleptonica-devel", rpm:"libleptonica-devel~1.80.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libleptonica5", rpm:"libleptonica5~1.80.0~1.mga7", rls:"MAGEIA7"))) {
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
