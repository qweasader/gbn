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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0098");
  script_cve_id("CVE-2020-19143", "CVE-2020-35521", "CVE-2020-35522", "CVE-2020-35523", "CVE-2020-35524");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-08 11:15:00 +0000 (Thu, 08 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0098)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0098");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0098.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28455");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4755-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/CVE-2020-19143");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/BMHBYFMX3D5VGR6Y3RXTTH3Q4NF4E6IG/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff' package(s) announced via the MGASA-2021-0098 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated libtiff packages fix security vulnerabilities:
- Integer overflow in tif_getimage.c (CVE-2020-35523).
- Heap-based buffer overflow in TIFF2PDF tool (CVE-2020-35524).
- Buffer Overflow in LibTiff v4.0.10 allows attackers to cause a denial of
 service via the 'TIFFVGetField' function in the component
 'libtiff/tif_dir.c'. (CVE-2020-19143)
- Memory allocation failure in tiff2rgba (CVE-2020-35521)
- Memory allocation failure in tiff2rgba (CVE-2020-35522)");

  script_tag(name:"affected", value:"'libtiff' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-devel", rpm:"lib64tiff-devel~4.2.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-static-devel", rpm:"lib64tiff-static-devel~4.2.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff5", rpm:"lib64tiff5~4.2.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.2.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.2.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~4.2.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-static-devel", rpm:"libtiff-static-devel~4.2.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.2.0~1.mga7", rls:"MAGEIA7"))) {
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
