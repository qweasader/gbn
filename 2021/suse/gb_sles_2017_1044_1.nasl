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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1044.1");
  script_cve_id("CVE-2016-10266", "CVE-2016-10267", "CVE-2016-10268", "CVE-2016-10269", "CVE-2016-10270", "CVE-2016-10271", "CVE-2016-10272");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-31 01:59:00 +0000 (Fri, 31 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1044-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1044-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171044-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2017:1044-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following issues:
Security issues fixed:
- CVE-2016-10272: LibTIFF 4.0.7 allows remote attackers to cause a denial
 of service (heap-based buffer overflow) or possibly have unspecified
 other impact via a crafted TIFF image, related to 'WRITE of size 2048'
 and libtiff/tif_next.c:64:9 (bsc#1031247).
- CVE-2016-10271: tools/tiffcrop.c in LibTIFF 4.0.7 allows remote
 attackers to cause a denial of service (heap-based buffer over-read and
 buffer overflow) or possibly have unspecified other impact via a crafted
 TIFF image, related to 'READ of size 1' and libtiff/tif_fax3.c:413:13
 (bsc#1031249).
- CVE-2016-10270: LibTIFF 4.0.7 allows remote attackers to cause a denial
 of service (heap-based buffer over-read) or possibly have unspecified
 other impact via a crafted TIFF image, related to 'READ of size 8' and
 libtiff/tif_read.c:523:22 (bsc#1031250).
- CVE-2016-10269: LibTIFF 4.0.7 allows remote attackers to cause a denial
 of service (heap-based buffer over-read) or possibly have unspecified
 other impact via a crafted TIFF image, related to 'READ of size 512' and
 libtiff/tif_unix.c:340:2 (bsc#1031254).
- CVE-2016-10268: tools/tiffcp.c in LibTIFF 4.0.7 allows remote attackers
 to cause a denial of service (integer underflow and heap-based buffer
 under-read) or possibly have unspecified other impact via a crafted TIFF
 image, related to 'READ of size 78490' and libtiff/tif_unix.c:115:23
 (bsc#1031255).
- CVE-2016-10267: LibTIFF 4.0.7 allows remote attackers to cause a denial
 of service (divide-by-zero error and application crash) via a crafted
 TIFF image, related to libtiff/tif_ojpeg.c:816:8 (bsc#1031262).
- CVE-2016-10266: LibTIFF 4.0.7 allows remote attackers to cause a denial
 of service (divide-by-zero error and application crash) via a crafted
 TIFF image, related to libtiff/tif_read.c:351:22. (bsc#1031263).");

  script_tag(name:"affected", value:"'tiff' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.7~43.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.7~43.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-debuginfo-32bit", rpm:"libtiff5-debuginfo-32bit~4.0.7~43.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.7~43.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.7~43.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.7~43.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.7~43.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.7~43.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.7~43.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-debuginfo-32bit", rpm:"libtiff5-debuginfo-32bit~4.0.7~43.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.7~43.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.7~43.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.7~43.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.7~43.1", rls:"SLES12.0SP2"))) {
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
