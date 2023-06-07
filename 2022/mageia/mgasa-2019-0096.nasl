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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0096");
  script_cve_id("CVE-2018-11490");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-02-07T12:10:58+0000");
  script_tag(name:"last_modification", value:"2023-02-07 12:10:58 +0000 (Tue, 07 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-03 19:05:00 +0000 (Fri, 03 Feb 2023)");

  script_name("Mageia: Security Advisory (MGASA-2019-0096)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0096");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0096.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24378");
  script_xref(name:"URL", value:"https://sourceforge.net/p/giflib/code/ci/master/tree/NEWS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'giflib' package(s) announced via the MGASA-2019-0096 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Null dereferences in main() of gifclrmp.
Heap Buffer Overflow-2 in function DGifDecompressLine() in cgif.c.
CVE-2018-11490)
Segmentation fault in PrintCodeBlock.
Segmentation fault of giftool reading a crafted file.
Floating point exception in giftext utility.
Heap buffer overflow in DumpScreen2RGB in gif2rgb.c:317.
Ineffective bounds check in DGifSlurp.
GIFLIB 5.1.4: DGifSlurp fails on empty comment.");

  script_tag(name:"affected", value:"'giflib' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"giflib", rpm:"giflib~5.1.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-progs", rpm:"giflib-progs~5.1.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gif-devel", rpm:"lib64gif-devel~5.1.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gif7", rpm:"lib64gif7~5.1.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif-devel", rpm:"libgif-devel~5.1.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7", rpm:"libgif7~5.1.6~1.mga6", rls:"MAGEIA6"))) {
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
