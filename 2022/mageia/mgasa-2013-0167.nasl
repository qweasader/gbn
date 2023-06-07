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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0167");
  script_cve_id("CVE-2013-2126");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-05-12T12:25:31+0000");
  script_tag(name:"last_modification", value:"2022-05-12 12:25:31 +0000 (Thu, 12 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0167)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0167");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0167.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53547/");
  script_xref(name:"URL", value:"http://www.libraw.org/news/libraw-0-15-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libraw' package(s) announced via the MGASA-2013-0167 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A double-free error exits when handling damaged full-color within Foveon and
sRAW files in libraw before 0.15.2 (CVE-2013-2126).");

  script_tag(name:"affected", value:"'libraw' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"lib64raw-devel", rpm:"lib64raw-devel~0.14.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64raw5", rpm:"lib64raw5~0.14.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64raw_r5", rpm:"lib64raw_r5~0.14.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw", rpm:"libraw~0.14.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-devel", rpm:"libraw-devel~0.14.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-tools", rpm:"libraw-tools~0.14.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw5", rpm:"libraw5~0.14.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw_r5", rpm:"libraw_r5~0.14.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64raw-devel", rpm:"lib64raw-devel~0.14.7~5.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64raw5", rpm:"lib64raw5~0.14.7~5.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64raw_r5", rpm:"lib64raw_r5~0.14.7~5.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw", rpm:"libraw~0.14.7~5.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-devel", rpm:"libraw-devel~0.14.7~5.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-tools", rpm:"libraw-tools~0.14.7~5.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw5", rpm:"libraw5~0.14.7~5.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw_r5", rpm:"libraw_r5~0.14.7~5.1.mga3", rls:"MAGEIA3"))) {
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
