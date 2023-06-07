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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0130");
  script_cve_id("CVE-2014-2240", "CVE-2014-2241");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-05-12T12:25:31+0000");
  script_tag(name:"last_modification", value:"2022-05-12 12:25:31 +0000 (Thu, 12 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0130)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0130");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0130.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12986");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1074646");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=741299");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype2' package(s) announced via the MGASA-2014-0130 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that Freetype before 2.5.3 suffers from an out-of-bounds
stack-based read/write flaw in cf2_hintmap_build() in the CFF rasterizing
code, which could lead to a buffer overflow (CVE-2014-2240).

It was also reported that Freetype before 2.5.3 has a denial-of-service
vulnerability in the CFF rasterizing code, due to a reachable assertion
(CVE-2014-2241).");

  script_tag(name:"affected", value:"'freetype2' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.5.0.1~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.5.0.1~3.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-demos", rpm:"freetype2-demos~2.5.0.1~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-demos", rpm:"freetype2-demos~2.5.0.1~3.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6", rpm:"lib64freetype6~2.5.0.1~3.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6", rpm:"lib64freetype6~2.5.0.1~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-devel", rpm:"lib64freetype6-devel~2.5.0.1~3.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-devel", rpm:"lib64freetype6-devel~2.5.0.1~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-static-devel", rpm:"lib64freetype6-static-devel~2.5.0.1~3.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-static-devel", rpm:"lib64freetype6-static-devel~2.5.0.1~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.5.0.1~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.5.0.1~3.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-devel", rpm:"libfreetype6-devel~2.5.0.1~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-devel", rpm:"libfreetype6-devel~2.5.0.1~3.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-static-devel", rpm:"libfreetype6-static-devel~2.5.0.1~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-static-devel", rpm:"libfreetype6-static-devel~2.5.0.1~3.1.mga4.tainted", rls:"MAGEIA4"))) {
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
