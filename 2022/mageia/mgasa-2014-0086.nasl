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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0086");
  script_cve_id("CVE-2013-6836");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0086)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0086");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0086.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12294");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1044857");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-chemistry-utils, gnumeric, goffice' package(s) announced via the MGASA-2014-0086 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heap-based buffer overflow in the ms_escher_get_data function in
plugins/excel/ms-escher.c in GNOME Office Gnumeric before 1.12.9
allows remote attackers to cause a denial of service (crash) via
a crafted xls file with a crafted length value. (CVE-2013-6836)");

  script_tag(name:"affected", value:"'gnome-chemistry-utils, gnumeric, goffice' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"gchem3d", rpm:"gchem3d~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gchemcalc", rpm:"gchemcalc~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gchempaint", rpm:"gchempaint~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gchemtable", rpm:"gchemtable~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcrystal", rpm:"gcrystal~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-chemistry-utils", rpm:"gnome-chemistry-utils~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-chemistry-utils-common", rpm:"gnome-chemistry-utils-common~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-chemistry-utils-devel", rpm:"gnome-chemistry-utils-devel~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-chemistry-utils-gnumeric", rpm:"gnome-chemistry-utils-gnumeric~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-chemistry-utils-goffice", rpm:"gnome-chemistry-utils-goffice~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnumeric", rpm:"gnumeric~1.12.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"goffice", rpm:"goffice~0.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gspectrum", rpm:"gspectrum~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gchempaint0.14_0", rpm:"lib64gchempaint0.14_0~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gcrystal0.14_0", rpm:"lib64gcrystal0.14_0~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gcu0.14_0", rpm:"lib64gcu0.14_0~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64goffice0.10-devel", rpm:"lib64goffice0.10-devel~0.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64goffice0.10_10", rpm:"lib64goffice0.10_10~0.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spreadsheet-devel", rpm:"lib64spreadsheet-devel~1.12.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spreadsheet1.12.9", rpm:"lib64spreadsheet1.12.9~1.12.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgchempaint0.14_0", rpm:"libgchempaint0.14_0~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrystal0.14_0", rpm:"libgcrystal0.14_0~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcu0.14_0", rpm:"libgcu0.14_0~0.14.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgoffice0.10-devel", rpm:"libgoffice0.10-devel~0.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgoffice0.10_10", rpm:"libgoffice0.10_10~0.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspreadsheet-devel", rpm:"libspreadsheet-devel~1.12.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspreadsheet1.12.9", rpm:"libspreadsheet1.12.9~1.12.9~1.mga3", rls:"MAGEIA3"))) {
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
