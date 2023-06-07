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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0281");
  script_cve_id("CVE-2019-8644", "CVE-2019-8649", "CVE-2019-8658", "CVE-2019-8666", "CVE-2019-8669", "CVE-2019-8671", "CVE-2019-8672", "CVE-2019-8673", "CVE-2019-8676", "CVE-2019-8677", "CVE-2019-8678", "CVE-2019-8679", "CVE-2019-8680", "CVE-2019-8681", "CVE-2019-8683", "CVE-2019-8684", "CVE-2019-8686", "CVE-2019-8687", "CVE-2019-8688", "CVE-2019-8689", "CVE-2019-8690");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-18 13:11:00 +0000 (Tue, 18 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2019-0281)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0281");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0281.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25377");
  script_xref(name:"URL", value:"https://webkitgtk.org/security/WSA-2019-0004.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2019/07/02/webkitgtk2.24.3-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2019/08/28/webkitgtk2.24.4-released.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2' package(s) announced via the MGASA-2019-0281 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated webkit2 packages fix security vulnerabilities:

Processing maliciously crafted web content may lead to arbitrary code
execution. Multiple memory corruption issues were addressed with
improved memory handling (CVE-2019-8644).

Processing maliciously crafted web content may lead to universal cross
site scripting. A logic issue existed in the handling of synchronous
page loads. This issue was addressed with improved state management
(CVE-2019-8649).

Processing maliciously crafted web content may lead to universal cross
site scripting. A logic issue was addressed with improved state management
(CVE-2019-8658).

Processing maliciously crafted web content may lead to arbitrary code
execution. Multiple memory corruption issues were addressed with improved
memory handling (CVE-2019-8666, CVE-2019-8669, CVE-2019-8671, CVE-2019-8672,
CVE-2019-8673, CVE-2019-8676, CVE-2019-8677, CVE-2019-8678, CVE-2019-8679,
CVE-2019-8680, CVE-2019-8681, CVE-2019-8683, CVE-2019-8684, CVE-2019-8686,
CVE-2019-8687, CVE-2019-8688, CVE-2019-8689).

Processing maliciously crafted web content may lead to universal cross
site scripting. A logic issue existed in the handling of document loads.
This issue was addressed with improved state management (CVE-2019-8690).

For other fixes in this update, see the referenced release links.");

  script_tag(name:"affected", value:"'webkit2' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir4.0", rpm:"lib64javascriptcore-gir4.0~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk4.0_18", rpm:"lib64javascriptcoregtk4.0_18~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2-devel", rpm:"lib64webkit2-devel~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk-gir4.0", rpm:"lib64webkit2gtk-gir4.0~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.0_37", rpm:"lib64webkit2gtk4.0_37~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir4.0", rpm:"libjavascriptcore-gir4.0~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk4.0_18", rpm:"libjavascriptcoregtk4.0_18~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2-devel", rpm:"libwebkit2-devel~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-gir4.0", rpm:"libwebkit2gtk-gir4.0~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.0_37", rpm:"libwebkit2gtk4.0_37~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2", rpm:"webkit2~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2-jsc", rpm:"webkit2-jsc~2.24.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2-plugin-process-gtk2", rpm:"webkit2-plugin-process-gtk2~2.24.4~1.mga7", rls:"MAGEIA7"))) {
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
