# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122337");
  script_cve_id("CVE-2010-2498", "CVE-2010-2499", "CVE-2010-2500", "CVE-2010-2519", "CVE-2010-2527", "CVE-2010-2541");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:02 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:49:18+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:49:18 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2010-0578)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux4|OracleLinux5)");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0578");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0578.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype' package(s) announced via the ELSA-2010-0578 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.2.1-25]
- Add freetype-2.2.1-axis-name-overflow.patch
 (Avoid overflow when dealing with names of axes)
- Resolves: #614012

[2.2.1-24]
- Modify freetype-2.2.1-CVE-2010-2519.patch (additional fix)
 (If the type of the POST fragment is 0, the segment is completely ignored)
- Resolves: #614012

[2.2.1-23]
- Add freetype-2.2.1-CVE-2010-2527.patch
 (Use precision for '%s' where appropriate to avoid buffer overflows)
- Resolves: #614012

[2.2.1-22]
- Add freetype-2.2.1-CVE-2010-2498.patch
 (Assure that 'end_point' is not larger than 'glyph->num_points')
- Add freetype-2.2.1-CVE-2010-2499.patch
 (Check the buffer size during gathering PFB fragments)
- Add freetype-2.2.1-CVE-2010-2500.patch
 (Use smaller threshold values for 'width' and 'height')
- Add freetype-2.2.1-CVE-2010-2519.patch
 (Check 'rlen' the length of fragment declared in the POST fragment header)
- Resolves: #614012");

  script_tag(name:"affected", value:"'freetype' package(s) on Oracle Linux 4, Oracle Linux 5.");

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

if(release == "OracleLinux4") {

  if(!isnull(res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.1.9~14.el4.8", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.1.9~14.el4.8", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.1.9~14.el4.8", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-utils", rpm:"freetype-utils~2.1.9~14.el4.8", rls:"OracleLinux4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.2.1~25.el5_5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.2.1~25.el5_5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.2.1~25.el5_5", rls:"OracleLinux5"))) {
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
