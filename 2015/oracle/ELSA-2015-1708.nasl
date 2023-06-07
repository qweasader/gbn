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
  script_oid("1.3.6.1.4.1.25623.1.0.123011");
  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");
  script_tag(name:"creation_date", value:"2015-10-06 06:46:37 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T07:26:47+0000");
  script_tag(name:"last_modification", value:"2022-04-05 07:26:47 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-1708)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1708");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1708.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libXfont' package(s) announced via the ELSA-2015-1708 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.4.5-5]
- CVE-2015-1802: missing range check in bdfReadProperties (bug 1258892)
- CVE-2015-1803: crash on invalid read in bdfReadCharacters (bug 1258892)
- CVE-2015-1804: out-of-bounds memory access in bdfReadCharacters (bug 1258892)");

  script_tag(name:"affected", value:"'libXfont' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.4.5~5.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXfont-devel", rpm:"libXfont-devel~1.4.5~5.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.4.7~3.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXfont-devel", rpm:"libXfont-devel~1.4.7~3.el7_1", rls:"OracleLinux7"))) {
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