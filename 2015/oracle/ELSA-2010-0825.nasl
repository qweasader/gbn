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
  script_oid("1.3.6.1.4.1.25623.1.0.122299");
  script_cve_id("CVE-2010-3677", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3833", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");
  script_tag(name:"creation_date", value:"2015-10-06 11:16:15 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:49:18+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:49:18 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2010-0825)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0825");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0825.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql' package(s) announced via the ELSA-2010-0825 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.0.77-4.4]
- Add fixes for CVE-2010-3677, CVE-2010-3680, CVE-2010-3681, CVE-2010-3682,
 CVE-2010-3833, CVE-2010-3835, CVE-2010-3836, CVE-2010-3837, CVE-2010-3838,
 CVE-2010-3839, CVE-2010-3840
Resolves: #645642
- Backpatch strmov fix so that code can be tested on more recent platforms");

  script_tag(name:"affected", value:"'mysql' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.77~4.el5_5.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.77~4.el5_5.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.77~4.el5_5.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.77~4.el5_5.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.77~4.el5_5.4", rls:"OracleLinux5"))) {
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