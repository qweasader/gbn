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
  script_oid("1.3.6.1.4.1.25623.1.0.122283");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-4345");
  script_tag(name:"creation_date", value:"2015-10-06 11:15:57 +0000 (Tue, 06 Oct 2015)");
  script_version("2024-07-17T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:57:37 +0000 (Tue, 16 Jul 2024)");

  script_name("Oracle: Security Advisory (ELSA-2011-0153)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux4|OracleLinux5)");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0153");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0153.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exim' package(s) announced via the ELSA-2011-0153 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[4.63-5.el5_6.2]
- fix privilege escalation (CVE-2010-4345, #662012)");

  script_tag(name:"affected", value:"'exim' package(s) on Oracle Linux 4, Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"exim", rpm:"exim~4.43~1.RHEL4.5.el4_8.3", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exim-doc", rpm:"exim-doc~4.43~1.RHEL4.5.el4_8.3", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exim-mon", rpm:"exim-mon~4.43~1.RHEL4.5.el4_8.3", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exim-sa", rpm:"exim-sa~4.43~1.RHEL4.5.el4_8.3", rls:"OracleLinux4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"exim", rpm:"exim~4.63~5.el5_6.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exim-mon", rpm:"exim-mon~4.63~5.el5_6.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exim-sa", rpm:"exim-sa~4.63~5.el5_6.2", rls:"OracleLinux5"))) {
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
