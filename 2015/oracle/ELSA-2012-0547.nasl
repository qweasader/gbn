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
  script_oid("1.3.6.1.4.1.25623.1.0.123926");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-1823");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:23 +0000 (Tue, 06 Oct 2015)");
  script_version("2024-07-17T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:48:42 +0000 (Tue, 16 Jul 2024)");

  script_name("Oracle: Security Advisory (ELSA-2012-0547)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0547");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0547.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php53' package(s) announced via the ELSA-2012-0547 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.3.3-7]
- correct detection of = in CVE-2012-1823 fix (#818607)

[5.3.3-6]
- add security fix for CVE-2012-1823 (#818607)");

  script_tag(name:"affected", value:"'php53' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-cli", rpm:"php53-cli~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-common", rpm:"php53-common~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-devel", rpm:"php53-devel~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-imap", rpm:"php53-imap~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-process", rpm:"php53-process~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xml", rpm:"php53-xml~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.3~7.el5_8", rls:"OracleLinux5"))) {
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
