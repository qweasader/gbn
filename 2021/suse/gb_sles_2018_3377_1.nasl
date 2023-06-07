# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3377.1");
  script_cve_id("CVE-2018-10915", "CVE-2018-10925");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-02-28T10:20:42+0000");
  script_tag(name:"last_modification", value:"2023-02-28 10:20:42 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:38:00 +0000 (Fri, 24 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3377-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3377-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183377-1/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-6-10.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql96' package(s) announced via the SUSE-SU-2018:3377-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql96 to 9.6.10 fixes the following issues:

These security issues were fixed:
CVE-2018-10915: libpq failed to properly reset its internal state
 between connections. If an affected version of libpq was used with
 'host' or 'hostaddr' connection parameters from untrusted input,
 attackers could have bypassed client-side connection security features,
 obtain access to higher privileged connections or potentially cause
 other impact SQL injection, by causing the PQescape() functions to
 malfunction (bsc#1104199)

CVE-2018-10925: Add missing authorization check on certain statements
 involved with 'INSERT ... ON CONFLICT DO UPDATE'. An attacker with
 'CREATE TABLE' privileges could have exploited this to read arbitrary
 bytes server memory. If the attacker also had certain 'INSERT' and
 limited 'UPDATE' privileges to a particular table, they could have
 exploited this to update
 other columns in the same table (bsc#1104202)

For addition details please see [link moved to references]");

  script_tag(name:"affected", value:"'postgresql96' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE OpenStack Cloud 7.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib-debuginfo", rpm:"postgresql96-contrib-debuginfo~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debuginfo", rpm:"postgresql96-debuginfo~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debugsource", rpm:"postgresql96-debugsource~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-libs-debugsource", rpm:"postgresql96-libs-debugsource~9.6.10~3.22.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server-debuginfo", rpm:"postgresql96-server-debuginfo~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib-debuginfo", rpm:"postgresql96-contrib-debuginfo~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debuginfo", rpm:"postgresql96-debuginfo~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debugsource", rpm:"postgresql96-debugsource~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-libs-debugsource", rpm:"postgresql96-libs-debugsource~9.6.10~3.22.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server-debuginfo", rpm:"postgresql96-server-debuginfo~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib-debuginfo", rpm:"postgresql96-contrib-debuginfo~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debuginfo", rpm:"postgresql96-debuginfo~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debugsource", rpm:"postgresql96-debugsource~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-libs-debugsource", rpm:"postgresql96-libs-debugsource~9.6.10~3.22.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server-debuginfo", rpm:"postgresql96-server-debuginfo~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib-debuginfo", rpm:"postgresql96-contrib-debuginfo~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debuginfo", rpm:"postgresql96-debuginfo~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debugsource", rpm:"postgresql96-debugsource~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-libs-debugsource", rpm:"postgresql96-libs-debugsource~9.6.10~3.22.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server-debuginfo", rpm:"postgresql96-server-debuginfo~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
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
