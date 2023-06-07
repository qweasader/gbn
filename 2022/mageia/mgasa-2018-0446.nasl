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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0446");
  script_cve_id("CVE-2018-1058", "CVE-2018-10915", "CVE-2018-10925", "CVE-2018-1115");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 20:11:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Mageia: Security Advisory (MGASA-2018-0446)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0446");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0446.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22687");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.4/static/release-9-4-17.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.4/static/release-9-4-18.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.4/static/release-9-4-19.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.6/static/release-9-6-8.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.6/static/release-9-6-9.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.6/static/release-9-6-10.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1834/");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1851/");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1878/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4269");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql9.4, postgresql9.6' package(s) announced via the MGASA-2018-0446 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way Postgresql allowed a user to modify the
behavior of a query for other users. An attacker with a user account
could use this flaw to execute code with the permissions of superuser in
the database (CVE-2018-1058).

Postgresql 9.6.x before 9.6.9 is vulnerable in the adminpack extension,
the pg_catalog.pg_logfile_rotate() function doesn't follow the same ACLs
than pg_rorate_logfile. If the adminpack is added to a database, an
attacker able to connect to it could exploit this to force log rotation
(CVE-2018-1115).

Andrew Krasichkov discovered that libpq did not reset all its connection
state during reconnects (CVE-2018-10915).

It was discovered that some 'CREATE TABLE' statements could disclose
server memory (CVE-2018-10925).

Fully fixing these security issues requires manual intervention. See
the upstream advisories for details.");

  script_tag(name:"affected", value:"'postgresql9.4, postgresql9.6' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.4_6", rpm:"lib64ecpg9.4_6~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.6_6", rpm:"lib64ecpg9.6_6~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq5", rpm:"lib64pq5~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq5.7", rpm:"lib64pq5.7~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.4_6", rpm:"libecpg9.4_6~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.6_6", rpm:"libecpg9.6_6~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5.7", rpm:"libpq5.7~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4", rpm:"postgresql9.4~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-contrib", rpm:"postgresql9.4-contrib~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-devel", rpm:"postgresql9.4-devel~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-docs", rpm:"postgresql9.4-docs~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-pl", rpm:"postgresql9.4-pl~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plperl", rpm:"postgresql9.4-plperl~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plpgsql", rpm:"postgresql9.4-plpgsql~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plpython", rpm:"postgresql9.4-plpython~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-pltcl", rpm:"postgresql9.4-pltcl~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-server", rpm:"postgresql9.4-server~9.4.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6", rpm:"postgresql9.6~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-contrib", rpm:"postgresql9.6-contrib~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-devel", rpm:"postgresql9.6-devel~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-docs", rpm:"postgresql9.6-docs~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-pl", rpm:"postgresql9.6-pl~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-plperl", rpm:"postgresql9.6-plperl~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-plpgsql", rpm:"postgresql9.6-plpgsql~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-plpython", rpm:"postgresql9.6-plpython~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-pltcl", rpm:"postgresql9.6-pltcl~9.6.10~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-server", rpm:"postgresql9.6-server~9.6.10~3.mga6", rls:"MAGEIA6"))) {
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
