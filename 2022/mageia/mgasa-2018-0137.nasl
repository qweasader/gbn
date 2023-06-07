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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0137");
  script_cve_id("CVE-2018-1053");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-05-12T12:25:31+0000");
  script_tag(name:"last_modification", value:"2022-05-12 12:25:31 +0000 (Thu, 12 May 2022)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0137)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0137");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0137.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22556");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.4/static/release-9-4-16.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.6/static/release-9-6-7.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1829/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql9.4, postgresql9.6' package(s) announced via the MGASA-2018-0137 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In postgresql 9.4.x before 9.4.16 and 9.6.x before 9.6.7, pg_upgrade creates
file in current working directory containing the output of `pg_dumpall -g`
under umask which was in effect when the user invoked pg_upgrade, and not
under 0077 which is normally used for other temporary files. This can allow
an authenticated attacker to read or modify the one file, which may contain
encrypted or unencrypted database passwords. The attack is infeasible if a
directory mode blocks the attacker searching the current working directory or
if the prevailing umask blocks the attacker opening the file (CVE-2018-1053).

Note that on Mageia 5, only the postgresql9.4 update is being provided. Users
of the postgresql9.3 package should migrate to 9.4.");

  script_tag(name:"affected", value:"'postgresql9.4, postgresql9.6' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.4_6", rpm:"lib64ecpg9.4_6~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq5", rpm:"lib64pq5~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.4_6", rpm:"libecpg9.4_6~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4", rpm:"postgresql9.4~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-contrib", rpm:"postgresql9.4-contrib~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-devel", rpm:"postgresql9.4-devel~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-docs", rpm:"postgresql9.4-docs~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-pl", rpm:"postgresql9.4-pl~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plperl", rpm:"postgresql9.4-plperl~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plpgsql", rpm:"postgresql9.4-plpgsql~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plpython", rpm:"postgresql9.4-plpython~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-pltcl", rpm:"postgresql9.4-pltcl~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-server", rpm:"postgresql9.4-server~9.4.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.4_6", rpm:"lib64ecpg9.4_6~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.6_6", rpm:"lib64ecpg9.6_6~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq5", rpm:"lib64pq5~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq5.7", rpm:"lib64pq5.7~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.4_6", rpm:"libecpg9.4_6~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.6_6", rpm:"libecpg9.6_6~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5.7", rpm:"libpq5.7~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4", rpm:"postgresql9.4~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-contrib", rpm:"postgresql9.4-contrib~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-devel", rpm:"postgresql9.4-devel~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-docs", rpm:"postgresql9.4-docs~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-pl", rpm:"postgresql9.4-pl~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plperl", rpm:"postgresql9.4-plperl~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plpgsql", rpm:"postgresql9.4-plpgsql~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plpython", rpm:"postgresql9.4-plpython~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-pltcl", rpm:"postgresql9.4-pltcl~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-server", rpm:"postgresql9.4-server~9.4.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6", rpm:"postgresql9.6~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-contrib", rpm:"postgresql9.6-contrib~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-devel", rpm:"postgresql9.6-devel~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-docs", rpm:"postgresql9.6-docs~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-pl", rpm:"postgresql9.6-pl~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-plperl", rpm:"postgresql9.6-plperl~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-plpgsql", rpm:"postgresql9.6-plpgsql~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-plpython", rpm:"postgresql9.6-plpython~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-pltcl", rpm:"postgresql9.6-pltcl~9.6.7~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.6-server", rpm:"postgresql9.6-server~9.6.7~1.mga6", rls:"MAGEIA6"))) {
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
