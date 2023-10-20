# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0424");
  script_cve_id("CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6491", "CVE-2014-6494", "CVE-2014-6496", "CVE-2014-6500", "CVE-2014-6507", "CVE-2014-6555", "CVE-2014-6559");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0424)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0424");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0424.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14304");
  script_xref(name:"URL", value:"https://blog.mariadb.org/mariadb-5-5-40-now-available/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/development/release-notes/mariadb-5540-release-notes/");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2384-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the MGASA-2014-0424 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides MariaDB 5.5.40, which fixes several security issues
and other bugs.");

  script_tag(name:"affected", value:"'mariadb' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-devel", rpm:"lib64mariadb-devel~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-embedded-devel", rpm:"lib64mariadb-embedded-devel~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-embedded18", rpm:"lib64mariadb-embedded18~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb18", rpm:"lib64mariadb18~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-devel", rpm:"libmariadb-devel~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-embedded-devel", rpm:"libmariadb-embedded-devel~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-embedded18", rpm:"libmariadb-embedded18~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb18", rpm:"libmariadb18~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common", rpm:"mariadb-common~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common-core", rpm:"mariadb-common-core~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-core", rpm:"mariadb-core~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-extra", rpm:"mariadb-extra~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-feedback", rpm:"mariadb-feedback~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-obsolete", rpm:"mariadb-obsolete~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-MariaDB", rpm:"mysql-MariaDB~5.5.40~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-devel", rpm:"lib64mariadb-devel~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-embedded-devel", rpm:"lib64mariadb-embedded-devel~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-embedded18", rpm:"lib64mariadb-embedded18~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb18", rpm:"lib64mariadb18~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-devel", rpm:"libmariadb-devel~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-embedded-devel", rpm:"libmariadb-embedded-devel~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-embedded18", rpm:"libmariadb-embedded18~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb18", rpm:"libmariadb18~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common", rpm:"mariadb-common~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common-core", rpm:"mariadb-common-core~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-core", rpm:"mariadb-core~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-extra", rpm:"mariadb-extra~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-feedback", rpm:"mariadb-feedback~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-obsolete", rpm:"mariadb-obsolete~5.5.40~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-MariaDB", rpm:"mysql-MariaDB~5.5.40~1.mga4", rls:"MAGEIA4"))) {
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
