# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0469");
  script_cve_id("CVE-2016-9843", "CVE-2018-3143", "CVE-2018-3156", "CVE-2018-3174", "CVE-2018-3251", "CVE-2018-3282");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-01 16:47:18 +0000 (Thu, 01 Jun 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0469)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0469");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0469.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23867");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the MGASA-2018-0469 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Some easily exploitable vulnerabilities allowing high privileged
attacker with network access via multiple protocols to compromise
MySQL Server have been fixed.");

  script_tag(name:"affected", value:"'mariadb' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-devel", rpm:"lib64mariadb-devel~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-embedded-devel", rpm:"lib64mariadb-embedded-devel~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-embedded18", rpm:"lib64mariadb-embedded18~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb18", rpm:"lib64mariadb18~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-devel", rpm:"libmariadb-devel~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-embedded-devel", rpm:"libmariadb-embedded-devel~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-embedded18", rpm:"libmariadb-embedded18~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb18", rpm:"libmariadb18~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-cassandra", rpm:"mariadb-cassandra~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common", rpm:"mariadb-common~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common-core", rpm:"mariadb-common-core~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-connect", rpm:"mariadb-connect~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-core", rpm:"mariadb-core~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-extra", rpm:"mariadb-extra~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-feedback", rpm:"mariadb-feedback~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-mroonga", rpm:"mariadb-mroonga~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-obsolete", rpm:"mariadb-obsolete~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-sequence", rpm:"mariadb-sequence~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-sphinx", rpm:"mariadb-sphinx~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-spider", rpm:"mariadb-spider~10.1.37~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-MariaDB", rpm:"mysql-MariaDB~10.1.37~1.mga6", rls:"MAGEIA6"))) {
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
