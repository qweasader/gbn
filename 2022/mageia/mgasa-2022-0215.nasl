# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0215");
  script_cve_id("CVE-2022-27376", "CVE-2022-27377", "CVE-2022-27378", "CVE-2022-27379", "CVE-2022-27380", "CVE-2022-27381", "CVE-2022-27382", "CVE-2022-27383", "CVE-2022-27384", "CVE-2022-27386", "CVE-2022-27387", "CVE-2022-27444", "CVE-2022-27445", "CVE-2022-27446", "CVE-2022-27447", "CVE-2022-27448", "CVE-2022-27449");
  script_tag(name:"creation_date", value:"2022-06-06 04:33:17 +0000 (Mon, 06 Jun 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-21 16:33:00 +0000 (Thu, 21 Apr 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0215)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0215");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0215.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30460");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10516-release-notes/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the MGASA-2022-0215 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Some security vulenarbilities have been fixed. Some bigger bugs in
optimizer and replication engine have been found and fixed. See
release notes for details.");

  script_tag(name:"affected", value:"'mariadb' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-devel", rpm:"lib64mariadb-devel~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-embedded-devel", rpm:"lib64mariadb-embedded-devel~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb3", rpm:"lib64mariadb3~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadbd19", rpm:"lib64mariadbd19~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-devel", rpm:"libmariadb-devel~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-embedded-devel", rpm:"libmariadb-embedded-devel~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb3", rpm:"libmariadb3~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd19", rpm:"libmariadbd19~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common", rpm:"mariadb-common~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common-core", rpm:"mariadb-common-core~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-connect", rpm:"mariadb-connect~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-core", rpm:"mariadb-core~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-extra", rpm:"mariadb-extra~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-feedback", rpm:"mariadb-feedback~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-mroonga", rpm:"mariadb-mroonga~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-obsolete", rpm:"mariadb-obsolete~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-pam", rpm:"mariadb-pam~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-rocks", rpm:"mariadb-rocks~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-sequence", rpm:"mariadb-sequence~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-sphinx", rpm:"mariadb-sphinx~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-spider", rpm:"mariadb-spider~10.5.16~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-MariaDB", rpm:"mysql-MariaDB~10.5.16~1.mga8", rls:"MAGEIA8"))) {
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
