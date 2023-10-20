# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0070");
  script_cve_id("CVE-2021-46659", "CVE-2021-46661", "CVE-2021-46663", "CVE-2021-46664", "CVE-2021-46665", "CVE-2021-46668", "CVE-2022-24048", "CVE-2022-24050", "CVE-2022-24051", "CVE-2022-24052");
  script_tag(name:"creation_date", value:"2022-02-18 03:17:16 +0000 (Fri, 18 Feb 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-28 14:46:00 +0000 (Mon, 28 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0070)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0070");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0070.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30047");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10514-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10515-release-notes/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the MGASA-2022-0070 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"InnoDB
- --skip-symbolic-links does not disallow .isl file creation (MDEV-26870)
- Indexed CHAR columns are broken with NO_PAD collations (MDEV-25440)
- insert-intention lock conflicts with waiting ORDINARY lock (MDEV-27025)
- Crash recovery improvements (MDEV-26784, MDEV-27022, MDEV-27183,
 MDEV-27610)

GaleraP
- Galera updated to 26.4.11
- Galera SST scripts should use ssl_capath (not ssl_ca) for CA directory
 (MDEV-27181)
- Alter Sequence do not replicate to another nodes with in Galera Cluster
 (MDEV-19353)
- Galera crash - Assertion. Possible parallel writeset problem (MDEV-26803)
- CREATE TABLE with FOREIGN KEY constraint fails to apply in parallel
 (MDEV-27276)
- Galera cluster node consider old server_id value even after modification
 of server_id [wsrep_gtid_mode=ON] (MDEV-26223)

Replication
- Seconds behind master corrected from artificial spikes at relay-log
 rotation (MDEV-16091)
- Statement rollback in binlog when transaction creates or drop temporary
 table is set right (MDEV-26833)
- CREATE-or-REPLACE SEQUENCE is made to binlog with the DDL flag to
 stabilize its parallel execution on slave (MDEV-27365)");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-devel", rpm:"lib64mariadb-devel~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb-embedded-devel", rpm:"lib64mariadb-embedded-devel~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadb3", rpm:"lib64mariadb3~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mariadbd19", rpm:"lib64mariadbd19~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-devel", rpm:"libmariadb-devel~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-embedded-devel", rpm:"libmariadb-embedded-devel~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb3", rpm:"libmariadb3~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd19", rpm:"libmariadbd19~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common", rpm:"mariadb-common~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common-core", rpm:"mariadb-common-core~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-connect", rpm:"mariadb-connect~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-core", rpm:"mariadb-core~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-extra", rpm:"mariadb-extra~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-feedback", rpm:"mariadb-feedback~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-mroonga", rpm:"mariadb-mroonga~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-obsolete", rpm:"mariadb-obsolete~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-pam", rpm:"mariadb-pam~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-rocks", rpm:"mariadb-rocks~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-sequence", rpm:"mariadb-sequence~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-sphinx", rpm:"mariadb-sphinx~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-spider", rpm:"mariadb-spider~10.5.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-MariaDB", rpm:"mysql-MariaDB~10.5.15~1.mga8", rls:"MAGEIA8"))) {
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
