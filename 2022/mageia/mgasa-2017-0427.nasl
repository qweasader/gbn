# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0427");
  script_cve_id("CVE-2017-12618");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-14 22:02:36 +0000 (Tue, 14 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0427)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0427");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0427.html");
  script_xref(name:"URL", value:"http://www.apache.org/dist/apr/Announcement1.x.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22054");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/3Z2STTD6D27UYP6XERSJGSCPYXEZ7KN6/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apr-util' package(s) announced via the MGASA-2017-0427 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apache Portable Runtime Utility (APR-util) 1.6.0 and prior fail to
validate the integrity of SDBM database files used by apr_sdbm*()
functions, resulting in a possible out of bound read access. A local
user with write access to the database can make a program or process
using these functions crash, and cause a denial of service
(CVE-2017-12618).");

  script_tag(name:"affected", value:"'apr-util' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"apr-util", rpm:"apr-util~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-freetds", rpm:"apr-util-dbd-freetds~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-ldap", rpm:"apr-util-dbd-ldap~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-mysql", rpm:"apr-util-dbd-mysql~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-odbc", rpm:"apr-util-dbd-odbc~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-pgsql", rpm:"apr-util-dbd-pgsql~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-sqlite3", rpm:"apr-util-dbd-sqlite3~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbm-db", rpm:"apr-util-dbm-db~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-nss", rpm:"apr-util-nss~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-openssl", rpm:"apr-util-openssl~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apr-util-devel", rpm:"lib64apr-util-devel~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apr-util1_0", rpm:"lib64apr-util1_0~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util-devel", rpm:"libapr-util-devel~1.5.4~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1_0", rpm:"libapr-util1_0~1.5.4~5.mga5", rls:"MAGEIA5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"apr-util", rpm:"apr-util~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-freetds", rpm:"apr-util-dbd-freetds~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-ldap", rpm:"apr-util-dbd-ldap~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-mysql", rpm:"apr-util-dbd-mysql~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-odbc", rpm:"apr-util-dbd-odbc~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-pgsql", rpm:"apr-util-dbd-pgsql~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-sqlite3", rpm:"apr-util-dbd-sqlite3~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbm-db", rpm:"apr-util-dbm-db~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-nss", rpm:"apr-util-nss~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-openssl", rpm:"apr-util-openssl~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apr-util-devel", rpm:"lib64apr-util-devel~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apr-util1_0", rpm:"lib64apr-util1_0~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util-devel", rpm:"libapr-util-devel~1.5.4~8.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1_0", rpm:"libapr-util1_0~1.5.4~8.mga6", rls:"MAGEIA6"))) {
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
