# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0045");
  script_cve_id("CVE-2022-25147");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-17 19:42:00 +0000 (Wed, 17 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0045)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0045");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0045.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31486");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/01/31/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apr-util' package(s) announced via the MGASA-2023-0045 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Integer Overflow or Wraparound vulnerability in apr_base64 functions of
Apache Portable Runtime Utility (APR-util) allows an attacker to write
beyond bounds of a buffer. (CVE-2022-25147)");

  script_tag(name:"affected", value:"'apr-util' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"apr-util", rpm:"apr-util~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-ldap", rpm:"apr-util-dbd-ldap~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-mysql", rpm:"apr-util-dbd-mysql~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-odbc", rpm:"apr-util-dbd-odbc~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-pgsql", rpm:"apr-util-dbd-pgsql~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbd-sqlite3", rpm:"apr-util-dbd-sqlite3~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-dbm-db", rpm:"apr-util-dbm-db~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-nss", rpm:"apr-util-nss~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-openssl", rpm:"apr-util-openssl~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apr-util-devel", rpm:"lib64apr-util-devel~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apr-util1_0", rpm:"lib64apr-util1_0~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util-devel", rpm:"libapr-util-devel~1.6.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1_0", rpm:"libapr-util1_0~1.6.3~1.mga8", rls:"MAGEIA8"))) {
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
