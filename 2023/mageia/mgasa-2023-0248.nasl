# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0248");
  script_cve_id("CVE-2023-3823", "CVE-2023-3824");
  script_tag(name:"creation_date", value:"2023-08-24 04:11:47 +0000 (Thu, 24 Aug 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-21 16:31:40 +0000 (Mon, 21 Aug 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0248)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0248");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0248.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32158");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.0.30");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the MGASA-2023-0248 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Libxml - GHSA-3qrf-m4j2-pcrr (Security issue with external entity loading
in XML without enabling it). (CVE-2023-3823)
Phar - GHSA-jqcx-ccgc-xwhv (Buffer mismanagement in phar_dir_read())
(CVE-2023-3824)");

  script_tag(name:"affected", value:"'php' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_php", rpm:"apache-mod_php~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php", rpm:"php~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bz2", rpm:"php-bz2~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-calendar", rpm:"php-calendar~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cgi", rpm:"php-cgi~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ctype", rpm:"php-ctype~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-curl", rpm:"php-curl~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-doc", rpm:"php-doc~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dom", rpm:"php-dom~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-exif", rpm:"php-exif~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fileinfo", rpm:"php-fileinfo~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-filter", rpm:"php-filter~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm-apache", rpm:"php-fpm-apache~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm-nginx", rpm:"php-fpm-nginx~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ftp", rpm:"php-ftp~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gettext", rpm:"php-gettext~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp", rpm:"php-gmp~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-iconv", rpm:"php-iconv~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ini", rpm:"php-ini~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqli", rpm:"php-mysqli~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd", rpm:"php-mysqlnd~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache", rpm:"php-opcache~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-openssl", rpm:"php-openssl~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pcntl", rpm:"php-pcntl~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_dblib", rpm:"php-pdo_dblib~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_firebird", rpm:"php-pdo_firebird~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_mysql", rpm:"php-pdo_mysql~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_odbc", rpm:"php-pdo_odbc~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_pgsql", rpm:"php-pdo_pgsql~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_sqlite", rpm:"php-pdo_sqlite~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-phar", rpm:"php-phar~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-posix", rpm:"php-posix~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-readline", rpm:"php-readline~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-session", rpm:"php-session~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-shmop", rpm:"php-shmop~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sockets", rpm:"php-sockets~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium", rpm:"php-sodium~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sqlite3", rpm:"php-sqlite3~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sysvmsg", rpm:"php-sysvmsg~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sysvsem", rpm:"php-sysvsem~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sysvshm", rpm:"php-sysvshm~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tokenizer", rpm:"php-tokenizer~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xmlreader", rpm:"php-xmlreader~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xmlwriter", rpm:"php-xmlwriter~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xsl", rpm:"php-xsl~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-zip", rpm:"php-zip~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-zlib", rpm:"php-zlib~8.0.30~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"phpdbg", rpm:"phpdbg~8.0.30~1.mga8", rls:"MAGEIA8"))) {
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
