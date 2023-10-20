# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0126.1");
  script_cve_id("CVE-2020-7071");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:45 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-15 15:15:00 +0000 (Thu, 15 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0126-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0126-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210126-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php74' package(s) announced via the SUSE-SU-2021:0126-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php74 fixes the following issue:

CVE-2020-7071: Fixed an insufficient filter in parse_url() that accepted
 URLs with invalid userinfo (bsc#1180706).");

  script_tag(name:"affected", value:"'php74' package(s) on SUSE Linux Enterprise Module for Web Scripting 12, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php74", rpm:"apache2-mod_php74~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php74-debuginfo", rpm:"apache2-mod_php74-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74", rpm:"php74~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-bcmath", rpm:"php74-bcmath~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-bcmath-debuginfo", rpm:"php74-bcmath-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-bz2", rpm:"php74-bz2~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-bz2-debuginfo", rpm:"php74-bz2-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-calendar", rpm:"php74-calendar~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-calendar-debuginfo", rpm:"php74-calendar-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-ctype", rpm:"php74-ctype~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-ctype-debuginfo", rpm:"php74-ctype-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-curl", rpm:"php74-curl~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-curl-debuginfo", rpm:"php74-curl-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-dba", rpm:"php74-dba~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-dba-debuginfo", rpm:"php74-dba-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-debuginfo", rpm:"php74-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-debugsource", rpm:"php74-debugsource~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-dom", rpm:"php74-dom~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-dom-debuginfo", rpm:"php74-dom-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-enchant", rpm:"php74-enchant~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-enchant-debuginfo", rpm:"php74-enchant-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-exif", rpm:"php74-exif~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-exif-debuginfo", rpm:"php74-exif-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-fastcgi", rpm:"php74-fastcgi~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-fastcgi-debuginfo", rpm:"php74-fastcgi-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-fileinfo", rpm:"php74-fileinfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-fileinfo-debuginfo", rpm:"php74-fileinfo-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-fpm", rpm:"php74-fpm~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-fpm-debuginfo", rpm:"php74-fpm-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-ftp", rpm:"php74-ftp~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-ftp-debuginfo", rpm:"php74-ftp-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-gd", rpm:"php74-gd~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-gd-debuginfo", rpm:"php74-gd-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-gettext", rpm:"php74-gettext~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-gettext-debuginfo", rpm:"php74-gettext-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-gmp", rpm:"php74-gmp~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-gmp-debuginfo", rpm:"php74-gmp-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-iconv", rpm:"php74-iconv~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-iconv-debuginfo", rpm:"php74-iconv-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-intl", rpm:"php74-intl~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-intl-debuginfo", rpm:"php74-intl-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-json", rpm:"php74-json~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-json-debuginfo", rpm:"php74-json-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-ldap", rpm:"php74-ldap~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-ldap-debuginfo", rpm:"php74-ldap-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-mbstring", rpm:"php74-mbstring~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-mbstring-debuginfo", rpm:"php74-mbstring-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-mysql", rpm:"php74-mysql~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-mysql-debuginfo", rpm:"php74-mysql-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-odbc", rpm:"php74-odbc~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-odbc-debuginfo", rpm:"php74-odbc-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-opcache", rpm:"php74-opcache~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-opcache-debuginfo", rpm:"php74-opcache-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-openssl", rpm:"php74-openssl~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-openssl-debuginfo", rpm:"php74-openssl-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-pcntl", rpm:"php74-pcntl~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-pcntl-debuginfo", rpm:"php74-pcntl-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-pdo", rpm:"php74-pdo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-pdo-debuginfo", rpm:"php74-pdo-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-pgsql", rpm:"php74-pgsql~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-pgsql-debuginfo", rpm:"php74-pgsql-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-phar", rpm:"php74-phar~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-phar-debuginfo", rpm:"php74-phar-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-posix", rpm:"php74-posix~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-posix-debuginfo", rpm:"php74-posix-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-readline", rpm:"php74-readline~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-readline-debuginfo", rpm:"php74-readline-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-shmop", rpm:"php74-shmop~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-shmop-debuginfo", rpm:"php74-shmop-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-snmp", rpm:"php74-snmp~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-snmp-debuginfo", rpm:"php74-snmp-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-soap", rpm:"php74-soap~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-soap-debuginfo", rpm:"php74-soap-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sockets", rpm:"php74-sockets~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sockets-debuginfo", rpm:"php74-sockets-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sodium", rpm:"php74-sodium~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sodium-debuginfo", rpm:"php74-sodium-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sqlite", rpm:"php74-sqlite~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sqlite-debuginfo", rpm:"php74-sqlite-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sysvmsg", rpm:"php74-sysvmsg~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sysvmsg-debuginfo", rpm:"php74-sysvmsg-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sysvsem", rpm:"php74-sysvsem~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sysvsem-debuginfo", rpm:"php74-sysvsem-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sysvshm", rpm:"php74-sysvshm~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-sysvshm-debuginfo", rpm:"php74-sysvshm-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-tidy", rpm:"php74-tidy~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-tidy-debuginfo", rpm:"php74-tidy-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-tokenizer", rpm:"php74-tokenizer~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-tokenizer-debuginfo", rpm:"php74-tokenizer-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-xmlreader", rpm:"php74-xmlreader~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-xmlreader-debuginfo", rpm:"php74-xmlreader-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-xmlrpc", rpm:"php74-xmlrpc~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-xmlrpc-debuginfo", rpm:"php74-xmlrpc-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-xmlwriter", rpm:"php74-xmlwriter~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-xmlwriter-debuginfo", rpm:"php74-xmlwriter-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-xsl", rpm:"php74-xsl~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-xsl-debuginfo", rpm:"php74-xsl-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-zip", rpm:"php74-zip~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-zip-debuginfo", rpm:"php74-zip-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-zlib", rpm:"php74-zlib~7.4.6~1.16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php74-zlib-debuginfo", rpm:"php74-zlib-debuginfo~7.4.6~1.16.1", rls:"SLES12.0"))) {
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
