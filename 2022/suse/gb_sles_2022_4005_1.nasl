# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4005.1");
  script_cve_id("CVE-2022-31630", "CVE-2022-37454");
  script_tag(name:"creation_date", value:"2022-11-16 04:24:29 +0000 (Wed, 16 Nov 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-25 15:23:16 +0000 (Tue, 25 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4005-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224005-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php8' package(s) announced via the SUSE-SU-2022:4005-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php8 fixes the following issues:

CVE-2022-37454: Fixed buffer overflow in hash_update() on long parameter
 (bug#81738) (bsc#1204577).

CVE-2022-31630: Fixed OOB read due to insufficient input validation in
 imageloadfont() (bug#81739) (bsc#1204979).

version update to 8.0.25 (27 Oct 2022)
 * Session: Fixed bug GH-9583 (session_create_id() fails with user
 defined save handler that doesn't have a validateId() method).
 * Streams: Fixed bug GH-9590 (stream_select does not abort upon
 exception or empty valid fd set).");

  script_tag(name:"affected", value:"'php8' package(s) on SUSE Linux Enterprise Module for Web Scripting 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php8", rpm:"apache2-mod_php8~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php8-debuginfo", rpm:"apache2-mod_php8-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php8-debugsource", rpm:"apache2-mod_php8-debugsource~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8", rpm:"php8~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-bcmath", rpm:"php8-bcmath~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-bcmath-debuginfo", rpm:"php8-bcmath-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-bz2", rpm:"php8-bz2~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-bz2-debuginfo", rpm:"php8-bz2-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-calendar", rpm:"php8-calendar~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-calendar-debuginfo", rpm:"php8-calendar-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-cli", rpm:"php8-cli~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-cli-debuginfo", rpm:"php8-cli-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-ctype", rpm:"php8-ctype~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-ctype-debuginfo", rpm:"php8-ctype-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-curl", rpm:"php8-curl~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-curl-debuginfo", rpm:"php8-curl-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-dba", rpm:"php8-dba~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-dba-debuginfo", rpm:"php8-dba-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-debuginfo", rpm:"php8-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-debugsource", rpm:"php8-debugsource~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-devel", rpm:"php8-devel~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-dom", rpm:"php8-dom~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-dom-debuginfo", rpm:"php8-dom-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-embed", rpm:"php8-embed~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-embed-debuginfo", rpm:"php8-embed-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-embed-debugsource", rpm:"php8-embed-debugsource~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-enchant", rpm:"php8-enchant~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-enchant-debuginfo", rpm:"php8-enchant-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-exif", rpm:"php8-exif~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-exif-debuginfo", rpm:"php8-exif-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-fastcgi", rpm:"php8-fastcgi~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-fastcgi-debuginfo", rpm:"php8-fastcgi-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-fastcgi-debugsource", rpm:"php8-fastcgi-debugsource~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-fileinfo", rpm:"php8-fileinfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-fileinfo-debuginfo", rpm:"php8-fileinfo-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-fpm", rpm:"php8-fpm~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-fpm-debuginfo", rpm:"php8-fpm-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-fpm-debugsource", rpm:"php8-fpm-debugsource~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-ftp", rpm:"php8-ftp~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-ftp-debuginfo", rpm:"php8-ftp-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-gd", rpm:"php8-gd~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-gd-debuginfo", rpm:"php8-gd-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-gettext", rpm:"php8-gettext~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-gettext-debuginfo", rpm:"php8-gettext-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-gmp", rpm:"php8-gmp~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-gmp-debuginfo", rpm:"php8-gmp-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-iconv", rpm:"php8-iconv~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-iconv-debuginfo", rpm:"php8-iconv-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-intl", rpm:"php8-intl~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-intl-debuginfo", rpm:"php8-intl-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-ldap", rpm:"php8-ldap~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-ldap-debuginfo", rpm:"php8-ldap-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-mbstring", rpm:"php8-mbstring~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-mbstring-debuginfo", rpm:"php8-mbstring-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-mysql", rpm:"php8-mysql~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-mysql-debuginfo", rpm:"php8-mysql-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-odbc", rpm:"php8-odbc~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-odbc-debuginfo", rpm:"php8-odbc-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-opcache", rpm:"php8-opcache~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-opcache-debuginfo", rpm:"php8-opcache-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-openssl", rpm:"php8-openssl~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-openssl-debuginfo", rpm:"php8-openssl-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-pcntl", rpm:"php8-pcntl~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-pcntl-debuginfo", rpm:"php8-pcntl-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-pdo", rpm:"php8-pdo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-pdo-debuginfo", rpm:"php8-pdo-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-pgsql", rpm:"php8-pgsql~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-pgsql-debuginfo", rpm:"php8-pgsql-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-phar", rpm:"php8-phar~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-phar-debuginfo", rpm:"php8-phar-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-posix", rpm:"php8-posix~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-posix-debuginfo", rpm:"php8-posix-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-readline", rpm:"php8-readline~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-readline-debuginfo", rpm:"php8-readline-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-shmop", rpm:"php8-shmop~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-shmop-debuginfo", rpm:"php8-shmop-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-snmp", rpm:"php8-snmp~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-snmp-debuginfo", rpm:"php8-snmp-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-soap", rpm:"php8-soap~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-soap-debuginfo", rpm:"php8-soap-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sockets", rpm:"php8-sockets~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sockets-debuginfo", rpm:"php8-sockets-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sodium", rpm:"php8-sodium~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sodium-debuginfo", rpm:"php8-sodium-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sqlite", rpm:"php8-sqlite~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sqlite-debuginfo", rpm:"php8-sqlite-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sysvmsg", rpm:"php8-sysvmsg~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sysvmsg-debuginfo", rpm:"php8-sysvmsg-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sysvsem", rpm:"php8-sysvsem~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sysvsem-debuginfo", rpm:"php8-sysvsem-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sysvshm", rpm:"php8-sysvshm~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sysvshm-debuginfo", rpm:"php8-sysvshm-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-test", rpm:"php8-test~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-tidy", rpm:"php8-tidy~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-tidy-debuginfo", rpm:"php8-tidy-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-tokenizer", rpm:"php8-tokenizer~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-tokenizer-debuginfo", rpm:"php8-tokenizer-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-xmlreader", rpm:"php8-xmlreader~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-xmlreader-debuginfo", rpm:"php8-xmlreader-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-xmlwriter", rpm:"php8-xmlwriter~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-xmlwriter-debuginfo", rpm:"php8-xmlwriter-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-xsl", rpm:"php8-xsl~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-xsl-debuginfo", rpm:"php8-xsl-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-zip", rpm:"php8-zip~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-zip-debuginfo", rpm:"php8-zip-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-zlib", rpm:"php8-zlib~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-zlib-debuginfo", rpm:"php8-zlib-debuginfo~8.0.25~150400.4.17.1", rls:"SLES15.0SP4"))) {
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
