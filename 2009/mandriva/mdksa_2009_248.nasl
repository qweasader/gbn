# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64960");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
  script_cve_id("CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3293");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:248 (php)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2009\.1");
  script_tag(name:"insight", value:"Multiple vulnerabilities was discovered and corrected in php:

The php_openssl_apply_verification_policy function in PHP before
5.2.11 does not properly perform certificate validation, which has
unknown impact and attack vectors, probably related to an ability to
spoof certificates (CVE-2009-3291).

Unspecified vulnerability in PHP before 5.2.11 has unknown impact
and attack vectors related to missing sanity checks around exif
processing. (CVE-2009-3292)

Unspecified vulnerability in the imagecolortransparent function in
PHP before 5.2.11 has unknown impact and attack vectors related to an
incorrect sanity check for the color index. (CVE-2009-3293). However
in Mandriva we don't use the bundled libgd source in php per default,
there is a unsupported package in contrib named php-gd-bundled that
eventually will get updated to pickup these fixes.

This update provides a solution to these vulnerabilities.

Affected: 2009.1");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:248");
  script_tag(name:"summary", value:"The remote host is missing an update to php
announced via advisory MDVSA-2009:248.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libphp5_common5", rpm:"libphp5_common5~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-bz2", rpm:"php-bz2~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-calendar", rpm:"php-calendar~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cgi", rpm:"php-cgi~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ctype", rpm:"php-ctype~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-curl", rpm:"php-curl~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-dbase", rpm:"php-dbase~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-dom", rpm:"php-dom~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-exif", rpm:"php-exif~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-fcgi", rpm:"php-fcgi~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-filter", rpm:"php-filter~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ftp", rpm:"php-ftp~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-gettext", rpm:"php-gettext~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-gmp", rpm:"php-gmp~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-hash", rpm:"php-hash~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-iconv", rpm:"php-iconv~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-json", rpm:"php-json~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mcrypt", rpm:"php-mcrypt~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mhash", rpm:"php-mhash~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mime_magic", rpm:"php-mime_magic~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ming", rpm:"php-ming~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mssql", rpm:"php-mssql~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mysqli", rpm:"php-mysqli~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ncurses", rpm:"php-ncurses~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-openssl", rpm:"php-openssl~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pcntl", rpm:"php-pcntl~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo_dblib", rpm:"php-pdo_dblib~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo_mysql", rpm:"php-pdo_mysql~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo_odbc", rpm:"php-pdo_odbc~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo_pgsql", rpm:"php-pdo_pgsql~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo_sqlite", rpm:"php-pdo_sqlite~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-posix", rpm:"php-posix~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-readline", rpm:"php-readline~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-recode", rpm:"php-recode~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-session", rpm:"php-session~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-shmop", rpm:"php-shmop~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sockets", rpm:"php-sockets~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sqlite", rpm:"php-sqlite~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sybase", rpm:"php-sybase~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sysvmsg", rpm:"php-sysvmsg~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sysvsem", rpm:"php-sysvsem~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sysvshm", rpm:"php-sysvshm~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-tokenizer", rpm:"php-tokenizer~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-wddx", rpm:"php-wddx~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xmlreader", rpm:"php-xmlreader~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xmlwriter", rpm:"php-xmlwriter~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xsl", rpm:"php-xsl~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-zip", rpm:"php-zip~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-zlib", rpm:"php-zlib~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64php5_common5", rpm:"lib64php5_common5~5.2.9~6.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
