# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66320");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-03 22:10:42 +0100 (Thu, 03 Dec 2009)");
  script_cve_id("CVE-2009-3557", "CVE-2009-3558", "CVE-2009-4017", "CVE-2009-4018");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandriva Security Advisory MDVSA-2009:303 (php)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2009\.1");
  script_tag(name:"insight", value:"Some vulnerabilities were discovered and corrected in php-5.2.11:

The tempnam function in ext/standard/file.c in PHP 5.2.11 and
earlier, and 5.3.x before 5.3.1, allows context-dependent attackers
to bypass safe_mode restrictions, and create files in group-writable
or world-writable directories, via the dir and prefix arguments
(CVE-2009-3557).

The posix_mkfifo function in ext/posix/posix.c in PHP 5.2.11 and
earlier, and 5.3.x before 5.3.1, allows context-dependent attackers
to bypass open_basedir restrictions, and create FIFO files, via the
pathname and mode arguments, as demonstrated by creating a .htaccess
file (CVE-2009-3558).

PHP 5.2.11, and 5.3.x before 5.3.1, does not restrict the number
of temporary files created when handling a multipart/form-data POST
request, which allows remote attackers to cause a denial of service
(resource exhaustion), and makes it easier for remote attackers to
exploit local file inclusion vulnerabilities, via multiple requests,
related to lack of support for the max_file_uploads directive
(CVE-2009-4017).

The proc_open function in ext/standard/proc_open.c in PHP
before 5.2.11 and 5.3.x before 5.3.1 does not enforce the (1)
safe_mode_allowed_env_vars and (2) safe_mode_protected_env_vars
directives, which allows context-dependent attackers to execute
programs with an arbitrary environment via the env parameter, as
demonstrated by a crafted value of the LD_LIBRARY_PATH environment
variable (CVE-2009-4018).

Intermittent segfaults occurred on x86_64 with the latest phpmyadmin
and with apache (#53735).

Additionally, some packages which require so, have been rebuilt and
are being provided as updates.

Affected: 2009.1");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:303");
  script_tag(name:"summary", value:"The remote host is missing an update to php
announced via advisory MDVSA-2009:303.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"apache-mod_php", rpm:"apache-mod_php~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libphp5_common5", rpm:"libphp5_common5~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-apc", rpm:"php-apc~3.1.3p1~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-apc-admin", rpm:"php-apc-admin~3.1.3p1~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-bz2", rpm:"php-bz2~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-calendar", rpm:"php-calendar~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cgi", rpm:"php-cgi~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ctype", rpm:"php-ctype~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-curl", rpm:"php-curl~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-dbase", rpm:"php-dbase~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-dbx", rpm:"php-dbx~1.1.0~26.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-dio", rpm:"php-dio~0.0.2~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-dom", rpm:"php-dom~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-eaccelerator", rpm:"php-eaccelerator~0.9.5.3~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-eaccelerator-admin", rpm:"php-eaccelerator-admin~0.9.5.3~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-exif", rpm:"php-exif~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-fam", rpm:"php-fam~5.0.1~7.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-fcgi", rpm:"php-fcgi~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-fileinfo", rpm:"php-fileinfo~1.0.4~15.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-filepro", rpm:"php-filepro~5.1.6~17.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-filter", rpm:"php-filter~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ftp", rpm:"php-ftp~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-gettext", rpm:"php-gettext~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-gmp", rpm:"php-gmp~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-hash", rpm:"php-hash~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-iconv", rpm:"php-iconv~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-idn", rpm:"php-idn~1.2b~15.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ini", rpm:"php-ini~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-json", rpm:"php-json~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mcal", rpm:"php-mcal~0.6~27.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mcrypt", rpm:"php-mcrypt~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mhash", rpm:"php-mhash~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mime_magic", rpm:"php-mime_magic~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ming", rpm:"php-ming~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mssql", rpm:"php-mssql~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mysqli", rpm:"php-mysqli~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ncurses", rpm:"php-ncurses~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-openssl", rpm:"php-openssl~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-optimizer", rpm:"php-optimizer~0.1~0.alpha1.5.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pcntl", rpm:"php-pcntl~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo_dblib", rpm:"php-pdo_dblib~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo_mysql", rpm:"php-pdo_mysql~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo_odbc", rpm:"php-pdo_odbc~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo_pgsql", rpm:"php-pdo_pgsql~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pdo_sqlite", rpm:"php-pdo_sqlite~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-posix", rpm:"php-posix~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-readline", rpm:"php-readline~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-recode", rpm:"php-recode~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sasl", rpm:"php-sasl~0.1.0~25.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-session", rpm:"php-session~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-shmop", rpm:"php-shmop~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sockets", rpm:"php-sockets~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sqlite", rpm:"php-sqlite~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ssh2", rpm:"php-ssh2~0.11.0~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-suhosin", rpm:"php-suhosin~0.9.29~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sybase", rpm:"php-sybase~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sysvmsg", rpm:"php-sysvmsg~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sysvsem", rpm:"php-sysvsem~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-sysvshm", rpm:"php-sysvshm~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-tclink", rpm:"php-tclink~3.4.4~10.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-tokenizer", rpm:"php-tokenizer~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-translit", rpm:"php-translit~0.6.0~7.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-vld", rpm:"php-vld~0.9.1~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-wddx", rpm:"php-wddx~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xattr", rpm:"php-xattr~1.1.0~6.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xdebug", rpm:"php-xdebug~2.0.5~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xmlreader", rpm:"php-xmlreader~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xmlwriter", rpm:"php-xmlwriter~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-xsl", rpm:"php-xsl~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-zip", rpm:"php-zip~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-zlib", rpm:"php-zlib~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64php5_common5", rpm:"lib64php5_common5~5.2.11~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
