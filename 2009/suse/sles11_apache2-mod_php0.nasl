# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=493122");
  script_oid("1.3.6.1.4.1.25623.1.0.65683");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-11 22:58:51 +0200 (Sun, 11 Oct 2009)");
  script_cve_id("CVE-2009-1271", "CVE-2009-1272");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SLES11: Security update for PHP5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0");
  script_tag(name:"solution", value:"Please install the updates provided by SuSE.");
  script_tag(name:"summary", value:"The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    apache2-mod_php5
    php5
    php5-bcmath
    php5-bz2
    php5-calendar
    php5-ctype
    php5-curl
    php5-dba
    php5-dbase
    php5-dom
    php5-exif
    php5-fastcgi
    php5-ftp
    php5-gd
    php5-gettext
    php5-gmp
    php5-hash
    php5-iconv
    php5-json
    php5-ldap
    php5-mbstring
    php5-mcrypt
    php5-mysql
    php5-odbc
    php5-openssl
    php5-pcntl
    php5-pdo
    php5-pear
    php5-pgsql
    php5-pspell
    php5-shmop
    php5-snmp
    php5-soap
    php5-suhosin
    php5-sysvmsg
    php5-sysvsem
    php5-sysvshm
    php5-tokenizer
    php5-wddx
    php5-xmlreader
    php5-xmlrpc
    php5-xmlwriter
    php5-xsl
    php5-zip
    php5-zlib


More details may also be found by searching for the SuSE
Enterprise Server 11 patch database linked in the references.");

  script_xref(name:"URL", value:"http://download.novell.com/patch/finder/");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5", rpm:"php5~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-hash", rpm:"php5-hash~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-json", rpm:"php5-json~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-suhosin", rpm:"php5-suhosin~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-xmlwriter", rpm:"php5-xmlwriter~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-zip", rpm:"php5-zip~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.2.6~50.19.1", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
