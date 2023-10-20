# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0040");
  script_cve_id("CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9425", "CVE-2014-9427", "CVE-2014-9620", "CVE-2014-9621", "CVE-2015-0231", "CVE-2015-0232");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0040)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0040");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0040.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15121");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php#5.5.21");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgd, php, php-apc' package(s) announced via the MGASA-2015-0040 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated php and libgd packages fix security vulnerabilities:

Double free vulnerability in the zend_ts_hash_graceful_destroy function in
zend_ts_hash.c in the Zend Engine in PHP before 5.5.21 allows remote
attackers to cause a denial of service or possibly have unspecified other
impact via unknown vectors (CVE-2014-9425).

sapi/cgi/cgi_main.c in the CGI component in PHP before 5.5.21, when mmap is
used to read a .php file, does not properly consider the mapping's length
during processing of an invalid file that begins with a # character and lacks
a newline character, which causes an out-of-bounds read and might allow remote
attackers to obtain sensitive information from php-cgi process memory by
leveraging the ability to upload a .php file or trigger unexpected code
execution if a valid PHP script is present in memory locations adjacent to the
mapping (CVE-2014-9427).

Use after free vulnerability in unserialize() in PHP before 5.5.21
(CVE-2015-0231).

Free called on an uninitialized pointer in php-exif in PHP before 5.5.21
(CVE-2015-0232).

The readelf.c source file has been removed from PHP's bundled copy of file's
libmagic, eliminating exposure to denial of service issues in ELF file parsing
such as CVE-2014-8116, CVE-2014-8117, CVE-2014-9620 and CVE-2014-9621 in PHP's
fileinfo module.

A buffer read overflow in gd_gif_in.c in the php#68601 bug referenced in the
PHP 5.5.21 ChangeLog has been fixed in the libgd package.

The php package has been updated to version 5.5.21 to fix these issues and
other bugs. Please see the upstream ChangeLog for more information.");

  script_tag(name:"affected", value:"'libgd, php, php-apc' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_php", rpm:"apache-mod_php~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.1.0~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gd-devel", rpm:"lib64gd-devel~2.1.0~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gd-static-devel", rpm:"lib64gd-static-devel~2.1.0~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gd3", rpm:"lib64gd3~2.1.0~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64php5_common5", rpm:"lib64php5_common5~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd", rpm:"libgd~2.1.0~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd-devel", rpm:"libgd-devel~2.1.0~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd-static-devel", rpm:"libgd-static-devel~2.1.0~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd3", rpm:"libgd3~2.1.0~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libphp5_common5", rpm:"libphp5_common5~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php", rpm:"php~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-apc", rpm:"php-apc~3.1.15~4.11.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-apc-admin", rpm:"php-apc-admin~3.1.15~4.11.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bz2", rpm:"php-bz2~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-calendar", rpm:"php-calendar~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cgi", rpm:"php-cgi~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ctype", rpm:"php-ctype~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-curl", rpm:"php-curl~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-doc", rpm:"php-doc~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dom", rpm:"php-dom~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-exif", rpm:"php-exif~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fileinfo", rpm:"php-fileinfo~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-filter", rpm:"php-filter~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ftp", rpm:"php-ftp~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gettext", rpm:"php-gettext~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp", rpm:"php-gmp~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-hash", rpm:"php-hash~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-iconv", rpm:"php-iconv~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ini", rpm:"php-ini~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-interbase", rpm:"php-interbase~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-json", rpm:"php-json~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mcrypt", rpm:"php-mcrypt~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mssql", rpm:"php-mssql~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqli", rpm:"php-mysqli~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd", rpm:"php-mysqlnd~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache", rpm:"php-opcache~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-openssl", rpm:"php-openssl~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pcntl", rpm:"php-pcntl~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_dblib", rpm:"php-pdo_dblib~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_firebird", rpm:"php-pdo_firebird~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_mysql", rpm:"php-pdo_mysql~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_odbc", rpm:"php-pdo_odbc~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_pgsql", rpm:"php-pdo_pgsql~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo_sqlite", rpm:"php-pdo_sqlite~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-phar", rpm:"php-phar~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-posix", rpm:"php-posix~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-readline", rpm:"php-readline~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-recode", rpm:"php-recode~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-session", rpm:"php-session~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-shmop", rpm:"php-shmop~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sockets", rpm:"php-sockets~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sqlite3", rpm:"php-sqlite3~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sybase_ct", rpm:"php-sybase_ct~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sysvmsg", rpm:"php-sysvmsg~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sysvsem", rpm:"php-sysvsem~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sysvshm", rpm:"php-sysvshm~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tokenizer", rpm:"php-tokenizer~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-wddx", rpm:"php-wddx~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xmlreader", rpm:"php-xmlreader~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xmlwriter", rpm:"php-xmlwriter~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xsl", rpm:"php-xsl~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-zip", rpm:"php-zip~5.5.21~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-zlib", rpm:"php-zlib~5.5.21~1.mga4", rls:"MAGEIA4"))) {
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
