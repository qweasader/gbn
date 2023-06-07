# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852447");
  script_version("2021-09-07T09:01:33+0000");
  script_cve_id("CVE-2018-20783", "CVE-2019-9020", "CVE-2019-9021", "CVE-2019-9023",
                "CVE-2019-9024", "CVE-2019-9641");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-18 18:15:00 +0000 (Tue, 18 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-04-24 02:01:24 +0000 (Wed, 24 Apr 2019)");
  script_name("openSUSE: Security Advisory for php5 (openSUSE-SU-2019:1256-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"openSUSE-SU", value:"2019:1256-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00083.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5'
  package(s) announced via the openSUSE-SU-2019:1256-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php5 fixes the following issues:

  Security issues fixed:

  - CVE-2019-9024: Fixed a vulnerability in xmlrpc_decode function which
  could allow to a hostile XMLRPC server to cause memory read outside the
  allocated areas (bsc#1126821).

  - CVE-2019-9020: Fixed a heap out of bounds in xmlrpc_decode function
  (bsc#1126711).

  - CVE-2018-20783: Fixed a buffer over-read in PHAR reading functions which
  could allow an attacker to read allocated and unallocated memory when
  parsing a phar file (bsc#1127122).

  - CVE-2019-9021: Fixed a heap buffer-based buffer over-read in PHAR
  reading functions which could allow an attacker to read allocated and
  unallocated memory when parsing a phar file (bsc#1126713).

  - CVE-2019-9023: Fixed multiple heap-based buffer over-read instances in
  mbstring regular expression functions (bsc#1126823).

  - CVE-2019-9641: Fixed multiple invalid memory access in EXIF extension
  and improved insecure implementation
  of rename function (bsc#1128722).

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1256=1");

  script_tag(name:"affected", value:"'php5' package(s) on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php5-debuginfo", rpm:"apache2-mod_php5-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5", rpm:"php5~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-bcmath-debuginfo", rpm:"php5-bcmath-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-bz2-debuginfo", rpm:"php5-bz2-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-calendar-debuginfo", rpm:"php5-calendar-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ctype-debuginfo", rpm:"php5-ctype-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-curl-debuginfo", rpm:"php5-curl-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-dba-debuginfo", rpm:"php5-dba-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-debuginfo", rpm:"php5-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-debugsource", rpm:"php5-debugsource~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-devel", rpm:"php5-devel~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-dom-debuginfo", rpm:"php5-dom-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-enchant", rpm:"php5-enchant~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-enchant-debuginfo", rpm:"php5-enchant-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-exif-debuginfo", rpm:"php5-exif-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fastcgi-debuginfo", rpm:"php5-fastcgi-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fileinfo", rpm:"php5-fileinfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fileinfo-debuginfo", rpm:"php5-fileinfo-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-firebird", rpm:"php5-firebird~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-firebird-debuginfo", rpm:"php5-firebird-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fpm", rpm:"php5-fpm~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fpm-debuginfo", rpm:"php5-fpm-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ftp-debuginfo", rpm:"php5-ftp-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gd-debuginfo", rpm:"php5-gd-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gettext-debuginfo", rpm:"php5-gettext-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gmp-debuginfo", rpm:"php5-gmp-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-iconv-debuginfo", rpm:"php5-iconv-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-imap", rpm:"php5-imap~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-imap-debuginfo", rpm:"php5-imap-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-intl", rpm:"php5-intl~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-intl-debuginfo", rpm:"php5-intl-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-json", rpm:"php5-json~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-json-debuginfo", rpm:"php5-json-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ldap-debuginfo", rpm:"php5-ldap-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mbstring-debuginfo", rpm:"php5-mbstring-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mcrypt-debuginfo", rpm:"php5-mcrypt-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mssql", rpm:"php5-mssql~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mssql-debuginfo", rpm:"php5-mssql-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mysql-debuginfo", rpm:"php5-mysql-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-odbc-debuginfo", rpm:"php5-odbc-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-opcache", rpm:"php5-opcache~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-opcache-debuginfo", rpm:"php5-opcache-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-openssl-debuginfo", rpm:"php5-openssl-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pcntl-debuginfo", rpm:"php5-pcntl-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pdo-debuginfo", rpm:"php5-pdo-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pgsql-debuginfo", rpm:"php5-pgsql-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-phar", rpm:"php5-phar~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-phar-debuginfo", rpm:"php5-phar-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-posix", rpm:"php5-posix~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-posix-debuginfo", rpm:"php5-posix-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pspell-debuginfo", rpm:"php5-pspell-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-readline", rpm:"php5-readline~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-readline-debuginfo", rpm:"php5-readline-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-shmop-debuginfo", rpm:"php5-shmop-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-snmp-debuginfo", rpm:"php5-snmp-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-soap-debuginfo", rpm:"php5-soap-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sockets-debuginfo", rpm:"php5-sockets-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sqlite-debuginfo", rpm:"php5-sqlite-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-suhosin", rpm:"php5-suhosin~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-suhosin-debuginfo", rpm:"php5-suhosin-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvmsg-debuginfo", rpm:"php5-sysvmsg-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvsem-debuginfo", rpm:"php5-sysvsem-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvshm-debuginfo", rpm:"php5-sysvshm-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-tidy", rpm:"php5-tidy~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-tidy-debuginfo", rpm:"php5-tidy-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-tokenizer-debuginfo", rpm:"php5-tokenizer-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-wddx-debuginfo", rpm:"php5-wddx-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlreader-debuginfo", rpm:"php5-xmlreader-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlrpc-debuginfo", rpm:"php5-xmlrpc-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlwriter", rpm:"php5-xmlwriter~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlwriter-debuginfo", rpm:"php5-xmlwriter-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xsl-debuginfo", rpm:"php5-xsl-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-zip", rpm:"php5-zip~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-zip-debuginfo", rpm:"php5-zip-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-zlib-debuginfo", rpm:"php5-zlib-debuginfo~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.5.14~115.1", rls:"openSUSELeap42.3"))) {
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
