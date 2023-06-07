# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122874");
  script_cve_id("CVE-2014-8142", "CVE-2014-9427", "CVE-2014-9652", "CVE-2014-9705", "CVE-2014-9709", "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-1351", "CVE-2015-2301", "CVE-2015-2305", "CVE-2015-2348", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3307", "CVE-2015-3329", "CVE-2015-3330", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4604", "CVE-2015-4605");
  script_tag(name:"creation_date", value:"2016-02-05 12:01:42 +0000 (Fri, 05 Feb 2016)");
  script_version("2021-10-13T13:01:32+0000");
  script_tag(name:"last_modification", value:"2021-10-13 13:01:32 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Oracle: Security Advisory (ELSA-2015-1066)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1066");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1066.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php54, php54-php, php54-php-pecl-zendopcache' package(s) announced via the ELSA-2015-1066 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"php54
[2.0-1]
- fix incorrect selinux contexts #1194332

php54-php
[5.4.40-1]
- rebase to PHP 5.4.40 for various security fix #1209887

[5.4.37-1]
- rebase to PHP 5.4.37

[5.4.36-1]
- rebase to PHP 5.4.36 #1168193
- fix package name in description
- php-fpm own session dir

php54-php-pecl-zendopcache
[7.0.4-3]
- fix use after free CVE-2015-1351

[7.0.4-2]
- add upstream patch for failed test

[7.0.4-1]
- Update to 7.0.4

[7.0.3-1]
- update to 7.0.3 #1055927");

  script_tag(name:"affected", value:"'php54, php54-php, php54-php-pecl-zendopcache' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"php54", rpm:"php54~2.0~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php", rpm:"php54-php~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-bcmath", rpm:"php54-php-bcmath~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-cli", rpm:"php54-php-cli~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-common", rpm:"php54-php-common~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-dba", rpm:"php54-php-dba~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-devel", rpm:"php54-php-devel~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-enchant", rpm:"php54-php-enchant~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-fpm", rpm:"php54-php-fpm~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-gd", rpm:"php54-php-gd~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-imap", rpm:"php54-php-imap~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-intl", rpm:"php54-php-intl~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-ldap", rpm:"php54-php-ldap~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-mbstring", rpm:"php54-php-mbstring~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-mysqlnd", rpm:"php54-php-mysqlnd~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-odbc", rpm:"php54-php-odbc~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pdo", rpm:"php54-php-pdo~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pecl-zendopcache", rpm:"php54-php-pecl-zendopcache~7.0.4~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pgsql", rpm:"php54-php-pgsql~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-process", rpm:"php54-php-process~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pspell", rpm:"php54-php-pspell~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-recode", rpm:"php54-php-recode~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-snmp", rpm:"php54-php-snmp~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-soap", rpm:"php54-php-soap~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-tidy", rpm:"php54-php-tidy~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-xml", rpm:"php54-php-xml~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-xmlrpc", rpm:"php54-php-xmlrpc~5.4.40~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-runtime", rpm:"php54-runtime~2.0~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-scldevel", rpm:"php54-scldevel~2.0~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"php54", rpm:"php54~2.0~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php", rpm:"php54-php~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-bcmath", rpm:"php54-php-bcmath~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-cli", rpm:"php54-php-cli~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-common", rpm:"php54-php-common~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-dba", rpm:"php54-php-dba~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-devel", rpm:"php54-php-devel~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-enchant", rpm:"php54-php-enchant~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-fpm", rpm:"php54-php-fpm~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-gd", rpm:"php54-php-gd~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-intl", rpm:"php54-php-intl~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-ldap", rpm:"php54-php-ldap~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-mbstring", rpm:"php54-php-mbstring~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-mysqlnd", rpm:"php54-php-mysqlnd~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-odbc", rpm:"php54-php-odbc~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pdo", rpm:"php54-php-pdo~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pecl-zendopcache", rpm:"php54-php-pecl-zendopcache~7.0.4~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pgsql", rpm:"php54-php-pgsql~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-process", rpm:"php54-php-process~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pspell", rpm:"php54-php-pspell~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-recode", rpm:"php54-php-recode~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-snmp", rpm:"php54-php-snmp~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-soap", rpm:"php54-php-soap~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-xml", rpm:"php54-php-xml~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-xmlrpc", rpm:"php54-php-xmlrpc~5.4.40~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-runtime", rpm:"php54-runtime~2.0~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-scldevel", rpm:"php54-scldevel~2.0~1.el7", rls:"OracleLinux7"))) {
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
