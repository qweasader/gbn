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
  script_oid("1.3.6.1.4.1.25623.1.0.122871");
  script_cve_id("CVE-2015-2783", "CVE-2015-3307", "CVE-2015-3329", "CVE-2015-3330", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4025", "CVE-2015-4026", "CVE-2015-4598", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4604", "CVE-2015-4605", "CVE-2015-4643", "CVE-2015-4644");
  script_tag(name:"creation_date", value:"2016-02-05 12:01:40 +0000 (Fri, 05 Feb 2016)");
  script_version("2021-10-08T09:29:56+0000");
  script_tag(name:"last_modification", value:"2021-10-08 09:29:56 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-22 17:48:00 +0000 (Mon, 22 Apr 2019)");

  script_name("Oracle: Security Advisory (ELSA-2015-1186)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1186");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1186.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php55-php' package(s) announced via the ELSA-2015-1186 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.5.21-4]
- fix more functions accept paths with NUL character #1213407

[5.5.21-3]
- core: fix multipart/form-data request can use excessive
 amount of CPU usage CVE-2015-4024
- fix various functions accept paths with NUL character
 CVE-2015-4025, CVE-2015-4026, #1213407
- fileinfo: fix denial of service when processing a crafted
 file #1213442
- ftp: fix integer overflow leading to heap overflow when
 reading FTP file listing CVE-2015-4022
- phar: fix buffer over-read in metadata parsing CVE-2015-2783
- phar: invalid pointer free() in phar_tar_process_metadata()
 CVE-2015-3307
- phar: fix buffer overflow in phar_set_inode() CVE-2015-3329
- phar: fix memory corruption in phar_parse_tarfile caused by
 empty entry file name CVE-2015-4021
- pgsql: fix NULL pointer dereference CVE-2015-1352
- soap: fix type confusion through unserialize #1222538
- apache2handler: fix pipelined request executed in deinitialized
 interpreter under httpd 2.4 CVE-2015-3330");

  script_tag(name:"affected", value:"'php55-php' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"php55-php", rpm:"php55-php~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-bcmath", rpm:"php55-php-bcmath~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-cli", rpm:"php55-php-cli~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-common", rpm:"php55-php-common~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-dba", rpm:"php55-php-dba~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-devel", rpm:"php55-php-devel~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-enchant", rpm:"php55-php-enchant~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-fpm", rpm:"php55-php-fpm~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-gd", rpm:"php55-php-gd~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-gmp", rpm:"php55-php-gmp~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-intl", rpm:"php55-php-intl~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-ldap", rpm:"php55-php-ldap~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-mbstring", rpm:"php55-php-mbstring~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-mysqlnd", rpm:"php55-php-mysqlnd~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-odbc", rpm:"php55-php-odbc~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-opcache", rpm:"php55-php-opcache~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-pdo", rpm:"php55-php-pdo~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-pgsql", rpm:"php55-php-pgsql~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-process", rpm:"php55-php-process~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-pspell", rpm:"php55-php-pspell~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-recode", rpm:"php55-php-recode~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-snmp", rpm:"php55-php-snmp~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-soap", rpm:"php55-php-soap~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-xml", rpm:"php55-php-xml~5.5.21~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php55-php-xmlrpc", rpm:"php55-php-xmlrpc~5.5.21~4.el7", rls:"OracleLinux7"))) {
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
