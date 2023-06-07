# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.123562");
  script_cve_id("CVE-2006-7243", "CVE-2011-1398", "CVE-2012-0831", "CVE-2012-2688", "CVE-2013-1643", "CVE-2013-4248");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:34 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:10:07+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:10:07 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1307)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1307");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1307.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php53' package(s) announced via the ELSA-2013-1307 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.3.3-21]
- add security fix for CVE-2013-4248

[5.3.3-20]
- add security fix for CVE-2013-4113

[5.3.3-19]
- add upstream reproducer for error_handler (#951075)

[5.3.3-18]
- add security fixes for CVE-2006-7243

[5.3.3-17]
- reorder security patches
- add security fixes for CVE-2012-2688, CVE-2012-0831,
 CVE-2011-1398, CVE-2013-1643

[5.3.3-15]
- fix segfault in error_handler with
 allow_call_time_pass_reference = Off (#951075)
- fix double free when destroy_zend_class fails (#951076)

[5.3.3-14]
- fix possible buffer overflow in pdo_odbc (#869694)
- rename php-5.3.3-extrglob.patch and reorder
- php script hangs when it exceeds max_execution_time
 when inside an ODBC call (#864954)
- fix zend garbage collector (#892695)
- fix transposed memset arguments in libzip (#953818)
- fix possible segfault in pdo_mysql (#869693)
- fix imap_open DISABLE_AUTHENTICATOR param ignores array (#859369)
- fix stream support in fileinfo (#869697)
- fix setDate when DateTime created from timestamp (#869691)
- fix permission on source files (#869688)
- add php(language) and missing provides (#837044)
- fix copy doesn't report failure on partial copy (#951413)");

  script_tag(name:"affected", value:"'php53' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-cli", rpm:"php53-cli~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-common", rpm:"php53-common~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-devel", rpm:"php53-devel~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-imap", rpm:"php53-imap~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-process", rpm:"php53-process~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xml", rpm:"php53-xml~5.3.3~21.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.3~21.el5", rls:"OracleLinux5"))) {
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
