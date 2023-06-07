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
  script_oid("1.3.6.1.4.1.25623.1.0.123663");
  script_cve_id("CVE-2012-3546", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:57 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:10:07+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:10:07 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2013-0640)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0640");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0640.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat5' package(s) announced via the ELSA-2013-0640 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0:5.5.23-0jpp.38]
- Resolves: CVE-2012-3439 rhbz#882008 three DIGEST authentication
- implementation
- Resolves: CVE-2012-3546, rhbz#913034 Bypass of security constraints.
- Remove unneeded handling of FORM authentication in RealmBase");

  script_tag(name:"affected", value:"'tomcat5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat5", rpm:"tomcat5~5.5.23~0jpp.38.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-admin-webapps", rpm:"tomcat5-admin-webapps~5.5.23~0jpp.38.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-common-lib", rpm:"tomcat5-common-lib~5.5.23~0jpp.38.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-jasper", rpm:"tomcat5-jasper~5.5.23~0jpp.38.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-jasper-javadoc", rpm:"tomcat5-jasper-javadoc~5.5.23~0jpp.38.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api", rpm:"tomcat5-jsp-2.0-api~5.5.23~0jpp.38.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api-javadoc", rpm:"tomcat5-jsp-2.0-api-javadoc~5.5.23~0jpp.38.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-server-lib", rpm:"tomcat5-server-lib~5.5.23~0jpp.38.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api", rpm:"tomcat5-servlet-2.4-api~5.5.23~0jpp.38.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api-javadoc", rpm:"tomcat5-servlet-2.4-api-javadoc~5.5.23~0jpp.38.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-webapps", rpm:"tomcat5-webapps~5.5.23~0jpp.38.el5_9", rls:"OracleLinux5"))) {
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
