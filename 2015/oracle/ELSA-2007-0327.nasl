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
  script_oid("1.3.6.1.4.1.25623.1.0.122681");
  script_cve_id("CVE-2005-2090", "CVE-2006-7195", "CVE-2007-0450", "CVE-2007-1358");
  script_tag(name:"creation_date", value:"2015-10-08 11:51:03 +0000 (Thu, 08 Oct 2015)");
  script_version("2022-04-05T09:12:43+0000");
  script_tag(name:"last_modification", value:"2022-04-05 09:12:43 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2007-0327)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0327");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0327.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jakarta-commons-modeler, tomcat5' package(s) announced via the ELSA-2007-0327 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"jakarta-commons-modeler-1.1-8jpp.1.0.2.el5

 [1.1-8jpp.1.0.2.el5]
 - rebuild after the fix for bug 238139 made it into the build root
 - Resolves: bug 238694

 [1.1-8jpp.1.0.1.el5]
 - Add patch to fix jira task: MODELER-15 to allow tomcat5 5.5.23
 to build against j-c-modeler
 - Resolves: bug 238694

 tomcat5-5.5.23-0jpp.1.0.3.el5

 [5.5.23-0jpp.1.0.3.el5]
 - Rebuild since brp-repack-jars has been fixed to not mangle INDEX.LIST
 files -
 (bug 238139)
 - Resolves: bug 237089

 [5.5.23-0jpp.1.0.2.el5]
 - Add catalina.out to the rpm and set explicit permissions, tomcat ownership
 - Resolves: bug 237089

 [5.5.23-0jpp.1.0.1.el5]
 - Backport 0:5.5.23-0jpp.2.el5 to the Z-stream
 - Resolves: bug 237089

 [5.5.23-0jpp.1]
 - Merge 0:5.5.17-8jpp.2 with sources/patches from 5.5.23
 - Build against jakarta-commons-modeler 1.1 with MODELER-15 patch");

  script_tag(name:"affected", value:"'jakarta-commons-modeler, tomcat5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"jakarta-commons-modeler", rpm:"jakarta-commons-modeler~1.1~8jpp.1.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jakarta-commons-modeler-javadoc", rpm:"jakarta-commons-modeler-javadoc~1.1~8jpp.1.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5", rpm:"tomcat5~5.5.23~0jpp.1.0.3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-admin-webapps", rpm:"tomcat5-admin-webapps~5.5.23~0jpp.1.0.3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-common-lib", rpm:"tomcat5-common-lib~5.5.23~0jpp.1.0.3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-jasper", rpm:"tomcat5-jasper~5.5.23~0jpp.1.0.3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-jasper-javadoc", rpm:"tomcat5-jasper-javadoc~5.5.23~0jpp.1.0.3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api", rpm:"tomcat5-jsp-2.0-api~5.5.23~0jpp.1.0.3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api-javadoc", rpm:"tomcat5-jsp-2.0-api-javadoc~5.5.23~0jpp.1.0.3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-server-lib", rpm:"tomcat5-server-lib~5.5.23~0jpp.1.0.3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api", rpm:"tomcat5-servlet-2.4-api~5.5.23~0jpp.1.0.3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api-javadoc", rpm:"tomcat5-servlet-2.4-api-javadoc~5.5.23~0jpp.1.0.3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat5-webapps", rpm:"tomcat5-webapps~5.5.23~0jpp.1.0.3.el5", rls:"OracleLinux5"))) {
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
