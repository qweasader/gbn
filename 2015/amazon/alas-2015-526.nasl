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
  script_oid("1.3.6.1.4.1.25623.1.0.120058");
  script_cve_id("CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099", "CVE-2014-0227");
  script_tag(name:"creation_date", value:"2015-09-08 11:16:27 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-05T14:03:08+0000");
  script_tag(name:"last_modification", value:"2022-01-05 14:03:08 +0000 (Wed, 05 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-526)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-526");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-526.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat7' package(s) announced via the ALAS-2015-526 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that JBoss Web / Apache Tomcat did not limit the length of chunk sizes when using chunked transfer encoding. A remote attacker could use this flaw to perform a denial of service attack against JBoss Web / Apache Tomcat by streaming an unlimited quantity of data, leading to excessive consumption of server resources. (CVE-2014-0075)

It was found that the org.apache.catalina.servlets.DefaultServlet implementation in JBoss Web / Apache Tomcat allowed the definition of XML External Entities (XXEs) in provided XSLTs. A malicious application could use this to circumvent intended security restrictions to disclose sensitive information. (CVE-2014-0096)

It was found that JBoss Web / Apache Tomcat did not check for overflowing values when parsing request content length headers. A remote attacker could use this flaw to perform an HTTP request smuggling attack on a JBoss Web / Apache Tomcat server located behind a reverse proxy that processed the content length header correctly. (CVE-2014-0099)

It was discovered that the ChunkedInputFilter in Tomcat did not fail subsequent attempts to read input after malformed chunked encoding was detected. A remote attacker could possibly use this flaw to make Tomcat process part of the request body as new request, or cause a denial of service. (CVE-2014-0227)");

  script_tag(name:"affected", value:"'tomcat7' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat7", rpm:"tomcat7~7.0.59~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-admin-webapps", rpm:"tomcat7-admin-webapps~7.0.59~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-docs-webapp", rpm:"tomcat7-docs-webapp~7.0.59~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-el-2.2-api", rpm:"tomcat7-el-2.2-api~7.0.59~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-javadoc", rpm:"tomcat7-javadoc~7.0.59~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-jsp-2.2-api", rpm:"tomcat7-jsp-2.2-api~7.0.59~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-lib", rpm:"tomcat7-lib~7.0.59~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-log4j", rpm:"tomcat7-log4j~7.0.59~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-servlet-3.0-api", rpm:"tomcat7-servlet-3.0-api~7.0.59~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-webapps", rpm:"tomcat7-webapps~7.0.59~1.8.amzn1", rls:"AMAZON"))) {
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
